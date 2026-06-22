from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any

RECIPIENT_NOT_FOUND = "RECIPIENT_NOT_FOUND"
NON_POSITIVE_AMOUNT = "NON_POSITIVE_AMOUNT"
SELF_TRANSFER = "SELF_TRANSFER"
INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS"
DUPLICATE_IDEMPOTENCY_KEY = "DUPLICATE_IDEMPOTENCY_KEY"
IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
ACCOUNT_INACTIVE = "ACCOUNT_INACTIVE"
MISSING_IDEMPOTENCY_KEY = "MISSING_IDEMPOTENCY_KEY"


@dataclass(frozen=True)
class TransferResult:
    success: bool
    message: str
    reason_code: str | None = None
    transaction_id: int | None = None
    idempotent_replay: bool = False


def parse_amount_cents(amount_raw: str) -> int | None:
    try:
        amount = Decimal(amount_raw.strip()).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, AttributeError):
        return None
    if amount <= 0:
        return None
    return int(amount * 100)


def cents_to_dollars(amount_cents: int) -> float:
    return float(Decimal(amount_cents) / Decimal(100))


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


def _sync_display_balance(db: sqlite3.Connection, account_id: int) -> None:
    db.execute(
        """
        UPDATE accounts
        SET balance = CAST(balance_cents AS REAL) / 100.0
        WHERE id = ?
        """,
        (account_id,),
    )


def _log_rejected_transfer(
    db: sqlite3.Connection,
    *,
    user_id: int,
    sender_account_id: int,
    recipient_lookup: str,
    recipient_account_id: int | None,
    amount_cents: int | None,
    idempotency_key: str | None,
    reason_code: str,
    request_context: dict[str, Any],
) -> None:
    db.execute(
        """
        INSERT INTO rejected_transfers (
            user_id, sender_account_id, recipient_lookup, recipient_account_id,
            amount_cents, idempotency_key, reason_code, status, request_context, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, 'rejected', ?, ?)
        """,
        (
            user_id,
            sender_account_id,
            recipient_lookup,
            recipient_account_id,
            amount_cents,
            idempotency_key,
            reason_code,
            json.dumps(request_context, sort_keys=True),
            _now(),
        ),
    )
    db.execute(
        """
        INSERT INTO audit_logs (timestamp, user_id, event_type, description, ip_address, severity)
        VALUES (?, ?, 'TRANSFER_REJECTED', ?, ?, 'Medium')
        """,
        (
            _now(),
            user_id,
            (
                f"reason={reason_code}; sender_account_id={sender_account_id}; "
                f"recipient_lookup={recipient_lookup}; amount_cents={amount_cents}; "
                f"idempotency_key={idempotency_key or 'missing'}"
            ),
            request_context.get("ip_address"),
        ),
    )


def _lookup_recipient(db: sqlite3.Connection, recipient_lookup: str) -> sqlite3.Row | None:
    return db.execute(
        """
        SELECT accounts.*, users.email, users.full_name, users.account_status
        FROM accounts
        JOIN users ON users.id = accounts.user_id
        WHERE users.email = ? OR accounts.account_number = ?
        """,
        (recipient_lookup, recipient_lookup),
    ).fetchone()


def _lookup_idempotency_record(
    db: sqlite3.Connection, sender_account_id: int, idempotency_key: str
) -> sqlite3.Row | None:
    return db.execute(
        """
        SELECT *
        FROM transfer_idempotency
        WHERE sender_account_id = ? AND idempotency_key = ?
        """,
        (sender_account_id, idempotency_key),
    ).fetchone()


def process_transfer(
    db: sqlite3.Connection,
    *,
    user_id: int,
    sender_account_id: int,
    sender_status: str,
    recipient_lookup: str,
    amount_raw: str,
    description: str,
    idempotency_key: str | None,
    request_context: dict[str, Any],
) -> TransferResult:
    if not idempotency_key or not idempotency_key.strip():
        db.execute("BEGIN")
        try:
            _log_rejected_transfer(
                db,
                user_id=user_id,
                sender_account_id=sender_account_id,
                recipient_lookup=recipient_lookup,
                recipient_account_id=None,
                amount_cents=None,
                idempotency_key=idempotency_key,
                reason_code=MISSING_IDEMPOTENCY_KEY,
                request_context=request_context,
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        return TransferResult(False, "Transfer request is missing a valid idempotency key.", MISSING_IDEMPOTENCY_KEY)

    idempotency_key = idempotency_key.strip()
    amount_cents = parse_amount_cents(amount_raw)

    if sender_status != "Active":
        db.execute("BEGIN")
        try:
            _log_rejected_transfer(
                db,
                user_id=user_id,
                sender_account_id=sender_account_id,
                recipient_lookup=recipient_lookup,
                recipient_account_id=None,
                amount_cents=amount_cents,
                idempotency_key=idempotency_key,
                reason_code=ACCOUNT_INACTIVE,
                request_context=request_context,
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        return TransferResult(False, "Your account is not active for transfers.", ACCOUNT_INACTIVE)

    if amount_cents is None:
        db.execute("BEGIN")
        try:
            _log_rejected_transfer(
                db,
                user_id=user_id,
                sender_account_id=sender_account_id,
                recipient_lookup=recipient_lookup,
                recipient_account_id=None,
                amount_cents=None,
                idempotency_key=idempotency_key,
                reason_code=NON_POSITIVE_AMOUNT,
                request_context=request_context,
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        return TransferResult(False, "Enter a positive transfer amount.", NON_POSITIVE_AMOUNT)

    existing = _lookup_idempotency_record(db, sender_account_id, idempotency_key)
    if existing:
        same_payload = (
            existing["recipient_account_id"] is not None
            and existing["amount_cents"] == amount_cents
            and (existing["description"] or "") == description
        )
        if existing["status"] == "completed" and same_payload:
            return TransferResult(
                True,
                "Transfer already completed.",
                transaction_id=existing["transaction_id"],
                idempotent_replay=True,
            )
        db.execute("BEGIN")
        try:
            _log_rejected_transfer(
                db,
                user_id=user_id,
                sender_account_id=sender_account_id,
                recipient_lookup=recipient_lookup,
                recipient_account_id=existing["recipient_account_id"],
                amount_cents=amount_cents,
                idempotency_key=idempotency_key,
                reason_code=IDEMPOTENCY_CONFLICT,
                request_context=request_context,
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        return TransferResult(
            False,
            "This idempotency key was already used with different transfer details.",
            IDEMPOTENCY_CONFLICT,
        )

    recipient = _lookup_recipient(db, recipient_lookup)
    if not recipient:
        db.execute("BEGIN")
        try:
            _log_rejected_transfer(
                db,
                user_id=user_id,
                sender_account_id=sender_account_id,
                recipient_lookup=recipient_lookup,
                recipient_account_id=None,
                amount_cents=amount_cents,
                idempotency_key=idempotency_key,
                reason_code=RECIPIENT_NOT_FOUND,
                request_context=request_context,
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        return TransferResult(False, "Recipient account was not found.", RECIPIENT_NOT_FOUND)

    if recipient["account_status"] != "Active":
        db.execute("BEGIN")
        try:
            _log_rejected_transfer(
                db,
                user_id=user_id,
                sender_account_id=sender_account_id,
                recipient_lookup=recipient_lookup,
                recipient_account_id=recipient["id"],
                amount_cents=amount_cents,
                idempotency_key=idempotency_key,
                reason_code=ACCOUNT_INACTIVE,
                request_context=request_context,
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        return TransferResult(False, "Recipient account is not active.", ACCOUNT_INACTIVE)

    if recipient["id"] == sender_account_id:
        db.execute("BEGIN")
        try:
            _log_rejected_transfer(
                db,
                user_id=user_id,
                sender_account_id=sender_account_id,
                recipient_lookup=recipient_lookup,
                recipient_account_id=recipient["id"],
                amount_cents=amount_cents,
                idempotency_key=idempotency_key,
                reason_code=SELF_TRANSFER,
                request_context=request_context,
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        return TransferResult(False, "Transfers to your own account are not allowed.", SELF_TRANSFER)

    db.execute("BEGIN IMMEDIATE")
    try:
        duplicate = _lookup_idempotency_record(db, sender_account_id, idempotency_key)
        if duplicate:
            db.rollback()
            if duplicate["status"] == "completed":
                return TransferResult(
                    True,
                    "Transfer already completed.",
                    transaction_id=duplicate["transaction_id"],
                    idempotent_replay=True,
                )
            return TransferResult(
                False,
                "This idempotency key was already used with different transfer details.",
                IDEMPOTENCY_CONFLICT,
            )

        debit = db.execute(
            """
            UPDATE accounts
            SET balance_cents = balance_cents - ?
            WHERE id = ? AND balance_cents >= ?
            """,
            (amount_cents, sender_account_id, amount_cents),
        )
        if debit.rowcount != 1:
            _log_rejected_transfer(
                db,
                user_id=user_id,
                sender_account_id=sender_account_id,
                recipient_lookup=recipient_lookup,
                recipient_account_id=recipient["id"],
                amount_cents=amount_cents,
                idempotency_key=idempotency_key,
                reason_code=INSUFFICIENT_FUNDS,
                request_context=request_context,
            )
            db.commit()
            return TransferResult(False, "Insufficient funds for this transfer.", INSUFFICIENT_FUNDS)

        db.execute(
            "UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?",
            (amount_cents, recipient["id"]),
        )
        _sync_display_balance(db, sender_account_id)
        _sync_display_balance(db, recipient["id"])

        amount_dollars = cents_to_dollars(amount_cents)
        cursor = db.execute(
            """
            INSERT INTO transactions (
                sender_account_id, recipient_account_id, amount, amount_cents,
                description, status
            )
            VALUES (?, ?, ?, ?, ?, 'Completed')
            """,
            (sender_account_id, recipient["id"], amount_dollars, amount_cents, description),
        )
        transaction_id = cursor.lastrowid

        db.execute(
            """
            INSERT INTO transfer_idempotency (
                sender_account_id, idempotency_key, recipient_account_id,
                amount_cents, description, status, transaction_id, created_at
            )
            VALUES (?, ?, ?, ?, ?, 'completed', ?, ?)
            """,
            (
                sender_account_id,
                idempotency_key,
                recipient["id"],
                amount_cents,
                description,
                transaction_id,
                _now(),
            ),
        )

        db.execute(
            """
            INSERT INTO audit_logs (timestamp, user_id, event_type, description, ip_address, severity)
            VALUES (?, ?, 'TRANSFER_CREATED', ?, ?, ?)
            """,
            (
                _now(),
                user_id,
                (
                    f"Transfer of CAD {amount_dollars:.2f} sent to {recipient['email']}. "
                    f"Note: {description}; idempotency_key={idempotency_key}"
                ),
                request_context.get("ip_address"),
                "Medium" if amount_cents >= 100_000 else "Low",
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        existing = _lookup_idempotency_record(db, sender_account_id, idempotency_key)
        if existing and existing["status"] == "completed":
            return TransferResult(
                True,
                "Transfer already completed.",
                transaction_id=existing["transaction_id"],
                idempotent_replay=True,
            )
        db.execute("BEGIN")
        try:
            _log_rejected_transfer(
                db,
                user_id=user_id,
                sender_account_id=sender_account_id,
                recipient_lookup=recipient_lookup,
                recipient_account_id=recipient["id"],
                amount_cents=amount_cents,
                idempotency_key=idempotency_key,
                reason_code=DUPLICATE_IDEMPOTENCY_KEY,
                request_context=request_context,
            )
            db.commit()
        except Exception:
            db.rollback()
            raise
        return TransferResult(
            False,
            "Duplicate transfer submission detected.",
            DUPLICATE_IDEMPOTENCY_KEY,
        )
    except Exception:
        db.rollback()
        raise

    return TransferResult(
        True,
        "Transfer completed.",
        transaction_id=transaction_id,
    )
