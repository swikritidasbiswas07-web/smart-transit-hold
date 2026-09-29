"""
Smart Transit Hold
Risk Fusion Engine

Version 1.0 FINAL

Purpose:
    Combines call-scam intelligence with transaction-risk intelligence.

This module connects:

    call_intelligence_v4_final.py
            +
    bank_security_v7.py
            |
            v
    Cross-Channel Risk Fusion
            |
            v
    ALLOW / WARN / SMART TRANSIT HOLD / SECURITY REVIEW

Important:
    This is a prototype fusion layer for the datathon.
    It does not replace a real bank's fraud decisioning system.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import math


APP_NAME = "Smart Transit Hold"
MODULE_NAME = "Risk Fusion Engine"
MODULE_VERSION = "1.0 FINAL"


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class CallContext:
    timestamp: str
    scam_risk: float
    manipulation_risk: float
    confidence: float
    risk_level: str
    recommended_action: str
    detected_language: str
    primary_pattern: str

    financial_request: bool
    safe_account_claim: bool
    bank_impersonation: bool
    account_compromise_claim: bool
    urgency: bool
    secrecy_request: bool
    otp_pin_request: bool
    remote_access_request: bool

    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TransactionContext:
    timestamp: str
    transaction_id: str
    customer_id: str
    amount: float
    recipient_id: str
    recipient_status: str
    risk_level: str
    transaction_risk: float
    ml_probability: float
    rule_score: float
    decision: str

    new_recipient: bool
    high_amount: bool
    unusual_location: bool
    unusual_device: bool
    rapid_transactions: bool
    previous_denial: bool
    unusual_hour: bool

    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FusionSignal:
    name: str
    detected: bool
    weight: float
    score: float
    explanation: str

    def contribution(self) -> float:
        if not self.detected:
            return 0.0

        return self.weight * self.score

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["contribution"] = round(self.contribution(), 3)
        return data


@dataclass
class FusionDecision:
    timestamp: str
    module_version: str

    final_risk: float
    final_risk_level: str
    decision: str
    confidence: float

    call_risk: float
    transaction_risk: float
    recipient_risk: float
    timing_risk: float
    manipulation_risk: float

    explanation: str
    customer_message: str
    analyst_summary: str
    recommended_next_step: str

    signals: List[Dict[str, Any]]
    call_context: Dict[str, Any]
    transaction_context: Dict[str, Any]

    smart_hold_required: bool
    security_review_required: bool
    allow_transaction: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            indent=4,
            ensure_ascii=False
        )


# =============================================================================
# SAFE VALUE HELPERS
# =============================================================================

class SafeRead:
    @staticmethod
    def value(source: Any, keys: List[str], default: Any = None) -> Any:
        if source is None:
            return default

        for key in keys:
            if isinstance(source, dict):
                if key in source:
                    return source[key]

            if hasattr(source, key):
                return getattr(source, key)

        return default

    @staticmethod
    def nested_value(
        source: Any,
        paths: List[List[str]],
        default: Any = None
    ) -> Any:
        for path in paths:
            current = source
            found = True

            for key in path:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                elif hasattr(current, key):
                    current = getattr(current, key)
                else:
                    found = False
                    break

            if found:
                return current

        return default

    @staticmethod
    def as_float(value: Any, default: float = 0.0) -> float:
        try:
            if value is None:
                return default

            number = float(value)

            if math.isnan(number) or math.isinf(number):
                return default

            if number > 1.0:
                number = number / 100.0

            return max(0.0, min(number, 1.0))

        except (TypeError, ValueError):
            return default

    @staticmethod
    def as_bool(value: Any, default: bool = False) -> bool:
        if isinstance(value, bool):
            return value

        if value is None:
            return default

        if isinstance(value, (int, float)):
            return bool(value)

        text = str(value).strip().lower()

        if text in {"true", "yes", "y", "1", "detected"}:
            return True

        if text in {"false", "no", "n", "0", "none", "not_detected"}:
            return False

        return default

    @staticmethod
    def as_str(value: Any, default: str = "") -> str:
        if value is None:
            return default

        return str(value)

    @staticmethod
    def as_amount(value: Any, default: float = 0.0) -> float:
        try:
            if value is None:
                return default

            text = str(value)
            text = text.replace("₹", "")
            text = text.replace(",", "")
            text = text.strip()

            return max(0.0, float(text))

        except (TypeError, ValueError):
            return default


# =============================================================================
# TIME HELPERS
# =============================================================================

class TimeTools:
    @staticmethod
    def now_iso() -> str:
        return datetime.now().isoformat(timespec="seconds")

    @staticmethod
    def parse_datetime(value: Any) -> Optional[datetime]:
        if isinstance(value, datetime):
            return value

        if not value:
            return None

        text = str(value).strip()

        known_formats = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M",
            "%Y-%m-%d %H:%M",
            "%d-%m-%Y %H:%M:%S",
            "%d-%m-%Y %H:%M"
        ]

        text = text.replace("Z", "")

        try:
            return datetime.fromisoformat(text)
        except ValueError:
            pass

        for fmt in known_formats:
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue

        return None

    @staticmethod
    def minutes_between(
        earlier: Optional[datetime],
        later: Optional[datetime]
    ) -> Optional[float]:
        if earlier is None or later is None:
            return None

        delta = later - earlier
        return delta.total_seconds() / 60.0


# =============================================================================
# ADAPTERS
# =============================================================================

class CallContextAdapter:
    @staticmethod
    def from_any(call_result: Any) -> CallContext:
        fusion_summary = SafeRead.value(
            call_result,
            ["fusion_ready_summary"],
            {}
        )

        high_value_flags = {}

        if isinstance(fusion_summary, dict):
            high_value_flags = fusion_summary.get("high_value_flags", {}) or {}

        timestamp = SafeRead.value(
            call_result,
            ["timestamp", "created_at", "call_timestamp"],
            TimeTools.now_iso()
        )

        scam_risk = SafeRead.as_float(
            SafeRead.value(
                call_result,
                ["scam_risk", "risk", "risk_score"],
                SafeRead.value(fusion_summary, ["scam_risk"], 0.0)
            )
        )

        manipulation_risk = SafeRead.as_float(
            SafeRead.value(
                call_result,
                ["manipulation_risk"],
                SafeRead.value(fusion_summary, ["manipulation_risk"], 0.0)
            )
        )

        confidence = SafeRead.as_float(
            SafeRead.value(
                call_result,
                ["confidence"],
                SafeRead.value(fusion_summary, ["confidence"], 0.5)
            ),
            default=0.5
        )

        risk_level = SafeRead.as_str(
            SafeRead.value(
                call_result,
                ["risk_level"],
                SafeRead.value(fusion_summary, ["risk_level"], "LOW")
            ),
            "LOW"
        ).upper()

        recommended_action = SafeRead.as_str(
            SafeRead.value(
                call_result,
                ["recommended_action"],
                SafeRead.value(fusion_summary, ["recommended_action"], "")
            ),
            ""
        )

        detected_language = SafeRead.as_str(
            SafeRead.value(
                call_result,
                ["detected_language"],
                SafeRead.value(fusion_summary, ["detected_language"], "unknown")
            ),
            "unknown"
        )

        primary_pattern = SafeRead.as_str(
            SafeRead.value(
                call_result,
                ["primary_pattern"],
                SafeRead.value(fusion_summary, ["primary_pattern"], "")
            ),
            ""
        )

        return CallContext(
            timestamp=SafeRead.as_str(timestamp, TimeTools.now_iso()),
            scam_risk=scam_risk,
            manipulation_risk=manipulation_risk,
            confidence=confidence,
            risk_level=risk_level,
            recommended_action=recommended_action,
            detected_language=detected_language,
            primary_pattern=primary_pattern,

            financial_request=SafeRead.as_bool(
                SafeRead.value(
                    call_result,
                    ["financial_request"],
                    high_value_flags.get("financial_request", False)
                )
            ),

            safe_account_claim=SafeRead.as_bool(
                SafeRead.value(
                    call_result,
                    ["safe_account_claim"],
                    high_value_flags.get("safe_account_claim", False)
                )
            ),

            bank_impersonation=SafeRead.as_bool(
                SafeRead.value(
                    call_result,
                    ["bank_impersonation"],
                    high_value_flags.get("bank_impersonation", False)
                )
            ),

            account_compromise_claim=SafeRead.as_bool(
                SafeRead.value(
                    call_result,
                    ["account_compromise_claim"],
                    high_value_flags.get("account_compromise_claim", False)
                )
            ),

            urgency=SafeRead.as_bool(
                SafeRead.value(
                    call_result,
                    ["urgency"],
                    high_value_flags.get("urgency", False)
                )
            ),

            secrecy_request=SafeRead.as_bool(
                SafeRead.value(
                    call_result,
                    ["secrecy_request"],
                    high_value_flags.get("secrecy_request", False)
                )
            ),

            otp_pin_request=SafeRead.as_bool(
                SafeRead.value(
                    call_result,
                    ["otp_pin_request"],
                    high_value_flags.get("otp_pin_request", False)
                )
            ),

            remote_access_request=SafeRead.as_bool(
                SafeRead.value(
                    call_result,
                    ["remote_access_request"],
                    high_value_flags.get("remote_access_request", False)
                )
            ),

            raw=call_result if isinstance(call_result, dict) else {}
        )


class TransactionContextAdapter:
    @staticmethod
    def from_any(transaction_result: Any) -> TransactionContext:
        timestamp = SafeRead.value(
            transaction_result,
            ["timestamp", "created_at", "transaction_time"],
            TimeTools.now_iso()
        )

        transaction_id = SafeRead.as_str(
            SafeRead.value(
                transaction_result,
                ["transaction_id", "tx_id", "id"],
                "TX_UNKNOWN"
            ),
            "TX_UNKNOWN"
        )

        customer_id = SafeRead.as_str(
            SafeRead.value(
                transaction_result,
                ["customer_id", "user_id", "account_id"],
                "USR_UNKNOWN"
            ),
            "USR_UNKNOWN"
        )

        amount = SafeRead.as_amount(
            SafeRead.value(
                transaction_result,
                ["amount", "transaction_amount"],
                0.0
            )
        )

        recipient_id = SafeRead.as_str(
            SafeRead.value(
                transaction_result,
                ["recipient_id", "recipient", "beneficiary_id"],
                "RECIPIENT_UNKNOWN"
            ),
            "RECIPIENT_UNKNOWN"
        )

        recipient_status = SafeRead.as_str(
            SafeRead.value(
                transaction_result,
                ["recipient_status", "recipient_risk", "beneficiary_status"],
                "UNKNOWN"
            ),
            "UNKNOWN"
        ).upper()

        risk_level = SafeRead.as_str(
            SafeRead.value(
                transaction_result,
                ["risk_level", "transaction_risk_level"],
                "LOW"
            ),
            "LOW"
        ).upper()

        transaction_risk = SafeRead.as_float(
            SafeRead.value(
                transaction_result,
                [
                    "transaction_risk",
                    "risk_score",
                    "hybrid_risk_score",
                    "final_risk",
                    "fraud_score"
                ],
                TransactionContextAdapter._risk_level_to_score(risk_level)
            )
        )

        ml_probability = SafeRead.as_float(
            SafeRead.value(
                transaction_result,
                ["ml_probability", "fraud_probability", "model_probability"],
                transaction_risk
            )
        )

        rule_score = SafeRead.as_float(
            SafeRead.value(
                transaction_result,
                ["rule_score", "rule_risk", "behavior_score"],
                transaction_risk
            )
        )

        decision = SafeRead.as_str(
            SafeRead.value(
                transaction_result,
                ["decision", "status", "action"],
                ""
            ),
            ""
        )

        signals = SafeRead.value(
            transaction_result,
            ["signals", "risk_signals", "features"],
            {}
        )

        return TransactionContext(
            timestamp=SafeRead.as_str(timestamp, TimeTools.now_iso()),
            transaction_id=transaction_id,
            customer_id=customer_id,
            amount=amount,
            recipient_id=recipient_id,
            recipient_status=recipient_status,
            risk_level=risk_level,
            transaction_risk=transaction_risk,
            ml_probability=ml_probability,
            rule_score=rule_score,
            decision=decision,

            new_recipient=TransactionContextAdapter._read_signal(
                transaction_result,
                signals,
                ["new_recipient", "is_new_recipient"]
            ),

            high_amount=TransactionContextAdapter._read_signal(
                transaction_result,
                signals,
                ["high_amount", "amount_anomaly", "large_amount"]
            ),

            unusual_location=TransactionContextAdapter._read_signal(
                transaction_result,
                signals,
                ["unusual_location", "location_anomaly"]
            ),

            unusual_device=TransactionContextAdapter._read_signal(
                transaction_result,
                signals,
                ["unusual_device", "device_anomaly"]
            ),

            rapid_transactions=TransactionContextAdapter._read_signal(
                transaction_result,
                signals,
                ["rapid_transactions", "velocity_risk"]
            ),

            previous_denial=TransactionContextAdapter._read_signal(
                transaction_result,
                signals,
                ["previous_denial", "previous_denied_transaction"]
            ),

            unusual_hour=TransactionContextAdapter._read_signal(
                transaction_result,
                signals,
                ["unusual_hour", "time_anomaly"]
            ),

            raw=transaction_result if isinstance(transaction_result, dict) else {}
        )

    @staticmethod
    def _read_signal(
        transaction_result: Any,
        signals: Any,
        names: List[str]
    ) -> bool:
        direct = SafeRead.value(transaction_result, names, None)

        if direct is not None:
            return SafeRead.as_bool(direct)

        if isinstance(signals, dict):
            for name in names:
                if name in signals:
                    return SafeRead.as_bool(signals[name])

        return False

    @staticmethod
    def _risk_level_to_score(risk_level: str) -> float:
        risk_level = (risk_level or "").upper()

        if risk_level == "HIGH":
            return 0.85

        if risk_level == "MEDIUM":
            return 0.55

        return 0.20


# =============================================================================
# RISK FUSION ENGINE
# =============================================================================

class RiskFusionEngine:
    def __init__(
        self,
        correlation_window_minutes: int = 30,
        extended_window_minutes: int = 120
    ) -> None:
        self.correlation_window_minutes = correlation_window_minutes
        self.extended_window_minutes = extended_window_minutes

    def fuse(
        self,
        call_result: Any,
        transaction_result: Any
    ) -> FusionDecision:
        call = CallContextAdapter.from_any(call_result)
        transaction = TransactionContextAdapter.from_any(transaction_result)

        signals = self._build_signals(call, transaction)

        call_risk = self._calculate_call_risk(call)
        transaction_risk = self._calculate_transaction_risk(transaction)
        recipient_risk = self._calculate_recipient_risk(transaction)
        timing_risk = self._calculate_timing_risk(call, transaction)
        manipulation_risk = call.manipulation_risk

        signal_bonus = sum(signal.contribution() for signal in signals)

        final_risk = (
            call_risk * 0.28
            + transaction_risk * 0.30
            + recipient_risk * 0.16
            + timing_risk * 0.14
            + manipulation_risk * 0.12
            + signal_bonus
        )

        final_risk = round(min(final_risk, 1.0), 3)

        final_risk_level = self._risk_level(final_risk)

        confidence = self._calculate_confidence(
            call=call,
            transaction=transaction,
            timing_risk=timing_risk,
            signal_count=sum(1 for signal in signals if signal.detected)
        )

        decision = self._decide(
            final_risk=final_risk,
            call=call,
            transaction=transaction,
            timing_risk=timing_risk
        )

        explanation = self._build_explanation(
            final_risk_level=final_risk_level,
            final_risk=final_risk,
            decision=decision,
            call=call,
            transaction=transaction,
            timing_risk=timing_risk,
            signals=signals
        )

        customer_message = self._build_customer_message(
            decision=decision,
            final_risk_level=final_risk_level,
            call=call,
            transaction=transaction
        )

        analyst_summary = self._build_analyst_summary(
            call=call,
            transaction=transaction,
            final_risk=final_risk,
            decision=decision,
            signals=signals
        )

        recommended_next_step = self._recommended_next_step(decision)

        return FusionDecision(
            timestamp=TimeTools.now_iso(),
            module_version=MODULE_VERSION,

            final_risk=final_risk,
            final_risk_level=final_risk_level,
            decision=decision,
            confidence=confidence,

            call_risk=call_risk,
            transaction_risk=transaction_risk,
            recipient_risk=recipient_risk,
            timing_risk=timing_risk,
            manipulation_risk=manipulation_risk,

            explanation=explanation,
            customer_message=customer_message,
            analyst_summary=analyst_summary,
            recommended_next_step=recommended_next_step,

            signals=[signal.to_dict() for signal in signals],
            call_context=call.to_dict(),
            transaction_context=transaction.to_dict(),

            smart_hold_required=decision in {
                "SMART_TRANSIT_HOLD_REQUIRED",
                "SECURITY_REVIEW_REQUIRED"
            },
            security_review_required=decision == "SECURITY_REVIEW_REQUIRED",
            allow_transaction=decision == "ALLOW"
        )

    def _build_signals(
        self,
        call: CallContext,
        transaction: TransactionContext
    ) -> List[FusionSignal]:
        timing_risk = self._calculate_timing_risk(call, transaction)

        return [
            FusionSignal(
                name="recent_suspicious_call",
                detected=timing_risk >= 0.50 and call.scam_risk >= 0.60,
                weight=0.06,
                score=max(call.scam_risk, timing_risk),
                explanation=(
                    "A suspicious call occurred close to the transaction."
                )
            ),

            FusionSignal(
                name="call_requested_payment",
                detected=call.financial_request,
                weight=0.05,
                score=call.scam_risk,
                explanation=(
                    "The call contained a request or pressure to perform "
                    "a financial action."
                )
            ),

            FusionSignal(
                name="safe_account_plus_transfer",
                detected=(
                    call.safe_account_claim
                    and call.financial_request
                ),
                weight=0.10,
                score=max(call.scam_risk, call.manipulation_risk),
                explanation=(
                    "The caller suggested transferring money to a safe, "
                    "secure, temporary, or protected account."
                )
            ),

            FusionSignal(
                name="bank_impersonation_before_payment",
                detected=(
                    call.bank_impersonation
                    and transaction.amount > 0
                ),
                weight=0.05,
                score=call.scam_risk,
                explanation=(
                    "The call appears to involve bank impersonation before "
                    "a payment attempt."
                )
            ),

            FusionSignal(
                name="urgent_call_before_payment",
                detected=call.urgency and timing_risk >= 0.40,
                weight=0.04,
                score=call.manipulation_risk,
                explanation=(
                    "Urgent language was detected shortly before the "
                    "transaction."
                )
            ),

            FusionSignal(
                name="new_or_risky_recipient",
                detected=(
                    transaction.new_recipient
                    or transaction.recipient_status in {
                        "SUSPECTED",
                        "BLACKLISTED",
                        "HIGH_RISK"
                    }
                ),
                weight=0.08,
                score=self._calculate_recipient_risk(transaction),
                explanation=(
                    "The transaction involves a new or risky recipient."
                )
            ),

            FusionSignal(
                name="risky_transaction_after_manipulation",
                detected=(
                    transaction.transaction_risk >= 0.60
                    and call.manipulation_risk >= 0.55
                ),
                weight=0.08,
                score=max(
                    transaction.transaction_risk,
                    call.manipulation_risk
                ),
                explanation=(
                    "The transaction is risky and follows signs of "
                    "customer manipulation."
                )
            ),

            FusionSignal(
                name="otp_or_remote_access_call",
                detected=(
                    call.otp_pin_request
                    or call.remote_access_request
                ),
                weight=0.10,
                score=1.0,
                explanation=(
                    "The call appears to request OTP/PIN information or "
                    "remote access."
                )
            ),

            FusionSignal(
                name="previous_denial_or_fraud_history",
                detected=transaction.previous_denial,
                weight=0.05,
                score=1.0,
                explanation=(
                    "The transaction context indicates prior denial or "
                    "fraud history."
                )
            )
        ]

    def _calculate_call_risk(self, call: CallContext) -> float:
        risk = (
            call.scam_risk * 0.70
            + call.manipulation_risk * 0.20
            + call.confidence * 0.10
        )

        if call.risk_level == "HIGH":
            risk = max(risk, 0.75)

        if call.recommended_action == "SMART_TRANSIT_HOLD_REQUIRED":
            risk = max(risk, 0.82)

        if call.otp_pin_request or call.remote_access_request:
            risk = max(risk, 0.90)

        return round(min(risk, 1.0), 3)

    def _calculate_transaction_risk(
        self,
        transaction: TransactionContext
    ) -> float:
        risk = (
            transaction.transaction_risk * 0.65
            + transaction.ml_probability * 0.20
            + transaction.rule_score * 0.15
        )

        if transaction.risk_level == "HIGH":
            risk = max(risk, 0.75)

        if transaction.risk_level == "MEDIUM":
            risk = max(risk, 0.45)

        if transaction.high_amount:
            risk += 0.06

        if transaction.unusual_device:
            risk += 0.05

        if transaction.unusual_location:
            risk += 0.05

        if transaction.rapid_transactions:
            risk += 0.05

        if transaction.previous_denial:
            risk += 0.10

        return round(min(risk, 1.0), 3)

    def _calculate_recipient_risk(
        self,
        transaction: TransactionContext
    ) -> float:
        status = transaction.recipient_status.upper()

        if status == "BLACKLISTED":
            return 1.0

        if status in {"SUSPECTED", "HIGH_RISK"}:
            return 0.75

        if status in {"UNKNOWN", "NEW"}:
            return 0.45 if transaction.new_recipient else 0.30

        if transaction.new_recipient:
            return 0.40

        return 0.10

    def _calculate_timing_risk(
        self,
        call: CallContext,
        transaction: TransactionContext
    ) -> float:
        call_time = TimeTools.parse_datetime(call.timestamp)
        transaction_time = TimeTools.parse_datetime(transaction.timestamp)

        minutes = TimeTools.minutes_between(call_time, transaction_time)

        if minutes is None:
            return 0.35

        if minutes < 0:
            return 0.15

        if minutes <= 5:
            return 1.0

        if minutes <= self.correlation_window_minutes:
            progress = minutes / self.correlation_window_minutes
            return round(1.0 - (progress * 0.45), 3)

        if minutes <= self.extended_window_minutes:
            progress = (
                (minutes - self.correlation_window_minutes)
                / max(
                    self.extended_window_minutes
                    - self.correlation_window_minutes,
                    1
                )
            )
            return round(0.50 - (progress * 0.30), 3)

        return 0.05

    def _calculate_confidence(
        self,
        call: CallContext,
        transaction: TransactionContext,
        timing_risk: float,
        signal_count: int
    ) -> float:
        confidence = 0.40

        confidence += call.confidence * 0.25

        if transaction.transaction_risk > 0:
            confidence += 0.10

        if transaction.amount > 0:
            confidence += 0.05

        if timing_risk >= 0.50:
            confidence += 0.10

        if signal_count >= 3:
            confidence += 0.07

        if signal_count >= 5:
            confidence += 0.05

        return round(min(confidence, 0.98), 3)

    def _decide(
        self,
        final_risk: float,
        call: CallContext,
        transaction: TransactionContext,
        timing_risk: float
    ) -> str:
        if transaction.recipient_status == "BLACKLISTED":
            return "SECURITY_REVIEW_REQUIRED"

        if call.otp_pin_request or call.remote_access_request:
            return "SECURITY_REVIEW_REQUIRED"

        if (
            call.safe_account_claim
            and call.financial_request
            and timing_risk >= 0.35
        ):
            return "SMART_TRANSIT_HOLD_REQUIRED"

        if (
            call.scam_risk >= 0.80
            and transaction.transaction_risk >= 0.45
            and timing_risk >= 0.35
        ):
            return "SMART_TRANSIT_HOLD_REQUIRED"

        if (
            call.manipulation_risk >= 0.70
            and transaction.new_recipient
            and timing_risk >= 0.35
        ):
            return "SMART_TRANSIT_HOLD_REQUIRED"

        if final_risk >= 0.85:
            return "SECURITY_REVIEW_REQUIRED"

        if final_risk >= 0.65:
            return "SMART_TRANSIT_HOLD_REQUIRED"

        if final_risk >= 0.40:
            return "WARN_AND_VERIFY"

        return "ALLOW"

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 0.70:
            return "HIGH"

        if score >= 0.40:
            return "MEDIUM"

        return "LOW"

    def _build_explanation(
        self,
        final_risk_level: str,
        final_risk: float,
        decision: str,
        call: CallContext,
        transaction: TransactionContext,
        timing_risk: float,
        signals: List[FusionSignal]
    ) -> str:
        detected_signals = [
            signal.explanation
            for signal in signals
            if signal.detected
        ]

        if not detected_signals:
            return (
                f"{final_risk_level} cross-channel risk. The transaction "
                "does not strongly correlate with a suspicious call context."
            )

        reason_text = self._join_sentences(detected_signals[:5])

        return (
            f"{final_risk_level} cross-channel risk "
            f"({final_risk * 100:.0f}%). Decision: {decision}. "
            f"The system connected the recent call context with the payment "
            f"attempt. {reason_text} Timing correlation score is "
            f"{timing_risk * 100:.0f}%."
        )

    @staticmethod
    def _build_customer_message(
        decision: str,
        final_risk_level: str,
        call: CallContext,
        transaction: TransactionContext
    ) -> str:
        amount_text = f"₹{transaction.amount:,.2f}"

        if decision == "SECURITY_REVIEW_REQUIRED":
            return (
                "For your protection, this payment has been stopped for "
                "security review. Do not continue instructions from the "
                "caller. Verify only through the official bank app, official "
                "customer-care number, or branch."
            )

        if decision == "SMART_TRANSIT_HOLD_REQUIRED":
            return (
                f"For your protection, your {amount_text} payment has been "
                "placed under Smart Transit Hold. A recent call appears to "
                "match financial manipulation patterns. End the call and "
                "verify independently before releasing the payment."
            )

        if decision == "WARN_AND_VERIFY":
            return (
                "This payment may be connected to a suspicious recent call. "
                "Proceed only after independently verifying the request "
                "through an official bank channel."
            )

        return (
            "No strong cross-channel scam pattern was detected. The payment "
            "can continue under normal monitoring."
        )

    @staticmethod
    def _build_analyst_summary(
        call: CallContext,
        transaction: TransactionContext,
        final_risk: float,
        decision: str,
        signals: List[FusionSignal]
    ) -> str:
        signal_names = [
            signal.name
            for signal in signals
            if signal.detected
        ]

        if not signal_names:
            signal_text = "No major fusion signals."
        else:
            signal_text = ", ".join(signal_names)

        return (
            f"Customer {transaction.customer_id} attempted transaction "
            f"{transaction.transaction_id} of ₹{transaction.amount:,.2f} "
            f"to recipient {transaction.recipient_id}. Transaction risk is "
            f"{transaction.transaction_risk * 100:.0f}% and call scam risk "
            f"is {call.scam_risk * 100:.0f}%. Final fused risk is "
            f"{final_risk * 100:.0f}%. Decision: {decision}. "
            f"Fusion signals: {signal_text}."
        )

    @staticmethod
    def _recommended_next_step(decision: str) -> str:
        if decision == "SECURITY_REVIEW_REQUIRED":
            return (
                "Escalate to bank security team. Keep transaction blocked "
                "until manual review is complete."
            )

        if decision == "SMART_TRANSIT_HOLD_REQUIRED":
            return (
                "Reserve the transaction amount under Smart Transit Hold. "
                "Ask the customer to end the call and verify independently."
            )

        if decision == "WARN_AND_VERIFY":
            return (
                "Show a clear warning and require customer confirmation "
                "through a trusted bank channel."
            )

        return "Allow transaction under normal monitoring."

    @staticmethod
    def _join_sentences(sentences: List[str]) -> str:
        cleaned = []

        for sentence in sentences:
            sentence = sentence.strip()

            if not sentence.endswith("."):
                sentence += "."

            cleaned.append(sentence)

        return " ".join(cleaned)


# =============================================================================
# DISPLAY AND EXPORT
# =============================================================================

class FusionDisplay:
    @staticmethod
    def show(decision: FusionDecision) -> None:
        print()
        print("=" * 74)
        print(f"{APP_NAME} - {MODULE_NAME}")
        print("=" * 74)

        print(f"Version              : {decision.module_version}")
        print(f"Final Risk Level     : {decision.final_risk_level}")
        print(f"Final Risk           : {decision.final_risk * 100:.0f}%")
        print(f"Confidence           : {decision.confidence * 100:.0f}%")
        print(f"Decision             : {decision.decision}")

        print()
        print("Risk Components")
        print("-" * 74)
        print(f"Call Risk            : {decision.call_risk * 100:.0f}%")
        print(f"Transaction Risk     : {decision.transaction_risk * 100:.0f}%")
        print(f"Recipient Risk       : {decision.recipient_risk * 100:.0f}%")
        print(f"Timing Risk          : {decision.timing_risk * 100:.0f}%")
        print(
            f"Manipulation Risk    : "
            f"{decision.manipulation_risk * 100:.0f}%"
        )

        print()
        print("Detected Fusion Signals")
        print("-" * 74)

        active_signals = [
            signal
            for signal in decision.signals
            if signal["detected"]
        ]

        if active_signals:
            for signal in active_signals:
                print(
                    f"[DETECTED] {signal['name']} "
                    f"(contribution: {signal['contribution']:.2f})"
                )
        else:
            print("No major cross-channel fusion signals detected.")

        print()
        print("Customer Message")
        print("-" * 74)
        print(decision.customer_message)

        print()
        print("Analyst Summary")
        print("-" * 74)
        print(decision.analyst_summary)

        print()
        print("Risk Explanation")
        print("-" * 74)
        print(decision.explanation)

        print()
        print("Recommended Next Step")
        print("-" * 74)
        print(decision.recommended_next_step)

        print()
        print("Structured Output")
        print("-" * 74)
        print(decision.to_json())

        print("=" * 74)

    @staticmethod
    def save_json(decision: FusionDecision) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(f"fusion_decision_{timestamp}.json")

        with path.open("w", encoding="utf-8") as file:
            file.write(decision.to_json())

        return path


# =============================================================================
# JSON LOADERS
# =============================================================================

def load_json_file(path_text: str) -> Dict[str, Any]:
    path = Path(path_text.strip().strip('"'))

    if not path.exists():
        raise FileNotFoundError(f"File not found:\n{path}")

    if not path.is_file():
        raise ValueError("The supplied path is not a file.")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


# =============================================================================
# DEMO DATA
# =============================================================================

def make_demo_call_result_high_risk() -> Dict[str, Any]:
    call_time = datetime.now() - timedelta(minutes=8)

    return {
        "timestamp": call_time.isoformat(timespec="seconds"),
        "module_version": "4.0 FINAL",
        "scam_risk": 1.0,
        "manipulation_risk": 0.78,
        "confidence": 0.98,
        "risk_level": "HIGH",
        "recommended_action": "SMART_TRANSIT_HOLD_REQUIRED",
        "detected_language": "hi",
        "primary_pattern": "Bank impersonation safe-account scam",
        "financial_request": True,
        "safe_account_claim": True,
        "bank_impersonation": True,
        "account_compromise_claim": True,
        "urgency": True,
        "secrecy_request": False,
        "otp_pin_request": False,
        "remote_access_request": False,
        "fusion_ready_summary": {
            "module": "call_intelligence",
            "module_version": "4.0 FINAL",
            "scam_risk": 1.0,
            "manipulation_risk": 0.78,
            "confidence": 0.98,
            "risk_level": "HIGH",
            "recommended_action": "SMART_TRANSIT_HOLD_REQUIRED",
            "detected_language": "hi",
            "cross_channel_relevant": True,
            "payment_intervention_recommended": True,
            "primary_pattern": "Bank impersonation safe-account scam",
            "high_value_flags": {
                "financial_request": True,
                "safe_account_claim": True,
                "bank_impersonation": True,
                "account_compromise_claim": True,
                "urgency": True,
                "secrecy_request": False,
                "otp_pin_request": False,
                "remote_access_request": False
            }
        }
    }


def make_demo_transaction_result_risky() -> Dict[str, Any]:
    transaction_time = datetime.now()

    return {
        "timestamp": transaction_time.isoformat(timespec="seconds"),
        "transaction_id": "TX_DEMO_9001",
        "customer_id": "USR_904",
        "amount": 80000,
        "recipient_id": "ACC_NEW_SAFE_777",
        "recipient_status": "UNKNOWN",
        "risk_level": "HIGH",
        "transaction_risk": 0.82,
        "ml_probability": 0.79,
        "rule_score": 0.86,
        "decision": "PENDING",
        "signals": {
            "new_recipient": True,
            "high_amount": True,
            "unusual_location": False,
            "unusual_device": False,
            "rapid_transactions": False,
            "previous_denial": False,
            "unusual_hour": False
        }
    }


def make_demo_transaction_result_normal() -> Dict[str, Any]:
    transaction_time = datetime.now()

    return {
        "timestamp": transaction_time.isoformat(timespec="seconds"),
        "transaction_id": "TX_DEMO_1001",
        "customer_id": "USR_904",
        "amount": 500,
        "recipient_id": "ACC_NORMAL_01",
        "recipient_status": "CLEAN",
        "risk_level": "LOW",
        "transaction_risk": 0.12,
        "ml_probability": 0.10,
        "rule_score": 0.14,
        "decision": "PENDING",
        "signals": {
            "new_recipient": False,
            "high_amount": False,
            "unusual_location": False,
            "unusual_device": False,
            "rapid_transactions": False,
            "previous_denial": False,
            "unusual_hour": False
        }
    }


def make_demo_call_result_low_risk() -> Dict[str, Any]:
    call_time = datetime.now() - timedelta(minutes=12)

    return {
        "timestamp": call_time.isoformat(timespec="seconds"),
        "scam_risk": 0.10,
        "manipulation_risk": 0.05,
        "confidence": 0.80,
        "risk_level": "LOW",
        "recommended_action": "ALLOW_NORMAL_MONITORING",
        "detected_language": "en",
        "primary_pattern": "Normal banking information",
        "financial_request": False,
        "safe_account_claim": False,
        "bank_impersonation": False,
        "account_compromise_claim": False,
        "urgency": False,
        "secrecy_request": False,
        "otp_pin_request": False,
        "remote_access_request": False
    }


# =============================================================================
# MANUAL INPUT
# =============================================================================

def ask_float(prompt: str, default: float) -> float:
    raw = input(prompt).strip()

    if not raw:
        return default

    try:
        value = float(raw)

        if value > 1.0:
            value = value / 100.0

        return max(0.0, min(value, 1.0))

    except ValueError:
        print(f"Invalid number. Using default {default}.")
        return default


def ask_bool(prompt: str, default: bool = False) -> bool:
    raw = input(prompt).strip().lower()

    if not raw:
        return default

    if raw in {"y", "yes", "true", "1"}:
        return True

    if raw in {"n", "no", "false", "0"}:
        return False

    print(f"Invalid answer. Using default {default}.")
    return default


def build_manual_call_result() -> Dict[str, Any]:
    print()
    print("Manual Call Context")
    print("-" * 74)

    minutes_ago = ask_float(
        "How many minutes ago did the call happen? [default 10]: ",
        10
    )

    call_time = datetime.now() - timedelta(minutes=minutes_ago)

    scam_risk = ask_float("Call scam risk 0-100 [default 80]: ", 80)
    manipulation_risk = ask_float("Manipulation risk 0-100 [default 70]: ", 70)
    confidence = ask_float("Call confidence 0-100 [default 85]: ", 85)

    risk_level = "HIGH" if scam_risk >= 0.70 else "MEDIUM"
    if scam_risk < 0.40:
        risk_level = "LOW"

    return {
        "timestamp": call_time.isoformat(timespec="seconds"),
        "scam_risk": scam_risk,
        "manipulation_risk": manipulation_risk,
        "confidence": confidence,
        "risk_level": risk_level,
        "recommended_action": (
            "SMART_TRANSIT_HOLD_REQUIRED"
            if scam_risk >= 0.70
            else "SHOW_WARNING_BEFORE_PAYMENT"
        ),
        "detected_language": input(
            "Detected language code [default en]: "
        ).strip() or "en",
        "primary_pattern": input(
            "Primary call pattern [default suspicious call]: "
        ).strip() or "suspicious call",
        "financial_request": ask_bool("Financial request? y/n [y]: ", True),
        "safe_account_claim": ask_bool("Safe-account claim? y/n [y]: ", True),
        "bank_impersonation": ask_bool("Bank impersonation? y/n [y]: ", True),
        "account_compromise_claim": ask_bool(
            "Account compromise claim? y/n [y]: ",
            True
        ),
        "urgency": ask_bool("Urgency? y/n [y]: ", True),
        "secrecy_request": ask_bool("Secrecy/isolation? y/n [n]: ", False),
        "otp_pin_request": ask_bool("OTP/PIN request? y/n [n]: ", False),
        "remote_access_request": ask_bool(
            "Remote access request? y/n [n]: ",
            False
        )
    }


def build_manual_transaction_result() -> Dict[str, Any]:
    print()
    print("Manual Transaction Context")
    print("-" * 74)

    amount_text = input("Amount [default 80000]: ").strip()

    try:
        amount = float(amount_text.replace(",", "")) if amount_text else 80000
    except ValueError:
        amount = 80000

    transaction_risk = ask_float(
        "Transaction risk 0-100 [default 70]: ",
        70
    )

    risk_level = "HIGH" if transaction_risk >= 0.70 else "MEDIUM"
    if transaction_risk < 0.40:
        risk_level = "LOW"

    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "transaction_id": input(
            "Transaction ID [default TX_MANUAL_001]: "
        ).strip() or "TX_MANUAL_001",
        "customer_id": input(
            "Customer ID [default USR_904]: "
        ).strip() or "USR_904",
        "amount": amount,
        "recipient_id": input(
            "Recipient ID [default ACC_NEW_SAFE_777]: "
        ).strip() or "ACC_NEW_SAFE_777",
        "recipient_status": input(
            "Recipient status CLEAN/UNKNOWN/SUSPECTED/BLACKLISTED "
            "[default UNKNOWN]: "
        ).strip().upper() or "UNKNOWN",
        "risk_level": risk_level,
        "transaction_risk": transaction_risk,
        "ml_probability": ask_float(
            "ML fraud probability 0-100 [default 70]: ",
            70
        ),
        "rule_score": ask_float(
            "Rule/behavior score 0-100 [default 70]: ",
            70
        ),
        "decision": "PENDING",
        "signals": {
            "new_recipient": ask_bool("New recipient? y/n [y]: ", True),
            "high_amount": ask_bool("High amount? y/n [y]: ", True),
            "unusual_location": ask_bool(
                "Unusual location? y/n [n]: ",
                False
            ),
            "unusual_device": ask_bool(
                "Unusual device? y/n [n]: ",
                False
            ),
            "rapid_transactions": ask_bool(
                "Rapid transactions? y/n [n]: ",
                False
            ),
            "previous_denial": ask_bool(
                "Previous denial? y/n [n]: ",
                False
            ),
            "unusual_hour": ask_bool(
                "Unusual hour? y/n [n]: ",
                False
            )
        }
    }


# =============================================================================
# MENU ACTIONS
# =============================================================================

def run_high_risk_demo(engine: RiskFusionEngine) -> None:
    call_result = make_demo_call_result_high_risk()
    transaction_result = make_demo_transaction_result_risky()

    decision = engine.fuse(call_result, transaction_result)
    FusionDisplay.show(decision)


def run_low_risk_demo(engine: RiskFusionEngine) -> None:
    call_result = make_demo_call_result_low_risk()
    transaction_result = make_demo_transaction_result_normal()

    decision = engine.fuse(call_result, transaction_result)
    FusionDisplay.show(decision)


def run_manual_demo(engine: RiskFusionEngine) -> None:
    call_result = build_manual_call_result()
    transaction_result = build_manual_transaction_result()

    decision = engine.fuse(call_result, transaction_result)
    FusionDisplay.show(decision)


def run_json_file_demo(engine: RiskFusionEngine) -> None:
    print()
    print("Load Call Result JSON + Transaction Result JSON")
    print("-" * 74)

    call_path = input("Enter call-result JSON path: ").strip()
    transaction_path = input("Enter transaction-result JSON path: ").strip()

    try:
        call_result = load_json_file(call_path)
        transaction_result = load_json_file(transaction_path)

        decision = engine.fuse(call_result, transaction_result)
        FusionDisplay.show(decision)

        save = input("Save fusion result JSON? y/n [y]: ").strip().lower()

        if save in {"", "y", "yes"}:
            output_path = FusionDisplay.save_json(decision)
            print()
            print(f"Saved to: {output_path.resolve()}")

    except Exception as error:
        print()
        print("ERROR")
        print("-" * 74)
        print(f"{type(error).__name__}: {error}")


def run_export_high_risk_demo(engine: RiskFusionEngine) -> None:
    call_result = make_demo_call_result_high_risk()
    transaction_result = make_demo_transaction_result_risky()

    decision = engine.fuse(call_result, transaction_result)
    FusionDisplay.show(decision)

    output_path = FusionDisplay.save_json(decision)

    print()
    print(f"Saved to: {output_path.resolve()}")


def show_system_info(engine: RiskFusionEngine) -> None:
    print()
    print("=" * 74)
    print("SYSTEM INFORMATION")
    print("=" * 74)

    print(f"Application                : {APP_NAME}")
    print(f"Module                     : {MODULE_NAME}")
    print(f"Version                    : {MODULE_VERSION}")
    print(
        f"Correlation window         : "
        f"{engine.correlation_window_minutes} minutes"
    )
    print(
        f"Extended correlation window: "
        f"{engine.extended_window_minutes} minutes"
    )

    print()
    print("Inputs")
    print("-" * 74)
    print("1. Call Intelligence V4 result or JSON")
    print("2. Bank Security V7 transaction result or JSON")

    print()
    print("Outputs")
    print("-" * 74)
    print("1. Final cross-channel risk score")
    print("2. ALLOW / WARN / SMART TRANSIT HOLD / SECURITY REVIEW decision")
    print("3. Customer-safe warning message")
    print("4. Analyst summary")
    print("5. Fusion-ready structured JSON")

    print("=" * 74)


# =============================================================================
# MENU
# =============================================================================

def display_menu() -> None:
    print()
    print("=" * 74)
    print(f"{APP_NAME} - {MODULE_NAME} {MODULE_VERSION}")
    print("=" * 74)

    print()
    print("1. Run high-risk cross-channel demo")
    print("2. Run low-risk normal demo")
    print("3. Enter manual call + transaction context")
    print("4. Load call JSON + transaction JSON")
    print("5. Run high-risk demo and export JSON")
    print("6. System information")
    print("0. Exit")
    print()


def pause() -> None:
    print()
    input("Press ENTER to return to the main menu...")


def main() -> None:
    engine = RiskFusionEngine()

    while True:
        display_menu()

        choice = input("Select option: ").strip()

        if choice == "1":
            run_high_risk_demo(engine)
            pause()

        elif choice == "2":
            run_low_risk_demo(engine)
            pause()

        elif choice == "3":
            run_manual_demo(engine)
            pause()

        elif choice == "4":
            run_json_file_demo(engine)
            pause()

        elif choice == "5":
            run_export_high_risk_demo(engine)
            pause()

        elif choice == "6":
            show_system_info(engine)
            pause()

        elif choice == "0":
            print()
            print("Risk Fusion Engine closed.")
            break

        else:
            print()
            print("Invalid option. Please choose 0 to 6.")
            pause()


if __name__ == "__main__":
    main()
