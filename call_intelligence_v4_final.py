"""
Smart Transit Hold
Call Intelligence Engine

Version 4.0 FINAL - Part 1A

This module detects possible financial social-engineering calls.

Core capabilities in this final version:
    - Multilingual audio transcription using Faster-Whisper
    - Original transcript preservation
    - English translation / normalization for analysis
    - Rule-based scam signal detection
    - Lightweight semantic intent detection
    - Social-engineering psychology scoring
    - Explainable structured JSON output
    - Ready for future risk_fusion.py integration

Important:
    This module does not claim perfect scam detection.
    It produces a risk assessment to support Smart Transit Hold decisions.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import json
import math
import re
import time


APP_NAME = "Smart Transit Hold"
MODULE_NAME = "Call Intelligence Engine"
MODULE_VERSION = "4.0 FINAL"

WHISPER_MODEL_SIZE = "base"
WHISPER_DEVICE = "cpu"
WHISPER_COMPUTE_TYPE = "int8"


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class SemanticMatch:
    signal_name: str
    phrase: str
    matched_concept: str
    score: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SignalFinding:
    name: str
    detected: bool
    rule_score: float = 0.0
    semantic_score: float = 0.0
    final_score: float = 0.0
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PsychologyProfile:
    authority_pressure: float
    urgency_pressure: float
    fear_pressure: float
    isolation_pressure: float
    financial_control_pressure: float
    trust_exploitation: float
    overall_manipulation: float
    pattern_name: str
    pattern_explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TranscriptionResult:
    audio_file: str
    detected_language: str
    language_probability: float
    duration_seconds: float
    processing_seconds: float
    original_transcript: str
    analysis_transcript: str
    translation_used: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CallRiskResult:
    timestamp: str
    module_version: str

    scam_risk: float
    manipulation_risk: float
    confidence: float
    risk_level: str
    recommended_action: str

    financial_request: bool
    bank_impersonation: bool
    urgency: bool
    fear_or_threat: bool
    account_compromise_claim: bool
    safe_account_claim: bool
    otp_pin_request: bool
    remote_access_request: bool
    secrecy_request: bool
    authority_impersonation: bool
    card_fraud_claim: bool
    international_transaction_claim: bool

    detected_signals: List[str]
    signal_findings: Dict[str, Dict[str, Any]]
    semantic_matches: List[Dict[str, Any]]
    psychology_profile: Dict[str, Any]

    call_summary: str
    explanation: str
    fusion_ready_summary: Dict[str, Any]

    detected_language: str
    original_transcript: str
    analysis_transcript: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            indent=4,
            ensure_ascii=False
        )


# =============================================================================
# TEXT UTILITIES
# =============================================================================

class TextTools:
    STOP_WORDS = {
        "a", "an", "the", "is", "are", "was", "were", "am", "be", "been",
        "being", "to", "of", "in", "on", "for", "from", "with", "and", "or",
        "but", "if", "then", "that", "this", "it", "as", "at", "by", "your",
        "you", "we", "our", "i", "me", "my", "sir", "madam", "please",
        "now", "so", "can", "could", "would", "should", "need", "have",
        "has", "had", "do", "does", "did", "will", "shall", "may", "might",
        "there", "their", "they", "them", "he", "she", "his", "her"
    }

    @staticmethod
    def clean(text: str) -> str:
        text = text or ""
        text = text.strip().lower()
        text = re.sub(r"\s+", " ", text)
        return text

    @staticmethod
    def normalize_for_matching(text: str) -> str:
        text = TextTools.clean(text)
        text = text.replace("’", "'")
        text = text.replace("“", '"').replace("”", '"')
        text = re.sub(r"[^a-z0-9₹$€£.,!?'\-\s]", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    @staticmethod
    def split_sentences(text: str) -> List[str]:
        text = text or ""
        chunks = re.split(r"(?<=[.!?])\s+|\n+", text)
        sentences = []

        for chunk in chunks:
            chunk = chunk.strip()
            if chunk:
                sentences.append(chunk)

        if not sentences and text.strip():
            sentences.append(text.strip())

        return sentences

    @staticmethod
    def tokenize(text: str) -> List[str]:
        text = TextTools.normalize_for_matching(text)
        tokens = re.findall(r"[a-z0-9]+", text)
        return [
            token
            for token in tokens
            if token not in TextTools.STOP_WORDS
        ]

    @staticmethod
    def unique_keep_order(items: List[str]) -> List[str]:
        seen = set()
        output = []

        for item in items:
            if item not in seen:
                output.append(item)
                seen.add(item)

        return output


# =============================================================================
# LIGHTWEIGHT SEMANTIC ENGINE
# =============================================================================

class LightweightSemanticEngine:
    """
    This semantic engine is intentionally dependency-free.

    It does not use a large neural model.
    It performs lightweight intent similarity using:
        - normalized tokens
        - concept phrase matching
        - important scam-domain keywords
        - phrase overlap

    Why this design:
        - Works in Python IDLE
        - No extra install beyond Faster-Whisper
        - Stable for datathon demo
        - Complements the rule engine
    """

    def __init__(self) -> None:
        self.concepts = self._build_concepts()
        self.keyword_boosts = self._build_keyword_boosts()

    def _build_concepts(self) -> Dict[str, List[str]]:
        return {
            "financial_request": [
                "transfer money",
                "send money",
                "move funds",
                "move your balance",
                "make a payment",
                "pay immediately",
                "deposit money",
                "add beneficiary",
                "send funds to this account",
                "complete the transaction",
                "open banking app and transfer",
                "use mobile banking to send money",
                "relocate your funds",
                "shift your balance",
                "send available balance"
            ],

            "bank_impersonation": [
                "calling from bank",
                "bank fraud department",
                "fraud prevention department",
                "bank security team",
                "bank customer care",
                "bank representative",
                "bank officer speaking",
                "account security department",
                "official bank support",
                "debit card fraud team",
                "security verification from bank"
            ],

            "urgency": [
                "do this immediately",
                "urgent action required",
                "right now",
                "act quickly",
                "do not delay",
                "time is running out",
                "another transaction is happening",
                "transaction is being attempted",
                "must act now",
                "immediate security process",
                "complete this quickly",
                "we have very little time"
            ],

            "fear_or_threat": [
                "you will lose money",
                "account will be blocked",
                "account will be frozen",
                "money may be debited",
                "more money can be stolen",
                "legal action will happen",
                "police case",
                "serious consequences",
                "your card is at risk",
                "your account is in danger",
                "fraud is happening",
                "criminal case connected to your account"
            ],

            "account_compromise_claim": [
                "account compromised",
                "card compromised",
                "banking details compromised",
                "unauthorized access detected",
                "suspicious activity detected",
                "suspicious transaction detected",
                "someone accessed your account",
                "someone hacked your account",
                "security breach detected",
                "your debit card is not safe",
                "your bank account is at risk"
            ],

            "safe_account_claim": [
                "safe account",
                "temporary safe account",
                "secure account",
                "security account",
                "protected account",
                "transfer to protect money",
                "move money for safety",
                "keep your funds safe",
                "temporary holding account",
                "bank safety account",
                "secure your available balance",
                "protect your funds by transferring"
            ],

            "otp_pin_request": [
                "share otp",
                "tell me otp",
                "read otp",
                "give verification code",
                "share pin",
                "tell me pin",
                "give me security code",
                "read the code",
                "one time password",
                "otp for verification",
                "confirm the code sent to phone"
            ],

            "remote_access_request": [
                "install remote access app",
                "install anydesk",
                "install teamviewer",
                "download this app",
                "share your screen",
                "allow screen sharing",
                "give remote access",
                "let me control your phone",
                "open remote support application",
                "share device access"
            ],

            "secrecy_request": [
                "do not tell anyone",
                "do not contact anyone",
                "do not contact family",
                "keep this confidential",
                "keep this secret",
                "do not call the bank",
                "do not disconnect",
                "stay on the call",
                "remain on the line",
                "do not hang up",
                "do not speak to anyone else",
                "finish this process only with me"
            ],

            "authority_impersonation": [
                "police officer",
                "cyber crime department",
                "rbi officer",
                "reserve bank officer",
                "government department",
                "income tax department",
                "court official",
                "investigation officer",
                "law enforcement",
                "criminal investigation",
                "official government verification"
            ],

            "card_fraud_claim": [
                "debit card suspicious transaction",
                "card fraud detected",
                "card compromised",
                "transactions on debit card",
                "card used internationally",
                "card security issue",
                "debit card blocked for safety",
                "fraudulent debit card activity"
            ],

            "international_transaction_claim": [
                "international transaction",
                "overseas transaction",
                "foreign transaction",
                "transaction from singapore",
                "transaction from dubai",
                "cross border transaction",
                "foreign payment attempted",
                "international card usage",
                "transaction from another country"
            ]
        }

    def _build_keyword_boosts(self) -> Dict[str, List[str]]:
        return {
            "financial_request": [
                "transfer", "send", "move", "payment", "deposit",
                "beneficiary", "recipient", "account", "funds", "balance",
                "upi"
            ],
            "bank_impersonation": [
                "bank", "fraud", "department", "security", "representative",
                "officer", "support", "customer", "care"
            ],
            "urgency": [
                "immediately", "urgent", "quickly", "now", "delay",
                "attempted", "processing", "right"
            ],
            "fear_or_threat": [
                "lose", "blocked", "frozen", "stolen", "legal", "police",
                "arrest", "penalty", "criminal", "danger", "risk"
            ],
            "account_compromise_claim": [
                "compromised", "unauthorized", "unauthorised", "suspicious",
                "hacked", "breach", "fraudulent", "access"
            ],
            "safe_account_claim": [
                "safe", "secure", "security", "protected", "temporary",
                "protect", "safety"
            ],
            "otp_pin_request": [
                "otp", "pin", "code", "password", "verification",
                "security"
            ],
            "remote_access_request": [
                "anydesk", "teamviewer", "remote", "screen", "sharing",
                "access", "control", "download", "install"
            ],
            "secrecy_request": [
                "secret", "confidential", "disconnect", "hang", "contact",
                "tell", "family", "line"
            ],
            "authority_impersonation": [
                "police", "cyber", "crime", "rbi", "reserve", "government",
                "court", "investigation", "officer", "law"
            ],
            "card_fraud_claim": [
                "debit", "card", "fraud", "suspicious", "compromised"
            ],
            "international_transaction_claim": [
                "international", "overseas", "foreign", "singapore",
                "dubai", "country", "cross", "border"
            ]
        }

    def analyse(self, text: str) -> Tuple[Dict[str, float], List[SemanticMatch]]:
        sentences = TextTools.split_sentences(text)

        if not sentences:
            return {}, []

        signal_scores = {
            signal: 0.0
            for signal in self.concepts
        }

        matches: List[SemanticMatch] = []

        for sentence in sentences:
            for signal_name, concept_phrases in self.concepts.items():
                best_score = 0.0
                best_concept = ""

                for concept in concept_phrases:
                    score = self._similarity(sentence, concept, signal_name)

                    if score > best_score:
                        best_score = score
                        best_concept = concept

                if best_score > signal_scores[signal_name]:
                    signal_scores[signal_name] = best_score

                if best_score >= 0.58:
                    matches.append(
                        SemanticMatch(
                            signal_name=signal_name,
                            phrase=sentence,
                            matched_concept=best_concept,
                            score=round(best_score, 3)
                        )
                    )

        return signal_scores, matches

    def _similarity(
        self,
        sentence: str,
        concept: str,
        signal_name: str
    ) -> float:
        sentence_clean = TextTools.normalize_for_matching(sentence)
        concept_clean = TextTools.normalize_for_matching(concept)

        if not sentence_clean or not concept_clean:
            return 0.0

        if concept_clean in sentence_clean:
            return 1.0

        sentence_tokens = set(TextTools.tokenize(sentence_clean))
        concept_tokens = set(TextTools.tokenize(concept_clean))

        if not sentence_tokens or not concept_tokens:
            return 0.0

        overlap = len(sentence_tokens.intersection(concept_tokens))
        union = len(sentence_tokens.union(concept_tokens))
        jaccard = overlap / union if union else 0.0

        concept_coverage = overlap / len(concept_tokens)

        boost = self._keyword_boost(sentence_tokens, signal_name)

        score = (jaccard * 0.40) + (concept_coverage * 0.45) + (boost * 0.15)

        return min(score, 1.0)

    def _keyword_boost(
        self,
        sentence_tokens: set,
        signal_name: str
    ) -> float:
        keywords = self.keyword_boosts.get(signal_name, [])

        if not keywords:
            return 0.0

        keyword_hits = sum(
            1
            for keyword in keywords
            if keyword in sentence_tokens
        )

        return min(keyword_hits / 3, 1.0)


# =============================================================================
# RULE ENGINE
# =============================================================================

class RuleEngine:
    def __init__(self) -> None:
        self.signal_patterns = self._build_signal_patterns()

    def _build_signal_patterns(self) -> Dict[str, Dict[str, Any]]:
        return {
            "financial_request": {
                "weight": 18,
                "patterns": [
                    r"\btransfer\b",
                    r"\btransfer the money\b",
                    r"\btransfer your money\b",
                    r"\btransfer your balance\b",
                    r"\btransfer funds\b",
                    r"\bsend money\b",
                    r"\bsend the money\b",
                    r"\bsend funds\b",
                    r"\bmove your money\b",
                    r"\bmove the money\b",
                    r"\bmove your funds\b",
                    r"\bmake a payment\b",
                    r"\bmake the payment\b",
                    r"\bwire transfer\b",
                    r"\bdeposit\b",
                    r"\bbeneficiary\b",
                    r"\brecipient\b",
                    r"\baccount number\b",
                    r"\bupi\b",
                    r"\bmobile banking.*transfer\b",
                    r"\bopen.*banking.*transfer\b",
                    r"\bsend.*available balance\b",
                    r"\bmove.*available balance\b",
                    r"\brelocate.*funds\b",
                    r"\bshift.*balance\b"
                ]
            },

            "bank_impersonation": {
                "weight": 15,
                "patterns": [
                    r"\bcalling from .* bank\b",
                    r"\bcalling from your bank\b",
                    r"\bfrom your bank\b",
                    r"\bfrom .* bank\b",
                    r"\bbank fraud department\b",
                    r"\bbank fraud prevention\b",
                    r"\bfraud prevention department\b",
                    r"\bfraud department\b",
                    r"\bfraud team\b",
                    r"\bbank representative\b",
                    r"\bbank officer\b",
                    r"\bsecurity department\b",
                    r"\bsecurity team\b",
                    r"\bcustomer care\b",
                    r"\bbank support\b",
                    r"\bbanking department\b",
                    r"\bcard security department\b",
                    r"\baccount security team\b"
                ]
            },

            "urgency": {
                "weight": 12,
                "patterns": [
                    r"\bimmediately\b",
                    r"\bright now\b",
                    r"\burgent\b",
                    r"\burgently\b",
                    r"\bact now\b",
                    r"\bquickly\b",
                    r"\bdo it now\b",
                    r"\bdo not delay\b",
                    r"\bdon't delay\b",
                    r"\bwithout delay\b",
                    r"\bas soon as possible\b",
                    r"\bbefore it is too late\b",
                    r"\bcurrently being attempted\b",
                    r"\bcurrently being processed\b",
                    r"\banother transaction.*attempted\b",
                    r"\btransaction.*being attempted\b",
                    r"\bwe have very little time\b",
                    r"\btime is running out\b",
                    r"\bcomplete.*immediately\b",
                    r"\bsecurity process.*immediately\b"
                ]
            },

            "fear_or_threat": {
                "weight": 12,
                "patterns": [
                    r"\baccount will be blocked\b",
                    r"\baccount will be frozen\b",
                    r"\baccount will be closed\b",
                    r"\byou will lose\b",
                    r"\byou may lose\b",
                    r"\blose your money\b",
                    r"\bmore money may be debited\b",
                    r"\badditional money may be debited\b",
                    r"\bfurther transactions could happen\b",
                    r"\bmoney will be stolen\b",
                    r"\bmoney can be stolen\b",
                    r"\blegal action\b",
                    r"\bpolice case\b",
                    r"\barrest\b",
                    r"\bpenalty\b",
                    r"\bfine\b",
                    r"\bcriminal\b",
                    r"\bserious consequences\b",
                    r"\byou may be arrested\b",
                    r"\byour account is in danger\b",
                    r"\byour money is at risk\b",
                    r"\bfunds are at risk\b"
                ]
            },

            "account_compromise_claim": {
                "weight": 12,
                "patterns": [
                    r"\baccount has been compromised\b",
                    r"\baccount is compromised\b",
                    r"\baccount was compromised\b",
                    r"\bcard has been compromised\b",
                    r"\bcard is compromised\b",
                    r"\bcard may have been compromised\b",
                    r"\bdebit card.*compromised\b",
                    r"\bbanking details.*compromised\b",
                    r"\bunauthorized access\b",
                    r"\bunauthorised access\b",
                    r"\bsuspicious activity\b",
                    r"\bsuspicious transaction\b",
                    r"\bsuspicious transactions\b",
                    r"\bsomeone accessed your account\b",
                    r"\bsomeone hacked your account\b",
                    r"\baccount has been hacked\b",
                    r"\baccount is hacked\b",
                    r"\bfraudulent activity\b",
                    r"\bsecurity breach\b",
                    r"\bcompromised.*banking details\b",
                    r"\bcompromised.*account\b"
                ]
            },

            "safe_account_claim": {
                "weight": 22,
                "patterns": [
                    r"\bsafe account\b",
                    r"\btemporary safe account\b",
                    r"\bsecure account\b",
                    r"\bsecurity account\b",
                    r"\bprotected account\b",
                    r"\btemporary account\b",
                    r"\btransfer your balance\b",
                    r"\bmove your balance\b",
                    r"\bprotect your money\b",
                    r"\bkeep your money safe\b",
                    r"\bsecure your money\b",
                    r"\bprotect your funds\b",
                    r"\bsecure your funds\b",
                    r"\btemporarily transfer\b",
                    r"\btemporary holding account\b",
                    r"\bbank safety account\b",
                    r"\bfor your protection.*transfer\b",
                    r"\bto protect.*funds\b",
                    r"\bto secure.*balance\b"
                ]
            },

            "otp_pin_request": {
                "weight": 25,
                "patterns": [
                    r"\btell me the otp\b",
                    r"\bshare the otp\b",
                    r"\bgive me the otp\b",
                    r"\bread out the otp\b",
                    r"\bprovide the otp\b",
                    r"\bshare your pin\b",
                    r"\btell me your pin\b",
                    r"\bgive me your pin\b",
                    r"\bverification code\b",
                    r"\bsecurity code\b",
                    r"\bone time password\b",
                    r"\bone-time password\b",
                    r"\bshare the code\b",
                    r"\bread the code\b",
                    r"\btell me the code\b",
                    r"\bconfirm.*otp\b",
                    r"\bconfirm.*code\b"
                ]
            },

            "remote_access_request": {
                "weight": 25,
                "patterns": [
                    r"\binstall anydesk\b",
                    r"\binstall teamviewer\b",
                    r"\binstall this app\b",
                    r"\bdownload this app\b",
                    r"\bremote access\b",
                    r"\bshare your screen\b",
                    r"\bscreen sharing\b",
                    r"\ballow access\b",
                    r"\bgive me access\b",
                    r"\bremote control\b",
                    r"\bcontrol your phone\b",
                    r"\bremote support\b",
                    r"\bopen.*remote.*app\b"
                ]
            },

            "secrecy_request": {
                "weight": 15,
                "patterns": [
                    r"\bdon't tell anyone\b",
                    r"\bdo not tell anyone\b",
                    r"\bdon't tell your family\b",
                    r"\bdo not tell your family\b",
                    r"\bkeep this confidential\b",
                    r"\bkeep this secret\b",
                    r"\bdo not contact the bank\b",
                    r"\bdon't contact the bank\b",
                    r"\bdo not contact anyone\b",
                    r"\bdon't contact anyone\b",
                    r"\bdo not contact anyone else\b",
                    r"\bdon't contact anyone else\b",
                    r"\bdo not disconnect\b",
                    r"\bdon't disconnect\b",
                    r"\bdo not disconnect the call\b",
                    r"\bdo not hang up\b",
                    r"\bdon't hang up\b",
                    r"\bstay on the line\b",
                    r"\bremain on the line\b",
                    r"\bdo not speak to anyone else\b",
                    r"\bdon't speak to anyone else\b",
                    r"\bfinish this process only with me\b",
                    r"\bstay connected\b"
                ]
            },

            "authority_impersonation": {
                "weight": 14,
                "patterns": [
                    r"\bpolice officer\b",
                    r"\bcyber crime\b",
                    r"\bcybercrime\b",
                    r"\brbi officer\b",
                    r"\breserve bank\b",
                    r"\bgovernment officer\b",
                    r"\bincome tax department\b",
                    r"\bcourt official\b",
                    r"\binvestigation officer\b",
                    r"\blaw enforcement\b",
                    r"\bgovernment department\b",
                    r"\bcrime branch\b",
                    r"\bofficial investigation\b"
                ]
            },

            "card_fraud_claim": {
                "weight": 9,
                "patterns": [
                    r"\bdebit card\b.*\bsuspicious\b",
                    r"\bcard.*suspicious transaction\b",
                    r"\bcard.*fraud\b",
                    r"\bdebit card.*compromised\b",
                    r"\bcard.*compromised\b",
                    r"\btransactions on your debit card\b",
                    r"\bcard.*international\b",
                    r"\binternational.*card\b"
                ]
            },

            "international_transaction_claim": {
                "weight": 8,
                "patterns": [
                    r"\binternational transaction\b",
                    r"\binternational transactions\b",
                    r"\boverseas transaction\b",
                    r"\boverseas transactions\b",
                    r"\bforeign transaction\b",
                    r"\bforeign transactions\b",
                    r"\btransaction.*singapore\b",
                    r"\btransactions.*singapore\b",
                    r"\btransaction.*dubai\b",
                    r"\btransactions.*dubai\b",
                    r"\bcross border transaction\b",
                    r"\bforeign payment\b",
                    r"\banother country\b"
                ]
            }
        }

    def analyse(self, text: str) -> Dict[str, SignalFinding]:
        clean_text = TextTools.normalize_for_matching(text)
        findings: Dict[str, SignalFinding] = {}

        for signal_name, config in self.signal_patterns.items():
            evidence = []
            detected = False

            for pattern in config["patterns"]:
                match = re.search(pattern, clean_text, re.IGNORECASE)

                if match:
                    detected = True
                    evidence.append(match.group(0))

            evidence = TextTools.unique_keep_order(evidence)

            rule_score = 1.0 if detected else 0.0

            findings[signal_name] = SignalFinding(
                name=signal_name,
                detected=detected,
                rule_score=rule_score,
                evidence=evidence[:5]
            )

        return findings

    def get_weight(self, signal_name: str) -> int:
        config = self.signal_patterns.get(signal_name, {})
        return int(config.get("weight", 0))


# =============================================================================
# SEMANTIC + RULE FUSION ENGINE
# =============================================================================

class SignalFusionEngine:
    def __init__(self) -> None:
        self.semantic_thresholds = {
            "financial_request": 0.58,
            "bank_impersonation": 0.58,
            "urgency": 0.56,
            "fear_or_threat": 0.57,
            "account_compromise_claim": 0.56,
            "safe_account_claim": 0.55,
            "otp_pin_request": 0.60,
            "remote_access_request": 0.60,
            "secrecy_request": 0.56,
            "authority_impersonation": 0.58,
            "card_fraud_claim": 0.58,
            "international_transaction_claim": 0.58
        }

    def fuse(
        self,
        rule_findings: Dict[str, SignalFinding],
        semantic_scores: Dict[str, float],
        semantic_matches: List[SemanticMatch]
    ) -> Dict[str, SignalFinding]:

        fused: Dict[str, SignalFinding] = {}

        semantic_evidence = self._group_semantic_evidence(semantic_matches)

        for signal_name, finding in rule_findings.items():
            semantic_score = semantic_scores.get(signal_name, 0.0)
            threshold = self.semantic_thresholds.get(signal_name, 0.58)

            semantic_detected = semantic_score >= threshold
            final_detected = finding.detected or semantic_detected

            if finding.detected and semantic_detected:
                final_score = max(0.92, semantic_score)
            elif finding.detected:
                final_score = 0.85
            elif semantic_detected:
                final_score = semantic_score
            else:
                final_score = max(finding.rule_score, semantic_score * 0.55)

            evidence = list(finding.evidence)

            for item in semantic_evidence.get(signal_name, []):
                if item not in evidence:
                    evidence.append(item)

            fused[signal_name] = SignalFinding(
                name=signal_name,
                detected=final_detected,
                rule_score=finding.rule_score,
                semantic_score=round(semantic_score, 3),
                final_score=round(final_score, 3),
                evidence=evidence[:6]
            )

        return fused

    @staticmethod
    def _group_semantic_evidence(
        semantic_matches: List[SemanticMatch]
    ) -> Dict[str, List[str]]:
        grouped: Dict[str, List[str]] = {}

        for match in semantic_matches:
            grouped.setdefault(match.signal_name, [])
            grouped[match.signal_name].append(match.phrase)

        for signal_name in grouped:
            grouped[signal_name] = TextTools.unique_keep_order(
                grouped[signal_name]
            )[:4]

        return grouped


# =============================================================================
# PSYCHOLOGY ENGINE
# =============================================================================

class PsychologyEngine:
    def analyse(
        self,
        findings: Dict[str, SignalFinding]
    ) -> PsychologyProfile:

        authority_pressure = self._score_average([
            findings["bank_impersonation"].final_score,
            findings["authority_impersonation"].final_score
        ])

        urgency_pressure = findings["urgency"].final_score

        fear_pressure = self._score_average([
            findings["fear_or_threat"].final_score,
            findings["account_compromise_claim"].final_score,
            findings["card_fraud_claim"].final_score,
            findings["international_transaction_claim"].final_score
        ])

        isolation_pressure = findings["secrecy_request"].final_score

        financial_control_pressure = self._score_average([
            findings["financial_request"].final_score,
            findings["safe_account_claim"].final_score,
            findings["otp_pin_request"].final_score,
            findings["remote_access_request"].final_score
        ])

        trust_exploitation = self._score_average([
            findings["bank_impersonation"].final_score,
            findings["safe_account_claim"].final_score,
            findings["account_compromise_claim"].final_score
        ])

        weighted_total = (
            authority_pressure * 0.16
            + urgency_pressure * 0.17
            + fear_pressure * 0.18
            + isolation_pressure * 0.17
            + financial_control_pressure * 0.20
            + trust_exploitation * 0.12
        )

        pattern_name, pattern_explanation = self._classify_pattern(findings)

        return PsychologyProfile(
            authority_pressure=round(authority_pressure, 3),
            urgency_pressure=round(urgency_pressure, 3),
            fear_pressure=round(fear_pressure, 3),
            isolation_pressure=round(isolation_pressure, 3),
            financial_control_pressure=round(financial_control_pressure, 3),
            trust_exploitation=round(trust_exploitation, 3),
            overall_manipulation=round(min(weighted_total, 1.0), 3),
            pattern_name=pattern_name,
            pattern_explanation=pattern_explanation
        )

    @staticmethod
    def _score_average(scores: List[float]) -> float:
        if not scores:
            return 0.0

        active_scores = [
            score
            for score in scores
            if score > 0
        ]

        if not active_scores:
            return 0.0

        return min(sum(active_scores) / len(active_scores), 1.0)

    def _classify_pattern(
        self,
        findings: Dict[str, SignalFinding]
    ) -> Tuple[str, str]:

        has_bank = findings["bank_impersonation"].detected
        has_authority = findings["authority_impersonation"].detected
        has_financial = findings["financial_request"].detected
        has_safe_account = findings["safe_account_claim"].detected
        has_otp = findings["otp_pin_request"].detected
        has_remote = findings["remote_access_request"].detected
        has_urgency = findings["urgency"].detected
        has_secrecy = findings["secrecy_request"].detected
        has_compromise = findings["account_compromise_claim"].detected

        if has_bank and has_safe_account and has_financial:
            return (
                "Bank impersonation safe-account scam",
                "The caller appears to impersonate a banking or fraud team, "
                "creates a security concern, and asks the customer to move "
                "money to a supposedly safe account."
            )

        if has_otp and (has_bank or has_authority):
            return (
                "Credential or OTP harvesting scam",
                "The caller appears to use authority or banking language to "
                "obtain sensitive authentication information such as an OTP, "
                "PIN, password, or verification code."
            )

        if has_remote:
            return (
                "Remote-access takeover scam",
                "The caller appears to request screen sharing, remote access, "
                "or installation of a support application that could allow "
                "control over the customer's device."
            )

        if has_authority and has_financial:
            return (
                "Authority impersonation payment coercion",
                "The caller appears to claim an official role and pressure "
                "the customer into making a financial transfer."
            )

        if has_compromise and has_urgency and has_financial:
            return (
                "Urgent account-compromise manipulation",
                "The caller creates fear about account compromise and then "
                "pushes the customer toward an immediate financial action."
            )

        if has_financial and has_secrecy:
            return (
                "Isolation-based financial manipulation",
                "The caller appears to request a financial action while also "
                "discouraging the customer from contacting other people."
            )

        if has_financial:
            return (
                "Suspicious financial request",
                "The call contains a request or pressure to perform a "
                "financial action."
            )

        return (
            "No clear scam psychology pattern",
            "The conversation does not strongly match the main scam "
            "psychology patterns used by this prototype."
        )


# =============================================================================
# SUMMARY ENGINE
# =============================================================================

class SummaryEngine:
    def build_call_summary(
        self,
        findings: Dict[str, SignalFinding],
        analysis_transcript: str
    ) -> str:

        points = []

        if findings["bank_impersonation"].detected:
            points.append(
                "Caller appears to claim a bank, fraud-prevention, "
                "customer-care, or security-team role."
            )

        if findings["authority_impersonation"].detected:
            points.append(
                "Caller appears to claim an official or authority role."
            )

        if findings["card_fraud_claim"].detected:
            points.append(
                "Caller refers to possible debit-card or card-related fraud."
            )

        if findings["international_transaction_claim"].detected:
            points.append(
                "Caller mentions international, overseas, or foreign "
                "transactions."
            )

        if findings["account_compromise_claim"].detected:
            points.append(
                "Caller claims the customer's account, card, or banking "
                "details may be compromised."
            )

        if findings["financial_request"].detected:
            points.append(
                "Caller asks or pressures the customer to perform a "
                "financial action."
            )

        if findings["safe_account_claim"].detected:
            points.append(
                "Caller suggests moving money to a safe, secure, protected, "
                "or temporary account."
            )

        if findings["otp_pin_request"].detected:
            points.append(
                "Caller appears to request an OTP, PIN, password, or "
                "verification code."
            )

        if findings["remote_access_request"].detected:
            points.append(
                "Caller appears to request remote access, screen sharing, "
                "or installation of an external app."
            )

        if findings["urgency"].detected:
            points.append(
                "Caller uses urgent language to make the customer act fast."
            )

        if findings["fear_or_threat"].detected:
            points.append(
                "Caller creates fear of financial loss, account restriction, "
                "or legal consequences."
            )

        if findings["secrecy_request"].detected:
            points.append(
                "Caller discourages the customer from disconnecting, "
                "contacting others, or verifying independently."
            )

        if not points:
            return (
                "The conversation does not contain strong financial "
                "social-engineering indicators according to this prototype."
            )

        return " ".join(points)

    def build_explanation(
        self,
        risk_level: str,
        scam_risk: float,
        psychology: PsychologyProfile,
        findings: Dict[str, SignalFinding]
    ) -> str:

        reasons = []

        if findings["bank_impersonation"].detected:
            reasons.append(
                "the caller appears to claim a banking or fraud-prevention role"
            )

        if findings["authority_impersonation"].detected:
            reasons.append(
                "the caller appears to claim an official authority role"
            )

        if findings["account_compromise_claim"].detected:
            reasons.append(
                "the caller claims the account, card, or banking details may "
                "be compromised"
            )

        if findings["international_transaction_claim"].detected:
            reasons.append(
                "the caller refers to international or overseas transactions"
            )

        if findings["financial_request"].detected:
            reasons.append(
                "the caller requests or pressures the customer to take a "
                "financial action"
            )

        if findings["safe_account_claim"].detected:
            reasons.append(
                "the caller suggests moving money to a supposedly safe account"
            )

        if findings["otp_pin_request"].detected:
            reasons.append(
                "the caller appears to request sensitive authentication "
                "information"
            )

        if findings["remote_access_request"].detected:
            reasons.append(
                "the caller appears to request remote or screen access"
            )

        if findings["urgency"].detected:
            reasons.append(
                "urgent language is used to pressure quick action"
            )

        if findings["fear_or_threat"].detected:
            reasons.append(
                "fear of loss or consequences is used as pressure"
            )

        if findings["secrecy_request"].detected:
            reasons.append(
                "the customer appears to be discouraged from disconnecting or "
                "contacting others"
            )

        if not reasons:
            return (
                f"{risk_level} risk. No major scam pattern was strongly "
                "detected by the rule and semantic analysis layers."
            )

        reason_text = self._join_reasons(reasons)

        return (
            f"{risk_level} risk. Scam risk is estimated at "
            f"{scam_risk * 100:.0f}%. The call is suspicious because "
            f"{reason_text}. Psychology pattern: "
            f"{psychology.pattern_name}. {psychology.pattern_explanation}"
        )

    @staticmethod
    def _join_reasons(reasons: List[str]) -> str:
        if len(reasons) == 1:
            return reasons[0]

        if len(reasons) == 2:
            return f"{reasons[0]} and {reasons[1]}"

        return ", ".join(reasons[:-1]) + ", and " + reasons[-1]


# =============================================================================
# RISK SCORING ENGINE
# =============================================================================

class RiskScoringEngine:
    def __init__(self, rule_engine: RuleEngine) -> None:
        self.rule_engine = rule_engine

    def calculate_scam_risk(
        self,
        findings: Dict[str, SignalFinding]
    ) -> float:
        weighted_score = 0.0

        for signal_name, finding in findings.items():
            weight = self.rule_engine.get_weight(signal_name)
            weighted_score += weight * finding.final_score

        weighted_score += self._combination_bonus(findings)

        return round(min(weighted_score / 100, 1.0), 3)

    def calculate_confidence(
        self,
        findings: Dict[str, SignalFinding],
        semantic_matches: List[SemanticMatch],
        analysis_transcript: str
    ) -> float:
        detected_count = sum(
            1
            for finding in findings.values()
            if finding.detected
        )

        evidence_count = sum(
            len(finding.evidence)
            for finding in findings.values()
        )

        transcript_length = len(TextTools.tokenize(analysis_transcript))

        confidence = 0.35

        if transcript_length >= 20:
            confidence += 0.15

        if transcript_length >= 50:
            confidence += 0.10

        if detected_count >= 2:
            confidence += 0.15

        if detected_count >= 4:
            confidence += 0.10

        if evidence_count >= 3:
            confidence += 0.08

        if len(semantic_matches) >= 2:
            confidence += 0.07

        return round(min(confidence, 0.98), 3)

    @staticmethod
    def calculate_manipulation_risk(
        psychology: PsychologyProfile,
        findings: Dict[str, SignalFinding]
    ) -> float:
        manipulation = psychology.overall_manipulation

        if (
            findings["safe_account_claim"].detected
            and findings["financial_request"].detected
        ):
            manipulation += 0.12

        if (
            findings["secrecy_request"].detected
            and findings["urgency"].detected
        ):
            manipulation += 0.10

        if (
            findings["fear_or_threat"].detected
            and findings["financial_request"].detected
        ):
            manipulation += 0.08

        if findings["otp_pin_request"].detected:
            manipulation += 0.10

        if findings["remote_access_request"].detected:
            manipulation += 0.10

        return round(min(manipulation, 1.0), 3)

    @staticmethod
    def get_risk_level(score: float) -> str:
        if score >= 0.70:
            return "HIGH"

        if score >= 0.40:
            return "MEDIUM"

        return "LOW"

    @staticmethod
    def recommended_action(
        risk_level: str,
        scam_risk: float,
        manipulation_risk: float,
        findings: Dict[str, SignalFinding]
    ) -> str:
        if findings["otp_pin_request"].detected:
            return "BLOCK_CALL_AND_WARN_CUSTOMER"

        if findings["remote_access_request"].detected:
            return "BLOCK_CALL_AND_WARN_CUSTOMER"

        if (
            findings["safe_account_claim"].detected
            and findings["financial_request"].detected
        ):
            return "SMART_TRANSIT_HOLD_REQUIRED"

        if scam_risk >= 0.75 or manipulation_risk >= 0.75:
            return "SMART_TRANSIT_HOLD_REQUIRED"

        if risk_level == "HIGH":
            return "HIGH_RISK_WARNING_AND_VERIFICATION"

        if risk_level == "MEDIUM":
            return "SHOW_WARNING_BEFORE_PAYMENT"

        return "ALLOW_NORMAL_MONITORING"

    @staticmethod
    def _combination_bonus(
        findings: Dict[str, SignalFinding]
    ) -> float:
        bonus = 0.0

        if (
            findings["bank_impersonation"].detected
            and findings["financial_request"].detected
        ):
            bonus += 12

        if (
            findings["financial_request"].detected
            and findings["urgency"].detected
        ):
            bonus += 8

        if (
            findings["account_compromise_claim"].detected
            and findings["financial_request"].detected
        ):
            bonus += 10

        if (
            findings["safe_account_claim"].detected
            and findings["financial_request"].detected
        ):
            bonus += 15

        if (
            findings["fear_or_threat"].detected
            and findings["urgency"].detected
        ):
            bonus += 7

        if (
            findings["secrecy_request"].detected
            and findings["financial_request"].detected
        ):
            bonus += 10

        if (
            findings["card_fraud_claim"].detected
            and findings["international_transaction_claim"].detected
        ):
            bonus += 6

        if (
            findings["bank_impersonation"].detected
            and findings["account_compromise_claim"].detected
            and findings["financial_request"].detected
        ):
            bonus += 10

        if findings["otp_pin_request"].detected:
            bonus += 8

        if findings["remote_access_request"].detected:
            bonus += 8

        return bonus


# =============================================================================
# LANGUAGE SUPPORT INFO
# =============================================================================

class LanguageSupport:
    """
    This class stores language-support messaging for the demo.

    Faster-Whisper performs the actual language detection and translation.
    This class only formats language names and risk disclaimers.
    """

    COMMON_LANGUAGE_NAMES = {
        "en": "English",
        "hi": "Hindi",
        "ur": "Urdu",
        "bn": "Bengali",
        "ta": "Tamil",
        "te": "Telugu",
        "ml": "Malayalam",
        "kn": "Kannada",
        "mr": "Marathi",
        "gu": "Gujarati",
        "pa": "Punjabi",
        "es": "Spanish",
        "fr": "French",
        "de": "German",
        "it": "Italian",
        "pt": "Portuguese",
        "ru": "Russian",
        "ar": "Arabic",
        "ja": "Japanese",
        "ko": "Korean",
        "zh": "Chinese",
        "tr": "Turkish",
        "id": "Indonesian",
        "vi": "Vietnamese",
        "th": "Thai"
    }

    @classmethod
    def display_name(cls, language_code: str) -> str:
        code = (language_code or "unknown").lower()

        if code in cls.COMMON_LANGUAGE_NAMES:
            return f"{cls.COMMON_LANGUAGE_NAMES[code]} ({code})"

        return language_code or "unknown"

    @staticmethod
    def support_message() -> str:
        return (
            "This prototype uses Faster-Whisper for multilingual speech "
            "recognition and English normalization. It can process many "
            "languages supported by Whisper, but quality can vary by accent, "
            "audio clarity, background noise, and code-switching."
        )


# =============================================================================
# FINAL CALL INTELLIGENCE ENGINE
# =============================================================================

class CallIntelligenceEngine:
    def __init__(self) -> None:
        self.rule_engine = RuleEngine()
        self.semantic_engine = LightweightSemanticEngine()
        self.signal_fusion_engine = SignalFusionEngine()
        self.psychology_engine = PsychologyEngine()
        self.summary_engine = SummaryEngine()
        self.scoring_engine = RiskScoringEngine(self.rule_engine)

    def analyse(
        self,
        analysis_transcript: str,
        original_transcript: Optional[str] = None,
        detected_language: str = "unknown"
    ) -> CallRiskResult:
        if not analysis_transcript or not analysis_transcript.strip():
            raise ValueError("Transcript cannot be empty.")

        if original_transcript is None:
            original_transcript = analysis_transcript

        analysis_transcript = analysis_transcript.strip()
        original_transcript = original_transcript.strip()

        rule_findings = self.rule_engine.analyse(analysis_transcript)

        semantic_scores, semantic_matches = self.semantic_engine.analyse(
            analysis_transcript
        )

        findings = self.signal_fusion_engine.fuse(
            rule_findings=rule_findings,
            semantic_scores=semantic_scores,
            semantic_matches=semantic_matches
        )

        psychology = self.psychology_engine.analyse(findings)

        scam_risk = self.scoring_engine.calculate_scam_risk(findings)

        manipulation_risk = self.scoring_engine.calculate_manipulation_risk(
            psychology=psychology,
            findings=findings
        )

        confidence = self.scoring_engine.calculate_confidence(
            findings=findings,
            semantic_matches=semantic_matches,
            analysis_transcript=analysis_transcript
        )

        risk_level = self.scoring_engine.get_risk_level(scam_risk)

        action = self.scoring_engine.recommended_action(
            risk_level=risk_level,
            scam_risk=scam_risk,
            manipulation_risk=manipulation_risk,
            findings=findings
        )

        detected_signals = self._detected_signal_names(findings)

        call_summary = self.summary_engine.build_call_summary(
            findings=findings,
            analysis_transcript=analysis_transcript
        )

        explanation = self.summary_engine.build_explanation(
            risk_level=risk_level,
            scam_risk=scam_risk,
            psychology=psychology,
            findings=findings
        )

        fusion_ready_summary = self._build_fusion_summary(
            scam_risk=scam_risk,
            manipulation_risk=manipulation_risk,
            confidence=confidence,
            risk_level=risk_level,
            action=action,
            findings=findings,
            psychology=psychology,
            detected_language=detected_language
        )

        return CallRiskResult(
            timestamp=datetime.now().isoformat(timespec="seconds"),
            module_version=MODULE_VERSION,

            scam_risk=scam_risk,
            manipulation_risk=manipulation_risk,
            confidence=confidence,
            risk_level=risk_level,
            recommended_action=action,

            financial_request=findings["financial_request"].detected,
            bank_impersonation=findings["bank_impersonation"].detected,
            urgency=findings["urgency"].detected,
            fear_or_threat=findings["fear_or_threat"].detected,
            account_compromise_claim=(
                findings["account_compromise_claim"].detected
            ),
            safe_account_claim=findings["safe_account_claim"].detected,
            otp_pin_request=findings["otp_pin_request"].detected,
            remote_access_request=findings["remote_access_request"].detected,
            secrecy_request=findings["secrecy_request"].detected,
            authority_impersonation=(
                findings["authority_impersonation"].detected
            ),
            card_fraud_claim=findings["card_fraud_claim"].detected,
            international_transaction_claim=(
                findings["international_transaction_claim"].detected
            ),

            detected_signals=detected_signals,

            signal_findings={
                signal_name: finding.to_dict()
                for signal_name, finding in findings.items()
            },

            semantic_matches=[
                match.to_dict()
                for match in semantic_matches[:12]
            ],

            psychology_profile=psychology.to_dict(),

            call_summary=call_summary,
            explanation=explanation,
            fusion_ready_summary=fusion_ready_summary,

            detected_language=detected_language,
            original_transcript=original_transcript,
            analysis_transcript=analysis_transcript
        )

    @staticmethod
    def _detected_signal_names(
        findings: Dict[str, SignalFinding]
    ) -> List[str]:
        names = []

        readable_names = {
            "financial_request": "Financial request",
            "bank_impersonation": "Bank impersonation",
            "urgency": "Urgency",
            "fear_or_threat": "Fear or threat",
            "account_compromise_claim": "Account compromise claim",
            "safe_account_claim": "Safe-account claim",
            "otp_pin_request": "OTP/PIN request",
            "remote_access_request": "Remote-access request",
            "secrecy_request": "Secrecy / isolation request",
            "authority_impersonation": "Authority impersonation",
            "card_fraud_claim": "Debit/card fraud claim",
            "international_transaction_claim": (
                "International transaction claim"
            )
        }

        for signal_name, finding in findings.items():
            if finding.detected:
                names.append(
                    readable_names.get(signal_name, signal_name)
                )

        return names

    @staticmethod
    def _build_fusion_summary(
        scam_risk: float,
        manipulation_risk: float,
        confidence: float,
        risk_level: str,
        action: str,
        findings: Dict[str, SignalFinding],
        psychology: PsychologyProfile,
        detected_language: str
    ) -> Dict[str, Any]:
        return {
            "module": "call_intelligence",
            "module_version": MODULE_VERSION,
            "scam_risk": scam_risk,
            "manipulation_risk": manipulation_risk,
            "confidence": confidence,
            "risk_level": risk_level,
            "recommended_action": action,
            "detected_language": detected_language,
            "cross_channel_relevant": (
                risk_level in {"MEDIUM", "HIGH"}
                or manipulation_risk >= 0.45
            ),
            "payment_intervention_recommended": (
                action == "SMART_TRANSIT_HOLD_REQUIRED"
            ),
            "primary_pattern": psychology.pattern_name,
            "high_value_flags": {
                "financial_request": findings["financial_request"].detected,
                "safe_account_claim": findings["safe_account_claim"].detected,
                "bank_impersonation": findings["bank_impersonation"].detected,
                "account_compromise_claim": (
                    findings["account_compromise_claim"].detected
                ),
                "urgency": findings["urgency"].detected,
                "secrecy_request": findings["secrecy_request"].detected,
                "otp_pin_request": findings["otp_pin_request"].detected,
                "remote_access_request": (
                    findings["remote_access_request"].detected
                )
            }
        }

    @staticmethod
    def display_result(result: CallRiskResult) -> None:
        language_name = LanguageSupport.display_name(
            result.detected_language
        )

        print()
        print("=" * 74)
        print(f"{APP_NAME} - {MODULE_NAME}")
        print("=" * 74)

        print(f"Version             : {result.module_version}")
        print(f"Detected Language   : {language_name}")
        print(f"Risk Level          : {result.risk_level}")
        print(f"Scam Risk           : {result.scam_risk * 100:.0f}%")
        print(
            f"Manipulation Risk   : "
            f"{result.manipulation_risk * 100:.0f}%"
        )
        print(f"Confidence          : {result.confidence * 100:.0f}%")
        print(f"Recommended Action  : {result.recommended_action}")

        print()
        print("Detected Signals")
        print("-" * 74)

        if result.detected_signals:
            for signal in result.detected_signals:
                print(f"[DETECTED] {signal}")
        else:
            print("No major risk signals detected.")

        print()
        print("Call Summary")
        print("-" * 74)
        print(result.call_summary)

        print()
        print("Psychology Pattern")
        print("-" * 74)
        psychology = result.psychology_profile
        print(f"Pattern: {psychology.get('pattern_name', 'Unknown')}")
        print(psychology.get("pattern_explanation", ""))

        print()
        print("Risk Explanation")
        print("-" * 74)
        print(result.explanation)

        print()
        print("Fusion-Ready Summary")
        print("-" * 74)
        print(
            json.dumps(
                result.fusion_ready_summary,
                indent=4,
                ensure_ascii=False
            )
        )

        print()
        print("Structured Output")
        print("-" * 74)
        print(result.to_json())

        print("=" * 74)


# =============================================================================
# TRANSCRIPTION DISPLAY
# =============================================================================

def display_transcription(transcription: TranscriptionResult) -> None:
    language_name = LanguageSupport.display_name(
        transcription.detected_language
    )

    print()
    print("=" * 74)
    print("MULTILINGUAL SPEECH-TO-TEXT RESULT")
    print("=" * 74)

    print(f"Audio file          : {Path(transcription.audio_file).name}")
    print(f"Detected language   : {language_name}")
    print(
        f"Language confidence : "
        f"{transcription.language_probability * 100:.1f}%"
    )
    print(
        f"Audio duration      : "
        f"{transcription.duration_seconds:.1f} sec"
    )
    print(
        f"Processing time     : "
        f"{transcription.processing_seconds:.1f} sec"
    )
    print(f"Translation used    : {transcription.translation_used}")

    print()
    print("ORIGINAL TRANSCRIPT")
    print("-" * 74)
    print(transcription.original_transcript)

    print()
    print("ENGLISH ANALYSIS TRANSCRIPT")
    print("-" * 74)
    print(transcription.analysis_transcript)

    print("=" * 74)


# =============================================================================
# DEMO SCENARIOS
# =============================================================================

def get_demo_scenarios() -> Dict[str, Dict[str, str]]:
    return {
        "1": {
            "name": "Normal Banking Call",
            "transcript": (
                "Hello. This is a reminder that your bank branch will be "
                "closed on Sunday. You can use the official banking "
                "application for normal services. Thank you."
            )
        },

        "2": {
            "name": "Fake Bank Safe-Account Scam",
            "transcript": (
                "Hello, I am calling from your bank fraud prevention "
                "department. We have detected suspicious international "
                "transactions on your debit card. Your card may have been "
                "compromised. Another transaction is currently being "
                "attempted. Transfer your balance to our temporary safe "
                "account immediately. Do not disconnect the call and do not "
                "contact anyone else until the security process is complete."
            )
        },

        "3": {
            "name": "OTP Scam",
            "transcript": (
                "This is your bank security team. We detected suspicious "
                "activity on your account. Tell me the OTP that was just "
                "sent to your phone so I can stop the transaction "
                "immediately."
            )
        },

        "4": {
            "name": "Remote Access Scam",
            "transcript": (
                "I am from customer care. There is a technical problem with "
                "your banking application. Download this app and share your "
                "screen with me so I can fix your account."
            )
        },

        "5": {
            "name": "Authority Impersonation Scam",
            "transcript": (
                "I am an investigation officer from the cyber crime "
                "department. Your bank account is connected to a criminal "
                "case. Transfer the money immediately or legal action will "
                "be taken. Do not tell anyone about this investigation."
            )
        },

        "6": {
            "name": "Semantic Safe-Account Scam",
            "transcript": (
                "For your protection, you must relocate your available funds "
                "to the account I provide. This is only temporary, and the "
                "money will be returned after our verification process is "
                "complete. Please stay on the line and do not speak to anyone "
                "else until we finish."
            )
        },

        "7": {
            "name": "Hinglish Normalized Demo",
            "transcript": (
                "Hello sir, I am calling from ABC Bank fraud prevention "
                "department. We have detected multiple suspicious "
                "transactions on your debit card. Your card may be "
                "compromised. Please open your mobile banking application "
                "and transfer your available balance to a temporary safe "
                "account immediately. Do not disconnect the call and do not "
                "contact anyone else."
            )
        }
    }


# =============================================================================
# DEMO AND MANUAL ANALYSIS HELPERS
# =============================================================================

def analyse_demo_transcript(engine: CallIntelligenceEngine) -> None:
    scenarios = get_demo_scenarios()

    print()
    print("Demo Transcript Scenarios")
    print("-" * 74)

    for key, scenario in scenarios.items():
        print(f"{key}. {scenario['name']}")

    print()

    choice = input("Select demo: ").strip()

    if choice not in scenarios:
        print()
        print("Invalid demo option.")
        return

    transcript = scenarios[choice]["transcript"]

    print()
    print("Transcript")
    print("-" * 74)
    print(transcript)

    result = engine.analyse(
        analysis_transcript=transcript,
        original_transcript=transcript,
        detected_language="en"
    )

    engine.display_result(result)


def analyse_manual_transcript(engine: CallIntelligenceEngine) -> None:
    print()
    print("MANUAL TRANSCRIPT ANALYSIS")
    print("-" * 74)
    print("Enter a transcript or English-normalized transcript.")
    print("Press ENTER twice when finished.")
    print()

    lines = []

    while True:
        line = input()

        if line == "":
            break

        lines.append(line)

    transcript = " ".join(lines).strip()

    if not transcript:
        print()
        print("No transcript entered.")
        return

    result = engine.analyse(
        analysis_transcript=transcript,
        original_transcript=transcript,
        detected_language="manual"
    )

    engine.display_result(result)


# =============================================================================
# QUICK SELF TEST
# =============================================================================

def run_quick_self_test() -> None:
    engine = CallIntelligenceEngine()
    scenarios = get_demo_scenarios()

    print()
    print("=" * 74)
    print("CALL INTELLIGENCE V4 QUICK SELF TEST")
    print("=" * 74)

    for key, scenario in scenarios.items():
        result = engine.analyse(
            analysis_transcript=scenario["transcript"],
            original_transcript=scenario["transcript"],
            detected_language="en"
        )

        print()
        print(f"Test {key}: {scenario['name']}")
        print("-" * 74)
        print(f"Risk Level         : {result.risk_level}")
        print(f"Scam Risk          : {result.scam_risk * 100:.0f}%")
        print(
            f"Manipulation Risk  : "
            f"{result.manipulation_risk * 100:.0f}%"
        )
        print(f"Confidence         : {result.confidence * 100:.0f}%")
        print(f"Recommended Action : {result.recommended_action}")

    print()
    print("=" * 74)
    print("Self test finished.")
    print("=" * 74)


# =============================================================================
# SPEECH-TO-TEXT ENGINE
# =============================================================================

class SpeechToTextEngine:
    def __init__(
        self,
        model_size: str = WHISPER_MODEL_SIZE,
        device: str = WHISPER_DEVICE,
        compute_type: str = WHISPER_COMPUTE_TYPE
    ) -> None:
        self.model_size = model_size
        self.device = device
        self.compute_type = compute_type

        self.model = None
        self.whisper_available = False
        self.WhisperModel = None

        self._check_whisper()

    def _check_whisper(self) -> None:
        try:
            from faster_whisper import WhisperModel

            self.WhisperModel = WhisperModel
            self.whisper_available = True

        except ImportError:
            self.WhisperModel = None
            self.whisper_available = False

    def load_model(self) -> None:
        if not self.whisper_available:
            raise RuntimeError(
                "Faster-Whisper is not installed.\n\n"
                "Open Command Prompt and run:\n"
                "py -m pip install faster-whisper"
            )

        if self.model is not None:
            return

        print()
        print("-" * 74)
        print("Loading multilingual speech-to-text model...")
        print(f"Model        : {self.model_size}")
        print(f"Device       : {self.device}")
        print(f"Compute type : {self.compute_type}")
        print("-" * 74)

        start_time = time.time()

        self.model = self.WhisperModel(
            self.model_size,
            device=self.device,
            compute_type=self.compute_type
        )

        elapsed = time.time() - start_time

        print()
        print(f"Speech-to-text model ready ({elapsed:.1f} seconds).")

    @staticmethod
    def _collect_segments(segments) -> str:
        parts = []

        for segment in segments:
            text = segment.text.strip()

            if text:
                parts.append(text)

        return " ".join(parts).strip()

    @staticmethod
    def _validate_audio_path(audio_path: str) -> Path:
        path = Path(audio_path.strip().strip('"'))

        if not path.exists():
            raise FileNotFoundError(f"Audio file not found:\n{path}")

        if not path.is_file():
            raise ValueError("The supplied path is not a file.")

        supported_extensions = {
            ".wav",
            ".mp3",
            ".m4a",
            ".flac",
            ".ogg",
            ".aac",
            ".wma",
            ".mp4"
        }

        if path.suffix.lower() not in supported_extensions:
            print()
            print(
                f"Warning: '{path.suffix}' is not one of the commonly "
                "tested audio formats."
            )

        return path

    def transcribe(self, audio_path: str) -> TranscriptionResult:
        audio_file = self._validate_audio_path(audio_path)

        self.load_model()

        print()
        print("-" * 74)
        print("Step 1: Creating original-language transcript...")
        print(f"File: {audio_file.name}")
        print("-" * 74)

        start_time = time.time()

        original_segments, original_info = self.model.transcribe(
            str(audio_file),
            beam_size=5,
            vad_filter=True,
            task="transcribe"
        )

        original_transcript = self._collect_segments(original_segments)

        if not original_transcript:
            raise ValueError("No speech could be detected in the audio file.")

        detected_language = getattr(original_info, "language", "unknown")
        language_probability = float(
            getattr(original_info, "language_probability", 0.0)
        )
        duration = float(getattr(original_info, "duration", 0.0))

        print()
        print(
            "Detected language: "
            f"{LanguageSupport.display_name(detected_language)}"
        )
        print(f"Language confidence: {language_probability * 100:.1f}%")

        translation_used = False
        analysis_transcript = original_transcript

        if detected_language.lower() != "en":
            print()
            print("-" * 74)
            print("Step 2: Normalizing conversation into English...")
            print("-" * 74)

            translated_segments, _ = self.model.transcribe(
                str(audio_file),
                beam_size=5,
                vad_filter=True,
                task="translate"
            )

            translated_text = self._collect_segments(translated_segments)

            if translated_text:
                analysis_transcript = translated_text
                translation_used = True

        else:
            print()
            print("English audio detected. Translation is not required.")

        processing_seconds = time.time() - start_time

        return TranscriptionResult(
            audio_file=str(audio_file),
            detected_language=detected_language,
            language_probability=round(language_probability, 3),
            duration_seconds=round(duration, 2),
            processing_seconds=round(processing_seconds, 2),
            original_transcript=original_transcript,
            analysis_transcript=analysis_transcript,
            translation_used=translation_used
        )


# =============================================================================
# AUDIO ANALYSIS
# =============================================================================

def analyse_audio_file(
    call_engine: CallIntelligenceEngine,
    speech_engine: SpeechToTextEngine
) -> None:
    print()
    print("MULTILINGUAL AUDIO CALL ANALYSIS")
    print("-" * 74)
    print(LanguageSupport.support_message())
    print()
    print("Common formats: WAV, MP3, M4A, FLAC, OGG, AAC, WMA and MP4")
    print()

    audio_path = input("Enter full audio file path: ").strip()

    if not audio_path:
        print()
        print("No audio file selected.")
        return

    try:
        transcription = speech_engine.transcribe(audio_path)

        display_transcription(transcription)

        print()
        print("Sending normalized conversation to Call Intelligence...")

        result = call_engine.analyse(
            analysis_transcript=transcription.analysis_transcript,
            original_transcript=transcription.original_transcript,
            detected_language=transcription.detected_language
        )

        call_engine.display_result(result)

    except FileNotFoundError as error:
        print()
        print("ERROR")
        print("-" * 74)
        print(error)

    except RuntimeError as error:
        print()
        print("ERROR")
        print("-" * 74)
        print(error)

    except ValueError as error:
        print()
        print("ERROR")
        print("-" * 74)
        print(error)

    except Exception as error:
        print()
        print("Unexpected audio-processing error:")
        print(f"{type(error).__name__}: {error}")


# =============================================================================
# EXPORT HELPERS
# =============================================================================

def save_result_to_json(result: CallRiskResult) -> None:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"call_risk_result_{timestamp}.json"

    output_path = Path(filename)

    with output_path.open("w", encoding="utf-8") as file:
        file.write(result.to_json())

    print()
    print(f"Result saved to: {output_path.resolve()}")


def analyse_and_export_manual(engine: CallIntelligenceEngine) -> None:
    print()
    print("MANUAL TRANSCRIPT ANALYSIS + JSON EXPORT")
    print("-" * 74)
    print("Enter a transcript or English-normalized transcript.")
    print("Press ENTER twice when finished.")
    print()

    lines = []

    while True:
        line = input()

        if line == "":
            break

        lines.append(line)

    transcript = " ".join(lines).strip()

    if not transcript:
        print()
        print("No transcript entered.")
        return

    result = engine.analyse(
        analysis_transcript=transcript,
        original_transcript=transcript,
        detected_language="manual"
    )

    engine.display_result(result)
    save_result_to_json(result)


def analyse_audio_and_export(
    call_engine: CallIntelligenceEngine,
    speech_engine: SpeechToTextEngine
) -> None:
    print()
    print("MULTILINGUAL AUDIO ANALYSIS + JSON EXPORT")
    print("-" * 74)
    print(LanguageSupport.support_message())
    print()

    audio_path = input("Enter full audio file path: ").strip()

    if not audio_path:
        print()
        print("No audio file selected.")
        return

    try:
        transcription = speech_engine.transcribe(audio_path)

        display_transcription(transcription)

        result = call_engine.analyse(
            analysis_transcript=transcription.analysis_transcript,
            original_transcript=transcription.original_transcript,
            detected_language=transcription.detected_language
        )

        call_engine.display_result(result)
        save_result_to_json(result)

    except Exception as error:
        print()
        print("ERROR")
        print("-" * 74)
        print(f"{type(error).__name__}: {error}")


# =============================================================================
# SYSTEM INFORMATION
# =============================================================================

def show_system_info(speech_engine: SpeechToTextEngine) -> None:
    print()
    print("=" * 74)
    print("SYSTEM INFORMATION")
    print("=" * 74)

    print(f"Application         : {APP_NAME}")
    print(f"Module              : {MODULE_NAME}")
    print(f"Version             : {MODULE_VERSION}")
    print(f"Whisper model       : {speech_engine.model_size}")
    print(f"Whisper device      : {speech_engine.device}")
    print(f"Compute type        : {speech_engine.compute_type}")

    whisper_status = (
        "INSTALLED"
        if speech_engine.whisper_available
        else "NOT INSTALLED"
    )

    print(f"Faster-Whisper      : {whisper_status}")
    print("Multilingual mode   : ENABLED")
    print("English normalize   : ENABLED")
    print("Semantic layer      : ENABLED")
    print("Psychology engine   : ENABLED")
    print("Fusion-ready output : ENABLED")

    print()
    print("Language Support Note")
    print("-" * 74)
    print(LanguageSupport.support_message())

    print()
    print("Recommended install command")
    print("-" * 74)
    print("py -m pip install faster-whisper")

    print("=" * 74)


# =============================================================================
# MENU
# =============================================================================

def display_main_menu() -> None:
    print()
    print("=" * 74)
    print(f"{APP_NAME} - {MODULE_NAME} {MODULE_VERSION}")
    print("=" * 74)

    print()
    print("1. Analyse demo transcript")
    print("2. Enter my own transcript")
    print("3. Analyse multilingual audio file")
    print("4. Manual transcript analysis + export JSON")
    print("5. Audio analysis + export JSON")
    print("6. Quick self test")
    print("7. System information")
    print("0. Exit")
    print()


def pause() -> None:
    print()
    input("Press ENTER to return to the main menu...")


# =============================================================================
# MAIN PROGRAM
# =============================================================================

def main() -> None:
    call_engine = CallIntelligenceEngine()
    speech_engine = SpeechToTextEngine()

    while True:
        display_main_menu()

        choice = input("Select option: ").strip()

        if choice == "1":
            try:
                analyse_demo_transcript(call_engine)
            except ValueError as error:
                print()
                print(f"Error: {error}")

            pause()

        elif choice == "2":
            try:
                analyse_manual_transcript(call_engine)
            except ValueError as error:
                print()
                print(f"Error: {error}")

            pause()

        elif choice == "3":
            analyse_audio_file(call_engine, speech_engine)
            pause()

        elif choice == "4":
            analyse_and_export_manual(call_engine)
            pause()

        elif choice == "5":
            analyse_audio_and_export(call_engine, speech_engine)
            pause()

        elif choice == "6":
            run_quick_self_test()
            pause()

        elif choice == "7":
            show_system_info(speech_engine)
            pause()

        elif choice == "0":
            print()
            print("Call Intelligence Engine closed.")
            break

        else:
            print()
            print("Invalid option. Please choose 0 to 7.")
            pause()


if __name__ == "__main__":
    main()
