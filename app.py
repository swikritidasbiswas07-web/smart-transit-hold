"""
Smart Transit Hold
Flask Backend API + Frontend Pages + Hold Actions + Verified Release + Mobile Report Upload

Version 2.5

Run:
    py app.py

Open:
    http://127.0.0.1:5000/
"""

import json
import threading
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from werkzeug.utils import secure_filename

from call_intelligence_v4_final import (
    CallIntelligenceEngine,
    SpeechToTextEngine
)

from risk_fusion import RiskFusionEngine


# =============================================================================
# OPTIONAL BANK SECURITY V7 IMPORT
# =============================================================================

BANK_V7_AVAILABLE = False
BANK_V7_IMPORT_ERROR = None
bank_v7_module = None

try:
    import bank_security_v7 as bank_v7_module
    BANK_V7_AVAILABLE = True
except Exception as error:
    BANK_V7_AVAILABLE = False
    BANK_V7_IMPORT_ERROR = f"{type(error).__name__}: {error}"


# =============================================================================
# FLASK SETUP
# =============================================================================

app = Flask(__name__)
CORS(app)

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app.config["MAX_CONTENT_LENGTH"] = 80 * 1024 * 1024

call_engine = CallIntelligenceEngine()
speech_engine = SpeechToTextEngine()
fusion_engine = RiskFusionEngine()

LATEST_CALL_RESULT = None
LATEST_TRANSCRIPTION_RESULT = None
LATEST_TRANSACTION_RESULT = None
LATEST_FUSION_RESULT = None
LATEST_MOBILE_REPORT = None


# =============================================================================
# RESPONSE HELPERS
# =============================================================================

def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def success_response(data, status_code=200):
    return jsonify({
        "success": True,
        "timestamp": now_iso(),
        "data": data
    }), status_code


def error_response(message, status_code=400):
    return jsonify({
        "success": False,
        "timestamp": now_iso(),
        "error": message
    }), status_code


def safe_float(value, default=0.0):
    try:
        if value is None:
            return default

        value = float(value)

        if value > 1.0:
            value = value / 100.0

        return max(0.0, min(value, 1.0))

    except Exception:
        return default


def safe_amount(value, default=0.0):
    try:
        if value is None:
            return default

        text = str(value)
        text = text.replace("₹", "")
        text = text.replace(",", "")
        text = text.strip()

        return max(0.0, float(text))

    except Exception:
        return default


def safe_bool(value, default=False):
    if isinstance(value, bool):
        return value

    if value is None:
        return default

    if isinstance(value, (int, float)):
        return bool(value)

    text = str(value).strip().lower()

    if text in {"true", "yes", "y", "1"}:
        return True

    if text in {"false", "no", "n", "0"}:
        return False

    return default


# =============================================================================
# AUDIT LOGGING MODULE (JSON-BASED STORAGE)
# =============================================================================

AUDIT_LOG_FILE = BASE_DIR / "audit_logs.json"
AUDIT_LOG_LOCK = threading.Lock()


def read_audit_logs():
    if not AUDIT_LOG_FILE.exists():
        return []

    try:
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return []
    except Exception as error:
        print(f"[AUDIT] Warning reading audit_logs.json: {error}")
        return []


def write_audit_logs(logs):
    try:
        with open(AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
        return True
    except Exception as error:
        print(f"[AUDIT] Error writing to audit_logs.json: {error}")
        return False


def log_audit_event(event_type, description, status, metadata=None):
    """
    Centralized audit logging function.
    Stores records in audit_logs.json containing:
    - id
    - timestamp
    - event_type
    - description
    - status
    - metadata
    """
    record = {
        "id": str(uuid4()),
        "timestamp": now_iso(),
        "event_type": str(event_type).upper(),
        "description": str(description),
        "status": str(status).upper(),
        "metadata": metadata if isinstance(metadata, dict) else {}
    }

    with AUDIT_LOG_LOCK:
        logs = read_audit_logs()
        logs.append(record)
        write_audit_logs(logs)

    return record


# =============================================================================
# TRANSACTION RISK ADAPTER
# =============================================================================

def fallback_transaction_analysis(data):
    amount = safe_amount(data.get("amount"), 0.0)
    recipient_id = str(data.get("recipient_id", "ACC_UNKNOWN")).strip()
    recipient_status = str(data.get("recipient_status", "UNKNOWN")).upper()
    device_id = str(data.get("device_id", "UNKNOWN_DEVICE")).strip()
    location = str(data.get("location", "UNKNOWN")).strip()

    new_recipient = safe_bool(data.get("new_recipient"), False)
    unusual_device = safe_bool(data.get("unusual_device"), False)
    unusual_location = safe_bool(data.get("unusual_location"), False)
    rapid_transactions = safe_bool(data.get("rapid_transactions"), False)
    previous_denial = safe_bool(data.get("previous_denial"), False)
    unusual_hour = safe_bool(data.get("unusual_hour"), False)

    high_amount = amount >= 50000

    recipient_risk_score = 0.10

    if recipient_status == "BLACKLISTED":
        recipient_risk_score = 1.0
    elif recipient_status in {"SUSPECTED", "HIGH_RISK"}:
        recipient_risk_score = 0.75
    elif recipient_status in {"UNKNOWN", "NEW"}:
        recipient_risk_score = 0.45

    risk = 0.10

    if high_amount:
        risk += 0.25

    if new_recipient:
        risk += 0.18

    if unusual_device:
        risk += 0.14

    if unusual_location:
        risk += 0.12

    if rapid_transactions:
        risk += 0.10

    if previous_denial:
        risk += 0.18

    if unusual_hour:
        risk += 0.06

    risk += recipient_risk_score * 0.20
    risk = round(min(risk, 1.0), 3)

    if risk >= 0.70:
        risk_level = "HIGH"
    elif risk >= 0.40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    decision = "PENDING_SECURITY_CHECK" if risk_level == "HIGH" else "PENDING"

    return {
        "timestamp": now_iso(),
        "transaction_id": data.get("transaction_id", "TX_FLASK_001"),
        "customer_id": data.get("customer_id", "USR_904"),
        "amount": amount,
        "recipient_id": recipient_id,
        "recipient_status": recipient_status,
        "risk_level": risk_level,
        "transaction_risk": risk,
        "ml_probability": risk,
        "rule_score": risk,
        "decision": decision,
        "source": "fallback_transaction_adapter",
        "device_id": device_id,
        "location": location,
        "signals": {
            "new_recipient": new_recipient,
            "high_amount": high_amount,
            "unusual_location": unusual_location,
            "unusual_device": unusual_device,
            "rapid_transactions": rapid_transactions,
            "previous_denial": previous_denial,
            "unusual_hour": unusual_hour
        }
    }


def try_bank_v7_transaction_analysis(data):
    if not BANK_V7_AVAILABLE or bank_v7_module is None:
        return fallback_transaction_analysis(data)

    possible_function_names = [
        "analyse_transaction",
        "analyze_transaction",
        "process_transaction",
        "create_transaction",
        "make_transaction",
        "run_transaction",
        "submit_transaction"
    ]

    for function_name in possible_function_names:
        function = getattr(bank_v7_module, function_name, None)

        if callable(function):
            try:
                result = function(
                    customer_id=data.get("customer_id", "USR_904"),
                    amount=safe_amount(data.get("amount"), 0.0),
                    recipient_id=data.get("recipient_id", "ACC_UNKNOWN"),
                    location=data.get("location", "Mumbai"),
                    device_id=data.get("device_id", "MY_IPHONE")
                )
                return normalize_transaction_result(result, data)

            except TypeError:
                try:
                    result = function(data)
                    return normalize_transaction_result(result, data)
                except Exception:
                    continue

            except Exception:
                continue

    possible_class_names = [
        "BankSecuritySystem",
        "BankSecurityEngine",
        "SmartTransitHoldSystem",
        "SmartTransitHoldEngine",
        "TransactionSecurityEngine",
        "BankSecurityV7"
    ]

    for class_name in possible_class_names:
        cls = getattr(bank_v7_module, class_name, None)

        if cls is None:
            continue

        try:
            instance = cls()
        except Exception:
            continue

        for method_name in possible_function_names:
            method = getattr(instance, method_name, None)

            if not callable(method):
                continue

            try:
                result = method(
                    customer_id=data.get("customer_id", "USR_904"),
                    amount=safe_amount(data.get("amount"), 0.0),
                    recipient_id=data.get("recipient_id", "ACC_UNKNOWN"),
                    location=data.get("location", "Mumbai"),
                    device_id=data.get("device_id", "MY_IPHONE")
                )
                return normalize_transaction_result(result, data)

            except TypeError:
                try:
                    result = method(data)
                    return normalize_transaction_result(result, data)
                except Exception:
                    continue

            except Exception:
                continue

    return fallback_transaction_analysis(data)


def normalize_transaction_result(result, original_data):
    if result is None:
        return fallback_transaction_analysis(original_data)

    if hasattr(result, "to_dict") and callable(result.to_dict):
        result = result.to_dict()

    if not isinstance(result, dict):
        return fallback_transaction_analysis(original_data)

    amount = safe_amount(
        result.get("amount", original_data.get("amount", 0.0))
    )

    risk_level = str(
        result.get(
            "risk_level",
            result.get("transaction_risk_level", "LOW")
        )
    ).upper()

    transaction_risk = safe_float(
        result.get(
            "transaction_risk",
            result.get(
                "risk_score",
                result.get(
                    "hybrid_risk_score",
                    result.get("final_risk", None)
                )
            )
        ),
        default=risk_level_to_score(risk_level)
    )

    ml_probability = safe_float(
        result.get(
            "ml_probability",
            result.get(
                "fraud_probability",
                result.get("model_probability", transaction_risk)
            )
        ),
        default=transaction_risk
    )

    rule_score = safe_float(
        result.get(
            "rule_score",
            result.get("rule_risk", transaction_risk)
        ),
        default=transaction_risk
    )

    signals = result.get("signals", result.get("risk_signals", {}))

    if not isinstance(signals, dict):
        signals = {}

    recipient_status = str(
        result.get(
            "recipient_status",
            original_data.get("recipient_status", "UNKNOWN")
        )
    ).upper()

    return {
        "timestamp": result.get("timestamp", now_iso()),
        "transaction_id": result.get(
            "transaction_id",
            result.get("tx_id", "TX_FLASK_001")
        ),
        "customer_id": result.get(
            "customer_id",
            original_data.get("customer_id", "USR_904")
        ),
        "amount": amount,
        "recipient_id": result.get(
            "recipient_id",
            original_data.get("recipient_id", "ACC_UNKNOWN")
        ),
        "recipient_status": recipient_status,
        "risk_level": risk_level,
        "transaction_risk": transaction_risk,
        "ml_probability": ml_probability,
        "rule_score": rule_score,
        "decision": result.get("decision", result.get("status", "PENDING")),
        "source": "bank_security_v7",
        "signals": {
            "new_recipient": safe_bool(
                result.get("new_recipient", signals.get("new_recipient")),
                safe_bool(original_data.get("new_recipient"), False)
            ),
            "high_amount": safe_bool(
                result.get("high_amount", signals.get("high_amount")),
                amount >= 50000
            ),
            "unusual_location": safe_bool(
                result.get("unusual_location", signals.get("unusual_location")),
                safe_bool(original_data.get("unusual_location"), False)
            ),
            "unusual_device": safe_bool(
                result.get("unusual_device", signals.get("unusual_device")),
                safe_bool(original_data.get("unusual_device"), False)
            ),
            "rapid_transactions": safe_bool(
                result.get("rapid_transactions", signals.get("rapid_transactions")),
                safe_bool(original_data.get("rapid_transactions"), False)
            ),
            "previous_denial": safe_bool(
                result.get("previous_denial", signals.get("previous_denial")),
                safe_bool(original_data.get("previous_denial"), False)
            ),
            "unusual_hour": safe_bool(
                result.get("unusual_hour", signals.get("unusual_hour")),
                safe_bool(original_data.get("unusual_hour"), False)
            )
        },
        "raw_v7_result": result
    }


def risk_level_to_score(risk_level):
    risk_level = str(risk_level).upper()

    if risk_level == "HIGH":
        return 0.85

    if risk_level == "MEDIUM":
        return 0.55

    return 0.20


# =============================================================================
# FRONTEND PAGE ROUTES
# =============================================================================

@app.route("/")
def login_page():
    return render_template("login.html")


@app.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")


@app.route("/mobile-report")
def mobile_report_page():
    return render_template("mobile_report.html")


@app.route("/risk-detection")
def risk_detection_page():
    return render_template("risk_detection.html")


@app.route("/transfer-page")
def transfer_page():
    return render_template("transfer.html")


@app.route("/result")
def result_page():
    return render_template("result.html")


@app.route("/verify-release")
def verify_release_page():
    return render_template("verify_release.html")


@app.route("/history")
def history_page():
    return render_template("history.html")


# =============================================================================
# API ROUTES
# =============================================================================

@app.route("/api")
def api_home():
    return jsonify({
        "app": "Smart Transit Hold",
        "backend": "running",
        "message": "Flask API is online",
        "frontend_routes": {
            "login": "GET /",
            "dashboard": "GET /dashboard",
            "mobile_report": "GET /mobile-report",
            "risk_detection": "GET /risk-detection",
            "transfer_page": "GET /transfer-page",
            "result": "GET /result",
            "verify_release": "GET /verify-release",
            "history": "GET /history"
        },
        "api_routes": {
            "health": "GET /health",
            "audit_log": "GET /api/audit-log",
            "analyze_call_text": "POST /api/analyze-call-text",
            "analyze_call_audio_path": "POST /api/analyze-call-audio-path",
            "analyze_call_audio_upload": "POST /api/analyze-call-audio-upload",
            "latest_call": "GET /api/latest-call",
            "latest_mobile_report": "GET /api/latest-mobile-report",
            "transfer": "POST /api/transfer",
            "fusion_demo": "GET /api/fusion-demo",
            "latest_transaction": "GET /api/latest-transaction",
            "latest_fusion": "GET /api/latest-fusion",
            "hold_cancel": "POST /api/hold/cancel",
            "hold_release": "POST /api/hold/release",
            "hold_verified_release": "POST /api/hold/verified-release",
            "hold_review": "POST /api/hold/review",
            "reset": "POST /api/reset"
        }
    })


@app.route("/api/audit-log", methods=["GET"])
def get_audit_log():
    with AUDIT_LOG_LOCK:
        logs = read_audit_logs()

    # Return events in reverse chronological order (newest first)
    reversed_logs = list(reversed(logs))

    return success_response({
        "total": len(reversed_logs),
        "logs": reversed_logs,
        "events": reversed_logs
    })


@app.route("/health")
def health():
    return jsonify({
        "backend": "online",
        "call_intelligence": "ready",
        "speech_to_text": (
            "ready" if speech_engine.whisper_available else "not_installed"
        ),
        "risk_fusion": "ready",
        "bank_security_v7_file": (
            "found" if BANK_V7_AVAILABLE else "not_found_or_import_error"
        ),
        "bank_security_v7_import_error": BANK_V7_IMPORT_ERROR,
        "transaction_security": (
            "bank_v7_available"
            if BANK_V7_AVAILABLE
            else "fallback_adapter_active"
        ),
        "mobile_report_upload": "ready",
        "upload_folder": str(UPLOAD_DIR)
    })


@app.route("/api/analyze-call-text", methods=["POST"])
def analyze_call_text():
    global LATEST_CALL_RESULT

    data = request.get_json() or {}

    transcript = str(data.get("transcript", "")).strip()
    detected_language = str(data.get("detected_language", "manual")).strip()

    if not transcript:
        return error_response("transcript is required.", 400)

    try:
        result = call_engine.analyse(
            analysis_transcript=transcript,
            original_transcript=transcript,
            detected_language=detected_language
        )

        LATEST_CALL_RESULT = result.to_dict()

        return success_response({
            "message": "Call transcript analysed successfully.",
            "call_result": LATEST_CALL_RESULT
        })

    except Exception as error:
        return error_response(f"{type(error).__name__}: {error}", 500)


@app.route("/api/analyze-call-audio-path", methods=["POST"])
def analyze_call_audio_path():
    global LATEST_CALL_RESULT
    global LATEST_TRANSCRIPTION_RESULT

    data = request.get_json() or {}
    audio_path = str(data.get("audio_path", "")).strip()

    if not audio_path:
        return error_response("audio_path is required.", 400)

    try:
        path = Path(audio_path.strip().strip('"'))

        if not path.exists():
            return error_response(f"Audio file not found: {path}", 404)

        transcription = speech_engine.transcribe(str(path))

        result = call_engine.analyse(
            analysis_transcript=transcription.analysis_transcript,
            original_transcript=transcription.original_transcript,
            detected_language=transcription.detected_language
        )

        LATEST_TRANSCRIPTION_RESULT = transcription.to_dict()
        LATEST_CALL_RESULT = result.to_dict()

        return success_response({
            "message": "Call audio analysed successfully.",
            "audio_source": str(path),
            "transcription": LATEST_TRANSCRIPTION_RESULT,
            "call_result": LATEST_CALL_RESULT
        })

    except Exception as error:
        return error_response(f"{type(error).__name__}: {error}", 500)


@app.route("/api/analyze-call-audio-upload", methods=["POST"])
def analyze_call_audio_upload():
    global LATEST_CALL_RESULT
    global LATEST_TRANSCRIPTION_RESULT
    global LATEST_MOBILE_REPORT

    if "audio_file" not in request.files:
        return error_response("audio_file is required.", 400)

    audio_file = request.files["audio_file"]

    if audio_file.filename == "":
        return error_response("No audio file selected.", 400)

    customer_id = request.form.get("customer_id", "USR_904")
    caller_number = request.form.get("caller_number", "Unknown Number")
    report_source = request.form.get("report_source", "mobile_report_simulation")

    try:
        original_name = secure_filename(audio_file.filename)
        extension = Path(original_name).suffix.lower()

        if not extension:
            extension = ".audio"

        saved_name = f"call_report_{uuid4().hex}{extension}"
        saved_path = UPLOAD_DIR / saved_name

        audio_file.save(saved_path)

        transcription = speech_engine.transcribe(str(saved_path))

        result = call_engine.analyse(
            analysis_transcript=transcription.analysis_transcript,
            original_transcript=transcription.original_transcript,
            detected_language=transcription.detected_language
        )

        LATEST_TRANSCRIPTION_RESULT = transcription.to_dict()
        LATEST_CALL_RESULT = result.to_dict()

        LATEST_MOBILE_REPORT = {
            "timestamp": now_iso(),
            "customer_id": customer_id,
            "caller_number": caller_number,
            "report_source": report_source,
            "original_filename": original_name,
            "saved_audio_path": str(saved_path),
            "detected_language": transcription.detected_language,
            "call_risk_level": LATEST_CALL_RESULT.get("risk_level"),
            "scam_risk": LATEST_CALL_RESULT.get("scam_risk"),
            "recommended_action": LATEST_CALL_RESULT.get("recommended_action"),
            "status": "CALL_ANALYSED_AND_CONTEXT_SAVED"
        }

        return success_response({
            "message": (
                "Mobile fraud report received. Audio was transcribed, "
                "analysed, and saved as latest call context."
            ),
            "mobile_report": LATEST_MOBILE_REPORT,
            "transcription": LATEST_TRANSCRIPTION_RESULT,
            "call_result": LATEST_CALL_RESULT
        })

    except Exception as error:
        return error_response(f"{type(error).__name__}: {error}", 500)


@app.route("/api/latest-call")
def latest_call():
    if LATEST_CALL_RESULT is None:
        return success_response({
            "available": False,
            "message": "No call has been analysed yet."
        })

    return success_response({
        "available": True,
        "call_result": LATEST_CALL_RESULT,
        "transcription": LATEST_TRANSCRIPTION_RESULT
    })


@app.route("/api/latest-mobile-report")
def latest_mobile_report():
    if LATEST_MOBILE_REPORT is None:
        return success_response({
            "available": False,
            "message": "No mobile report has been submitted yet."
        })

    return success_response({
        "available": True,
        "mobile_report": LATEST_MOBILE_REPORT
    })


@app.route("/api/transfer", methods=["POST"])
def transfer():
    global LATEST_TRANSACTION_RESULT
    global LATEST_FUSION_RESULT

    data = request.get_json() or {}

    if "amount" not in data:
        return error_response("amount is required.", 400)

    if "recipient_id" not in data:
        return error_response("recipient_id is required.", 400)

    try:
        transaction_result = try_bank_v7_transaction_analysis(data)
        LATEST_TRANSACTION_RESULT = transaction_result

        if LATEST_CALL_RESULT is not None:
            fusion_result = fusion_engine.fuse(
                call_result=LATEST_CALL_RESULT,
                transaction_result=transaction_result
            )

            LATEST_FUSION_RESULT = fusion_result.to_dict()

            if LATEST_FUSION_RESULT.get("smart_hold_required"):
                LATEST_FUSION_RESULT["hold_status"] = "ACTIVE"
                LATEST_FUSION_RESULT["settlement_status"] = "NOT_SETTLED"
                LATEST_FUSION_RESULT["funds_status"] = "RESERVED_UNDER_SMART_TRANSIT_HOLD"
            else:
                LATEST_FUSION_RESULT["hold_status"] = "NOT_REQUIRED"
                LATEST_FUSION_RESULT["settlement_status"] = (
                    "SETTLEMENT_ALLOWED"
                    if LATEST_FUSION_RESULT.get("allow_transaction")
                    else "PENDING_VERIFICATION"
                )
                LATEST_FUSION_RESULT["funds_status"] = "NOT_RESERVED"

            return success_response({
                "message": "Transfer analysed with latest call context.",
                "call_context_available": True,
                "transaction_result": transaction_result,
                "fusion_result": LATEST_FUSION_RESULT
            })

        return success_response({
            "message": "Transfer analysed without call context.",
            "call_context_available": False,
            "transaction_result": transaction_result,
            "fusion_result": None,
            "note": "Analyse or upload a suspicious call first to enable cross-channel risk fusion."
        })

    except Exception as error:
        return error_response(f"{type(error).__name__}: {error}", 500)


@app.route("/api/fusion-demo")
def fusion_demo():
    global LATEST_FUSION_RESULT

    demo_call_result = {
        "timestamp": now_iso(),
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
        "remote_access_request": False
    }

    demo_transaction_result = fallback_transaction_analysis({
        "transaction_id": "TX_WEB_DEMO_001",
        "customer_id": "USR_904",
        "amount": 80000,
        "recipient_id": "ACC_NEW_SAFE_777",
        "recipient_status": "UNKNOWN",
        "new_recipient": True,
        "high_amount": True,
        "location": "Mumbai",
        "device_id": "MY_IPHONE"
    })

    fusion_result = fusion_engine.fuse(
        call_result=demo_call_result,
        transaction_result=demo_transaction_result
    )

    LATEST_FUSION_RESULT = fusion_result.to_dict()
    LATEST_FUSION_RESULT["hold_status"] = "ACTIVE"
    LATEST_FUSION_RESULT["settlement_status"] = "NOT_SETTLED"
    LATEST_FUSION_RESULT["funds_status"] = "RESERVED_UNDER_SMART_TRANSIT_HOLD"

    return success_response({
        "message": "High-risk cross-channel demo completed.",
        "call_result": demo_call_result,
        "transaction_result": demo_transaction_result,
        "fusion_result": LATEST_FUSION_RESULT
    })


@app.route("/api/latest-transaction")
def latest_transaction():
    if LATEST_TRANSACTION_RESULT is None:
        return success_response({
            "available": False,
            "message": "No transaction has been analysed yet."
        })

    return success_response({
        "available": True,
        "transaction_result": LATEST_TRANSACTION_RESULT
    })


@app.route("/api/latest-fusion")
def latest_fusion():
    if LATEST_FUSION_RESULT is None:
        return success_response({
            "available": False,
            "message": "No fusion result has been generated yet."
        })

    return success_response({
        "available": True,
        "fusion_result": LATEST_FUSION_RESULT
    })


# =============================================================================
# SMART TRANSIT HOLD ACTION ROUTES
# =============================================================================

@app.route("/api/hold/cancel", methods=["POST"])
def cancel_hold():
    global LATEST_FUSION_RESULT

    if LATEST_FUSION_RESULT is None:
        return error_response("No Smart Transit Hold transaction found.", 404)

    LATEST_FUSION_RESULT["hold_status"] = "CANCELLED"
    LATEST_FUSION_RESULT["final_customer_action"] = "CUSTOMER_CANCELLED_TRANSFER"
    LATEST_FUSION_RESULT["settlement_status"] = "NOT_SETTLED"
    LATEST_FUSION_RESULT["funds_status"] = "RESTORED_TO_CUSTOMER"
    LATEST_FUSION_RESULT["action_timestamp"] = now_iso()

    return success_response({
        "message": "Transfer cancelled before settlement. Funds restored.",
        "hold_status": LATEST_FUSION_RESULT["hold_status"],
        "settlement_status": LATEST_FUSION_RESULT["settlement_status"],
        "funds_status": LATEST_FUSION_RESULT["funds_status"],
        "fusion_result": LATEST_FUSION_RESULT
    })


@app.route("/api/hold/release", methods=["POST"])
def release_hold():
    global LATEST_FUSION_RESULT

    if LATEST_FUSION_RESULT is None:
        return error_response("No Smart Transit Hold transaction found.", 404)

    final_risk_level = str(
        LATEST_FUSION_RESULT.get("final_risk_level", "")
    ).upper()

    decision = str(
        LATEST_FUSION_RESULT.get("decision", "")
    ).upper()

    if final_risk_level == "HIGH" or decision == "SMART_TRANSIT_HOLD_REQUIRED":
        LATEST_FUSION_RESULT["hold_status"] = "RELEASE_BLOCKED_PENDING_VERIFICATION"
        LATEST_FUSION_RESULT["final_customer_action"] = "RELEASE_ATTEMPTED_HIGH_RISK"
        LATEST_FUSION_RESULT["settlement_status"] = "NOT_SETTLED"
        LATEST_FUSION_RESULT["funds_status"] = "STILL_RESERVED"
        LATEST_FUSION_RESULT["action_timestamp"] = now_iso()

        return success_response({
            "message": (
                "Release blocked for high-risk scam pattern. "
                "Customer must complete independent verification before release."
            ),
            "hold_status": LATEST_FUSION_RESULT["hold_status"],
            "settlement_status": LATEST_FUSION_RESULT["settlement_status"],
            "funds_status": LATEST_FUSION_RESULT["funds_status"],
            "verification_required": True,
            "verification_url": "/verify-release",
            "fusion_result": LATEST_FUSION_RESULT
        })

    LATEST_FUSION_RESULT["hold_status"] = "RELEASED"
    LATEST_FUSION_RESULT["final_customer_action"] = "CUSTOMER_VERIFIED_AND_RELEASED"
    LATEST_FUSION_RESULT["settlement_status"] = "SETTLEMENT_ALLOWED"
    LATEST_FUSION_RESULT["funds_status"] = "TRANSFER_PROCEEDS"
    LATEST_FUSION_RESULT["action_timestamp"] = now_iso()

    return success_response({
        "message": "Customer verification accepted. Transfer released.",
        "hold_status": LATEST_FUSION_RESULT["hold_status"],
        "settlement_status": LATEST_FUSION_RESULT["settlement_status"],
        "funds_status": LATEST_FUSION_RESULT["funds_status"],
        "verification_required": False,
        "fusion_result": LATEST_FUSION_RESULT
    })


@app.route("/api/hold/verified-release", methods=["POST"])
def verified_release_hold():
    global LATEST_FUSION_RESULT

    if LATEST_FUSION_RESULT is None:
        return error_response("No Smart Transit Hold transaction found.", 404)

    LATEST_FUSION_RESULT["hold_status"] = "RELEASED_AFTER_INDEPENDENT_VERIFICATION"
    LATEST_FUSION_RESULT["final_customer_action"] = "CUSTOMER_COMPLETED_INDEPENDENT_VERIFICATION"
    LATEST_FUSION_RESULT["settlement_status"] = "SETTLEMENT_ALLOWED"
    LATEST_FUSION_RESULT["funds_status"] = "TRANSFER_PROCEEDS"
    LATEST_FUSION_RESULT["verification_method"] = "OFFICIAL_CHANNEL_PLUS_STEP_UP_AUTH"
    LATEST_FUSION_RESULT["action_timestamp"] = now_iso()

    return success_response({
        "message": "Independent verification completed. Transfer released safely.",
        "hold_status": LATEST_FUSION_RESULT["hold_status"],
        "settlement_status": LATEST_FUSION_RESULT["settlement_status"],
        "funds_status": LATEST_FUSION_RESULT["funds_status"],
        "fusion_result": LATEST_FUSION_RESULT
    })


@app.route("/api/hold/review", methods=["POST"])
def review_hold():
    global LATEST_FUSION_RESULT

    if LATEST_FUSION_RESULT is None:
        return error_response("No Smart Transit Hold transaction found.", 404)

    LATEST_FUSION_RESULT["hold_status"] = "SENT_TO_SECURITY_REVIEW"
    LATEST_FUSION_RESULT["final_customer_action"] = "CUSTOMER_REQUESTED_SECURITY_REVIEW"
    LATEST_FUSION_RESULT["settlement_status"] = "NOT_SETTLED"
    LATEST_FUSION_RESULT["funds_status"] = "STILL_RESERVED"
    LATEST_FUSION_RESULT["action_timestamp"] = now_iso()

    return success_response({
        "message": "Transaction sent to bank security review. Funds remain protected.",
        "hold_status": LATEST_FUSION_RESULT["hold_status"],
        "settlement_status": LATEST_FUSION_RESULT["settlement_status"],
        "funds_status": LATEST_FUSION_RESULT["funds_status"],
        "fusion_result": LATEST_FUSION_RESULT
    })


@app.route("/api/reset", methods=["POST"])
def reset_state():
    global LATEST_CALL_RESULT
    global LATEST_TRANSCRIPTION_RESULT
    global LATEST_TRANSACTION_RESULT
    global LATEST_FUSION_RESULT
    global LATEST_MOBILE_REPORT

    LATEST_CALL_RESULT = None
    LATEST_TRANSCRIPTION_RESULT = None
    LATEST_TRANSACTION_RESULT = None
    LATEST_FUSION_RESULT = None
    LATEST_MOBILE_REPORT = None

    return success_response({
        "message": "Temporary backend state cleared."
    })


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    app.run(
        debug=False,
        host="127.0.0.1",
        port=5000
    )