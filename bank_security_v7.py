# Smart Transit Hold banking security prototype
# Core backend: fraud scoring, transaction holds, verification, persistence and audit logging.

import datetime
import json
import random
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
try:
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score
except ImportError:
    print("\nREQUIRED ML PACKAGES NOT INSTALLED")
    print()
    print('Open Windows Command Prompt and run:')
    print()
    print('py -m pip install scikit-learn joblib')
    print()
    raise SystemExit
APP_NAME = 'AI Banking Security System'
APP_VERSION = 'V7'
INITIAL_BALANCE = 50000.0
HOLD_MINUTES = 15
LOW_RISK_THRESHOLD = 0.4
HIGH_RISK_THRESHOLD = 0.7
BASE_FOLDER = Path(__file__).resolve().parent
STATE_FILE = BASE_FOLDER / 'bank_v6_1_state.json'
MODEL_FILE = BASE_FOLDER / 'fraud_model_v6_1.joblib'

def current_time():
    return datetime.datetime.now()

def money(value):
    return round(float(value), 2)

def datetime_to_text(value):
    if value is None:
        return None
    return value.isoformat()

def text_to_datetime(value):
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None

def normalize_account_id(value):
    return str(value).strip().upper()

def normalize_location(value):
    return str(value).strip()

def normalize_device(value):
    return str(value).strip().upper()

@dataclass
class UserProfile:
    user_id: str
    usual_location: str
    avg_tx_amount: float
    trusted_devices: list

@dataclass
class BankAccount:
    account_id: str
    available_balance: float
    reserved_balance: float = 0.0

    def to_dict(self):
        return {'account_id': self.account_id, 'available_balance': self.available_balance, 'reserved_balance': self.reserved_balance}

    @classmethod
    def from_dict(cls, data):
        return cls(account_id=data.get('account_id', 'ACC_USER_904'), available_balance=float(data.get('available_balance', INITIAL_BALANCE)), reserved_balance=float(data.get('reserved_balance', 0.0)))

@dataclass
class Transaction:
    sender_id: str
    recipient_account: str
    amount: float
    location: str
    device_id: str
    transaction_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime = field(default_factory=current_time)
    rule_score: float = 0.0
    ml_probability: float = 0.0
    risk_score: float = 0.0
    risk_level: str = 'UNKNOWN'
    status: str = 'PENDING'
    hold_expires_at: Optional[datetime.datetime] = None
    message: str = ''
    risk_reasons: list = field(default_factory=list)
    escalated_at: Optional[datetime.datetime] = None
    verified_at: Optional[datetime.datetime] = None

    def to_dict(self):
        return {'sender_id': self.sender_id, 'recipient_account': self.recipient_account, 'amount': self.amount, 'location': self.location, 'device_id': self.device_id, 'transaction_id': self.transaction_id, 'timestamp': datetime_to_text(self.timestamp), 'rule_score': self.rule_score, 'ml_probability': self.ml_probability, 'risk_score': self.risk_score, 'risk_level': self.risk_level, 'status': self.status, 'hold_expires_at': datetime_to_text(self.hold_expires_at), 'message': self.message, 'risk_reasons': self.risk_reasons, 'escalated_at': datetime_to_text(self.escalated_at), 'verified_at': datetime_to_text(self.verified_at)}

    @classmethod
    def from_dict(cls, data):
        timestamp = text_to_datetime(data.get('timestamp'))
        if timestamp is None:
            timestamp = current_time()
        return cls(sender_id=data.get('sender_id', 'UNKNOWN'), recipient_account=normalize_account_id(data.get('recipient_account', 'UNKNOWN')), amount=float(data.get('amount', 0.0)), location=data.get('location', ''), device_id=data.get('device_id', ''), transaction_id=data.get('transaction_id', str(uuid.uuid4())), timestamp=timestamp, rule_score=float(data.get('rule_score', 0.0)), ml_probability=float(data.get('ml_probability', 0.0)), risk_score=float(data.get('risk_score', 0.0)), risk_level=data.get('risk_level', 'UNKNOWN'), status=data.get('status', 'PENDING'), hold_expires_at=text_to_datetime(data.get('hold_expires_at')), message=data.get('message', ''), risk_reasons=list(data.get('risk_reasons', [])), escalated_at=text_to_datetime(data.get('escalated_at')), verified_at=text_to_datetime(data.get('verified_at')))

class AuditLogger:

    def __init__(self):
        self.events = []

    def log(self, event_type, message, transaction_id=None):
        event = {'timestamp': datetime_to_text(current_time()), 'event_type': str(event_type), 'transaction_id': transaction_id, 'message': str(message)}
        self.events.append(event)

    def show_logs(self):
        print('\n===================================')
        print(' SECURITY AUDIT LOG')
        print()
        if not self.events:
            print('No audit events available.')
            return
        for number, event in enumerate(self.events, start=1):
            print('\nEvent', number)
            print('-' * 35)
            print('Time:', event.get('timestamp'))
            print('Type:', event.get('event_type'))
            tx_id = event.get('transaction_id')
            if tx_id:
                print('Transaction:', tx_id)
            print('Message:', event.get('message'))

class FraudMLModel:
    FEATURE_NAMES = ['amount_ratio', 'location_anomaly', 'device_anomaly', 'new_recipient', 'recipient_risk', 'rapid_transactions', 'previous_denial', 'unusual_hour']
    MODEL_SIGNATURE = 'SMART_TRANSIT_HOLD_RF_V6_1'

    def __init__(self):
        self.model = None
        self.validation_accuracy = 0.0
        self.loaded_from_disk = False
        self.load_or_train_model()

    def create_model(self):
        return RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42, class_weight='balanced')

    def generate_training_data(self):
        random.seed(42)
        X = []
        y = []
        for _ in range(2500):
            amount_ratio = round(random.uniform(0.1, 15.0), 2)
            location_anomaly = random.choice([0, 0, 0, 1])
            device_anomaly = random.choice([0, 0, 0, 1])
            new_recipient = random.choice([0, 0, 1])
            recipient_risk = random.choice([0.0, 0.0, 0.0, 0.0, 0.5, 1.0])
            rapid_transactions = random.choice([0, 0, 0, 1, 2, 3])
            previous_denial = random.choice([0, 0, 0, 0, 1])
            unusual_hour = random.choice([0, 0, 0, 0, 1])
            fraud_score = 0.03
            if amount_ratio > 8:
                fraud_score += 0.3
            elif amount_ratio > 5:
                fraud_score += 0.22
            elif amount_ratio > 3:
                fraud_score += 0.1
            if location_anomaly:
                fraud_score += 0.12
            if device_anomaly:
                fraud_score += 0.18
            if new_recipient:
                fraud_score += 0.1
            if recipient_risk == 0.5:
                fraud_score += 0.2
            elif recipient_risk == 1.0:
                fraud_score += 0.4
            if rapid_transactions >= 2:
                fraud_score += 0.14
            if previous_denial:
                fraud_score += 0.28
            if unusual_hour:
                fraud_score += 0.08
            if location_anomaly and device_anomaly:
                fraud_score += 0.12
            if new_recipient and amount_ratio > 5:
                fraud_score += 0.1
            if recipient_risk == 1.0 and device_anomaly:
                fraud_score += 0.15
            noise = random.uniform(-0.12, 0.12)
            final_probability = fraud_score + noise
            fraud_label = 1 if final_probability >= 0.55 else 0
            features = [amount_ratio, location_anomaly, device_anomaly, new_recipient, recipient_risk, rapid_transactions, previous_denial, unusual_hour]
            X.append(features)
            y.append(fraud_label)
        return (X, y)

    def train_model(self):
        self.model = self.create_model()
        X, y = self.generate_training_data()
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        self.model.fit(X_train, y_train)
        predictions = self.model.predict(X_test)
        self.validation_accuracy = accuracy_score(y_test, predictions)

    def save_model(self):
        model_package = {'signature': self.MODEL_SIGNATURE, 'feature_names': self.FEATURE_NAMES, 'validation_accuracy': self.validation_accuracy, 'model': self.model}
        joblib.dump(model_package, MODEL_FILE)

    def try_load_model(self):
        if not MODEL_FILE.exists():
            return False
        try:
            package = joblib.load(MODEL_FILE)
            if not isinstance(package, dict):
                return False
            if package.get('signature') != self.MODEL_SIGNATURE:
                return False
            if package.get('feature_names') != self.FEATURE_NAMES:
                return False
            model = package.get('model')
            if model is None:
                return False
            self.model = model
            self.validation_accuracy = float(package.get('validation_accuracy', 0.0))
            self.loaded_from_disk = True
            return True
        except Exception:
            return False

    def load_or_train_model(self):
        if self.try_load_model():
            return
        self.train_model()
        self.save_model()
        self.loaded_from_disk = False

    def predict_probability(self, features):
        probability = self.model.predict_proba([features])[0][1]
        return round(float(probability), 3)

    def show_feature_importance(self):
        print('\n===================================')
        print(' ML FEATURE IMPORTANCE')
        print()
        importances = self.model.feature_importances_
        data = list(zip(self.FEATURE_NAMES, importances))
        data.sort(key=lambda item: item[1], reverse=True)
        for name, importance in data:
            print(f'{name:<22}', round(importance, 3))

class RiskEngine:

    def __init__(self, recipient_registry, ml_model):
        self.recipient_registry = recipient_registry
        self.ml_model = ml_model

    def get_historical_average(self, profile, transaction_history):
        successful_amounts = [tx.amount for tx in transaction_history if tx.status == 'PROCESSED']
        if successful_amounts:
            return sum(successful_amounts) / len(successful_amounts)
        return profile.avg_tx_amount

    def extract_features(self, tx, profile, transaction_history):
        reasons = []
        historical_average = self.get_historical_average(profile, transaction_history)
        if historical_average <= 0:
            historical_average = profile.avg_tx_amount
        if historical_average <= 0:
            historical_average = 1.0
        amount_ratio = tx.amount / historical_average
        amount_ratio = min(amount_ratio, 20.0)
        if amount_ratio > 5:
            reasons.append('Transaction amount far above normal spending')
        elif amount_ratio > 3:
            reasons.append('Transaction amount above normal spending')
        location_anomaly = 0
        if tx.location.strip().lower() != profile.usual_location.strip().lower():
            location_anomaly = 1
            reasons.append('Unusual transaction location')
        trusted_devices = {normalize_device(device) for device in profile.trusted_devices}
        device_anomaly = 0
        if normalize_device(tx.device_id) not in trusted_devices:
            device_anomaly = 1
            reasons.append('Unknown device')
        previous_recipients = {normalize_account_id(old_tx.recipient_account) for old_tx in transaction_history if old_tx.status == 'PROCESSED'}
        new_recipient = 0
        normalized_recipient = normalize_account_id(tx.recipient_account)
        if previous_recipients and normalized_recipient not in previous_recipients:
            new_recipient = 1
            reasons.append('New recipient compared with customer history')
        recipient_info = self.recipient_registry.get(normalized_recipient, {'flag_status': 'CLEAN'})
        recipient_status = recipient_info.get('flag_status', 'CLEAN').upper()
        recipient_risk = 0.0
        if recipient_status == 'SUSPECTED':
            recipient_risk = 0.5
            reasons.append('Recipient is marked suspicious')
        elif recipient_status == 'BLACKLISTED':
            recipient_risk = 1.0
            reasons.append('Recipient is blacklisted')
        rapid_transactions = 0
        for old_tx in transaction_history:
            difference = tx.timestamp - old_tx.timestamp
            seconds = difference.total_seconds()
            if 0 <= seconds <= 120:
                rapid_transactions += 1
        rapid_transactions = min(rapid_transactions, 3)
        if rapid_transactions >= 2:
            reasons.append('Multiple transactions within two minutes')
        previous_denial = 0
        for old_tx in transaction_history:
            if normalize_account_id(old_tx.recipient_account) == normalized_recipient and old_tx.status == 'CANCELLED' and ('Customer denied' in old_tx.message):
                previous_denial = 1
                reasons.append('Previous payment to this recipient was denied')
                break
        unusual_hour = 0
        if 0 <= tx.timestamp.hour < 5:
            unusual_hour = 1
            reasons.append('Transaction performed during unusual hours')
        features = [amount_ratio, location_anomaly, device_anomaly, new_recipient, recipient_risk, rapid_transactions, previous_denial, unusual_hour]
        return (features, reasons, historical_average)

    def calculate_rule_score(self, features):
        amount_ratio, location_anomaly, device_anomaly, new_recipient, recipient_risk, rapid_transactions, previous_denial, unusual_hour = features
        score = 0.0
        if amount_ratio > 5:
            score += 0.2
        elif amount_ratio > 3:
            score += 0.1
        if location_anomaly:
            score += 0.15
        if device_anomaly:
            score += 0.2
        if new_recipient:
            score += 0.1
        if recipient_risk == 0.5:
            score += 0.2
        elif recipient_risk == 1.0:
            score += 0.4
        if rapid_transactions >= 2:
            score += 0.15
        if previous_denial:
            score += 0.25
        if unusual_hour:
            score += 0.05
        return round(min(score, 1.0), 2)

    def analyse_transaction(self, tx, profile, transaction_history):
        features, reasons, historical_average = self.extract_features(tx, profile, transaction_history)
        rule_score = self.calculate_rule_score(features)
        ml_probability = self.ml_model.predict_probability(features)
        hybrid_score = ml_probability * 0.65 + rule_score * 0.35
        if features[4] == 1.0:
            hybrid_score = max(hybrid_score, 0.75)
        if features[6] == 1:
            hybrid_score = max(hybrid_score, 0.7)
        hybrid_score = round(min(hybrid_score, 1.0), 2)
        tx.rule_score = rule_score
        tx.ml_probability = ml_probability
        tx.risk_score = hybrid_score
        tx.risk_reasons = reasons
        return {'historical_average': historical_average, 'features': features, 'rule_score': rule_score, 'ml_probability': ml_probability, 'hybrid_score': hybrid_score, 'reasons': reasons}

class DataStore:

    def __init__(self, file_path):
        self.file_path = Path(file_path)

    def exists(self):
        return self.file_path.exists()

    def save(self, account, recipient_registry, transaction_history, audit_events):
        data = {'version': APP_VERSION, 'saved_at': datetime_to_text(current_time()), 'account': account.to_dict(), 'recipient_registry': recipient_registry, 'transaction_history': [tx.to_dict() for tx in transaction_history], 'audit_events': audit_events}
        temporary_file = self.file_path.with_suffix('.tmp')
        with open(temporary_file, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=4)
        temporary_file.replace(self.file_path)

    def load(self):
        with open(self.file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        if not isinstance(data, dict):
            raise ValueError('Invalid state file format.')
        account_data = data.get('account')
        if not isinstance(account_data, dict):
            raise ValueError('Account data missing from state file.')
        account = BankAccount.from_dict(account_data)
        registry = data.get('recipient_registry', {})
        if not isinstance(registry, dict):
            registry = {}
        normalized_registry = {}
        for account_id, info in registry.items():
            normalized_registry[normalize_account_id(account_id)] = info
        history_data = data.get('transaction_history', [])
        if not isinstance(history_data, list):
            history_data = []
        history = []
        for tx_data in history_data:
            if not isinstance(tx_data, dict):
                continue
            try:
                history.append(Transaction.from_dict(tx_data))
            except Exception:
                continue
        audit_events = data.get('audit_events', [])
        if not isinstance(audit_events, list):
            audit_events = []
        return (account, normalized_registry, history, audit_events)

    def reset(self):
        if self.file_path.exists():
            self.file_path.unlink()

class SmartHoldSystem:

    def __init__(self, risk_engine, datastore, audit_logger, account):
        self.risk_engine = risk_engine
        self.datastore = datastore
        self.audit_logger = audit_logger
        self.account = account
        self.transaction_history = []
        self.active_holds = {}

    def restore_history(self, history):
        self.transaction_history = history
        self.active_holds = {}
        for tx in history:
            if tx.status in ('ON_HOLD', 'ESCALATED'):
                self.active_holds[tx.transaction_id] = tx

    def save_state(self):
        self.datastore.save(self.account, self.risk_engine.recipient_registry, self.transaction_history, self.audit_logger.events)

    def check_expired_holds(self):
        now = current_time()
        escalated_count = 0
        for tx in list(self.active_holds.values()):
            if tx.status == 'ON_HOLD' and tx.hold_expires_at is not None and (now >= tx.hold_expires_at):
                tx.status = 'ESCALATED'
                tx.escalated_at = now
                tx.message = 'Smart Transit Hold expired. Transaction escalated to bank security review. Funds remain protected.'
                escalated_count += 1
                self.audit_logger.log('HOLD_ESCALATED', 'Smart Transit Hold expired and was escalated to security review.', tx.transaction_id)
        if escalated_count > 0:
            self.save_state()
        return escalated_count

    def process_transaction(self, tx, profile):
        self.check_expired_holds()
        tx.recipient_account = normalize_account_id(tx.recipient_account)
        tx.device_id = normalize_device(tx.device_id)
        tx.location = normalize_location(tx.location)
        if tx.amount <= 0:
            tx.status = 'CANCELLED'
            tx.risk_level = 'NOT_ANALYSED'
            tx.message = 'Transaction cancelled. Amount must be greater than zero.'
            self.transaction_history.append(tx)
            self.audit_logger.log('TRANSACTION_REJECTED', tx.message, tx.transaction_id)
            self.save_state()
            return tx
        if not tx.recipient_account:
            tx.status = 'CANCELLED'
            tx.risk_level = 'NOT_ANALYSED'
            tx.message = 'Transaction cancelled. Recipient account is required.'
            self.transaction_history.append(tx)
            self.audit_logger.log('TRANSACTION_REJECTED', tx.message, tx.transaction_id)
            self.save_state()
            return tx
        if tx.amount > self.account.available_balance:
            tx.status = 'CANCELLED'
            tx.risk_level = 'NOT_ANALYSED'
            tx.message = 'Transaction cancelled due to insufficient available balance.'
            self.transaction_history.append(tx)
            self.audit_logger.log('INSUFFICIENT_BALANCE', tx.message, tx.transaction_id)
            self.save_state()
            return tx
        self.risk_engine.analyse_transaction(tx, profile, self.transaction_history)
        if tx.risk_score < LOW_RISK_THRESHOLD:
            tx.risk_level = 'LOW'
            tx.status = 'PROCESSED'
            self.account.available_balance -= tx.amount
            self.account.available_balance = money(self.account.available_balance)
            tx.message = 'AI classified transaction as low risk. Funds transferred.'
            self.audit_logger.log('TRANSACTION_PROCESSED', 'Low-risk transaction processed successfully.', tx.transaction_id)
        elif tx.risk_score < HIGH_RISK_THRESHOLD:
            tx.risk_level = 'MEDIUM'
            self.place_on_hold(tx)
            tx.message = 'AI detected suspicious behaviour. Transaction placed under Smart Transit Hold.'
            self.audit_logger.log('SMART_HOLD_CREATED', 'Medium-risk transaction placed under Smart Transit Hold.', tx.transaction_id)
        else:
            tx.risk_level = 'HIGH'
            self.place_on_hold(tx)
            tx.message = 'AI detected a high-risk transaction. Funds blocked under Smart Transit Hold.'
            self.audit_logger.log('HIGH_RISK_HOLD_CREATED', 'High-risk transaction blocked under Smart Transit Hold.', tx.transaction_id)
        self.transaction_history.append(tx)
        self.save_state()
        return tx

    def place_on_hold(self, tx):
        self.account.available_balance -= tx.amount
        self.account.reserved_balance += tx.amount
        self.account.available_balance = money(self.account.available_balance)
        self.account.reserved_balance = money(self.account.reserved_balance)
        tx.status = 'ON_HOLD'
        tx.hold_expires_at = current_time() + datetime.timedelta(minutes=HOLD_MINUTES)
        self.active_holds[tx.transaction_id] = tx

    def verify_transaction(self, transaction_id, action):
        self.check_expired_holds()
        tx = self.active_holds.get(transaction_id)
        if tx is None:
            return (None, 'Transaction is not currently on hold.')
        if tx.status == 'ESCALATED':
            return (tx, 'Transaction has already been escalated to security review.')
        if tx.status != 'ON_HOLD':
            return (tx, 'Transaction is not awaiting customer verification.')
        action = action.strip().upper()
        if action == 'APPROVE':
            self.account.reserved_balance -= tx.amount
            self.account.reserved_balance = money(max(self.account.reserved_balance, 0.0))
            tx.status = 'PROCESSED'
            tx.verified_at = current_time()
            tx.message = 'Customer approved transaction. Reserved funds released to recipient.'
            del self.active_holds[transaction_id]
            self.audit_logger.log('CUSTOMER_APPROVED', 'Customer approved Smart Transit Hold.', tx.transaction_id)
        elif action == 'DENY':
            self.account.reserved_balance -= tx.amount
            self.account.available_balance += tx.amount
            self.account.reserved_balance = money(max(self.account.reserved_balance, 0.0))
            self.account.available_balance = money(self.account.available_balance)
            tx.status = 'CANCELLED'
            tx.verified_at = current_time()
            tx.message = 'Customer denied transaction. Transfer cancelled and funds restored.'
            current_status = self.risk_engine.recipient_registry.get(tx.recipient_account, {}).get('flag_status', 'CLEAN')
            if current_status != 'BLACKLISTED':
                self.risk_engine.recipient_registry[tx.recipient_account] = {'flag_status': 'SUSPECTED'}
            del self.active_holds[transaction_id]
            self.audit_logger.log('CUSTOMER_DENIED', 'Customer denied transaction. Funds restored and recipient flagged.', tx.transaction_id)
        else:
            return (tx, 'Invalid verification action.')
        self.save_state()
        return (tx, tx.message)

    def security_review(self, transaction_id, decision):
        self.check_expired_holds()
        tx = self.active_holds.get(transaction_id)
        if tx is None:
            return (None, 'Transaction not found.')
        if tx.status != 'ESCALATED':
            return (tx, 'Only escalated transactions can enter security review.')
        decision = decision.strip().upper()
        if decision == 'RELEASE':
            self.account.reserved_balance -= tx.amount
            self.account.reserved_balance = money(max(self.account.reserved_balance, 0.0))
            tx.status = 'PROCESSED'
            tx.verified_at = current_time()
            tx.message = 'Bank security reviewed and released the transaction.'
            del self.active_holds[transaction_id]
            self.audit_logger.log('SECURITY_RELEASED', 'Escalated transaction released by bank security.', tx.transaction_id)
        elif decision == 'CANCEL':
            self.account.reserved_balance -= tx.amount
            self.account.available_balance += tx.amount
            self.account.reserved_balance = money(max(self.account.reserved_balance, 0.0))
            self.account.available_balance = money(self.account.available_balance)
            tx.status = 'CANCELLED'
            tx.verified_at = current_time()
            tx.message = 'Bank security cancelled the escalated transaction. Funds restored.'
            current_status = self.risk_engine.recipient_registry.get(tx.recipient_account, {}).get('flag_status', 'CLEAN')
            if current_status != 'BLACKLISTED':
                self.risk_engine.recipient_registry[tx.recipient_account] = {'flag_status': 'SUSPECTED'}
            del self.active_holds[transaction_id]
            self.audit_logger.log('SECURITY_CANCELLED', 'Security cancelled escalated transaction and restored funds.', tx.transaction_id)
        else:
            return (tx, 'Invalid security decision.')
        self.save_state()
        return (tx, tx.message)

    def force_timeout_for_demo(self, transaction_id):
        tx = self.active_holds.get(transaction_id)
        if tx is None:
            return (None, 'Transaction not found.')
        if tx.status != 'ON_HOLD':
            return (tx, 'Only ON_HOLD transactions can be timed out.')
        tx.hold_expires_at = current_time() - datetime.timedelta(seconds=1)
        self.audit_logger.log('DEMO_TIMEOUT_TRIGGERED', 'Hold expiry moved into the past for demo timeout testing.', tx.transaction_id)
        self.save_state()
        self.check_expired_holds()
        return (tx, 'Demo timeout triggered.')

    def show_pending_holds(self):
        self.check_expired_holds()
        print('\n===================================')
        print(' PENDING / ESCALATED HOLDS')
        print()
        if not self.active_holds:
            print('No active Smart Transit Holds.')
            return
        for number, tx in enumerate(self.active_holds.values(), start=1):
            print('\nHold', number)
            print('-' * 35)
            print('Transaction ID:', tx.transaction_id)
            print('Recipient:', tx.recipient_account)
            print('Amount: ₹', tx.amount)
            print('Risk Level:', tx.risk_level)
            print('Risk Score:', tx.risk_score)
            print('Status:', tx.status)
            print('Expires:', tx.hold_expires_at)
            if tx.escalated_at:
                print('Escalated:', tx.escalated_at)

    def show_transaction_history(self):
        print('\n===================================')
        print(' TRANSACTION HISTORY')
        print()
        if not self.transaction_history:
            print('No transactions found.')
            return
        for number, tx in enumerate(self.transaction_history, start=1):
            print('\nTransaction', number)
            print('-' * 35)
            print('Transaction ID:', tx.transaction_id)
            print('Recipient:', tx.recipient_account)
            print('Amount: ₹', tx.amount)
            print('Location:', tx.location)
            print('Device:', tx.device_id)
            print('Rule Score:', tx.rule_score)
            print('ML Probability:', tx.ml_probability)
            print('Hybrid Risk Score:', tx.risk_score)
            print('Risk Level:', tx.risk_level)
            print('Status:', tx.status)
            print('Time:', tx.timestamp)
            if tx.hold_expires_at:
                print('Hold Expiry:', tx.hold_expires_at)
            if tx.escalated_at:
                print('Escalated At:', tx.escalated_at)
            if tx.verified_at:
                print('Verified At:', tx.verified_at)
            print('Message:', tx.message)
            if tx.risk_reasons:
                print('Risk Reasons:')
                for reason in tx.risk_reasons:
                    print('  -', reason)

    def show_behaviour_summary(self, profile):
        print('\n===================================')
        print(' CUSTOMER BEHAVIOUR PROFILE')
        print()
        successful = [tx for tx in self.transaction_history if tx.status == 'PROCESSED']
        cancelled = [tx for tx in self.transaction_history if tx.status == 'CANCELLED']
        on_hold = [tx for tx in self.transaction_history if tx.status == 'ON_HOLD']
        escalated = [tx for tx in self.transaction_history if tx.status == 'ESCALATED']
        print('Customer ID:', profile.user_id)
        print('Usual Location:', profile.usual_location)
        print('Initial Average Amount: ₹', profile.avg_tx_amount)
        print('Trusted Devices:', ', '.join(profile.trusted_devices))
        print('Total Transactions:', len(self.transaction_history))
        print('Successful:', len(successful))
        print('Cancelled:', len(cancelled))
        print('On Hold:', len(on_hold))
        print('Escalated:', len(escalated))
        if successful:
            observed_average = sum((tx.amount for tx in successful)) / len(successful)
            print('Observed Average Amount: ₹', round(observed_average, 2))
            recipients = {tx.recipient_account for tx in successful}
            print('Known Recipients:', ', '.join(sorted(recipients)))
        else:
            print('Observed Average Amount: No completed history yet')
            print('Known Recipients: None yet')

    def get_account_summary(self):
        return {'account_id': self.account.account_id, 'available_balance': self.account.available_balance, 'reserved_balance': self.account.reserved_balance, 'active_holds': len(self.active_holds), 'transactions': len(self.transaction_history)}

    def get_transactions_as_dicts(self):
        return [tx.to_dict() for tx in self.transaction_history]

def create_default_registry():
    return {'ACC_NORMAL_01': {'flag_status': 'CLEAN'}, 'ACC_NORMAL_02': {'flag_status': 'CLEAN'}, 'ACC_SUSPECT_22': {'flag_status': 'SUSPECTED'}, 'ACC_FRAUD_88': {'flag_status': 'BLACKLISTED'}}

def create_default_account():
    return BankAccount(account_id='ACC_USER_904', available_balance=INITIAL_BALANCE, reserved_balance=0.0)

def display_analysis(tx, risk_engine, profile, history_before):
    print('\n===================================')
    print(' AI / ML FRAUD ANALYSIS')
    print()
    historical_average = risk_engine.get_historical_average(profile, history_before)
    if historical_average <= 0:
        historical_average = profile.avg_tx_amount
    if historical_average <= 0:
        historical_average = 1.0
    amount_ratio = tx.amount / historical_average
    print('Historical Average: ₹', round(historical_average, 2))
    print('Amount Ratio:', round(amount_ratio, 2), 'x')
    print('Rule Score:', tx.rule_score)
    print('ML Fraud Probability:', tx.ml_probability)
    print('Final Hybrid Risk Score:', tx.risk_score)
    if tx.risk_reasons:
        print('\nDetected Signals:')
        for reason in tx.risk_reasons:
            print(' -', reason)
    else:
        print('\nNo major fraud signals detected.')

def display_hold_alert(tx):
    print('\n===================================')
    print(' SMART TRANSIT HOLD ALERT')
    print()
    print('Suspicious transaction detected.')
    print('Amount: ₹', tx.amount)
    print('Recipient:', tx.recipient_account)
    print('ML Fraud Probability:', tx.ml_probability)
    print('Final Risk Score:', tx.risk_score)
    print('Risk Level:', tx.risk_level)
    print('Hold Expires:', tx.hold_expires_at)
    print('\nReasons:')
    if tx.risk_reasons:
        for reason in tx.risk_reasons:
            print(' -', reason)
    else:
        print(' - Automated security review')
    print('\nFunds have been temporarily reserved.')
    print('APPROVE = Release funds')
    print('DENY = Cancel and restore funds')
    print('LATER = Keep transaction on hold')
if __name__ == '__main__':
    print(f"\n{APP_NAME} - {APP_VERSION}")
    print('Final Backend Polish')
    print('ML + Persistence + Smart Transit Hold')
    print()
    print('Loading fraud detection model...')
    ml_model = FraudMLModel()
    if ml_model.loaded_from_disk:
        print('Saved ML model loaded successfully.')
    else:
        print('New ML model trained and saved successfully.')
    print('Demo validation accuracy:', round(ml_model.validation_accuracy * 100, 2), '%')
    print('Model Type: Random Forest Classifier')
    print('Training Data: 2500 synthetic transactions')
    print('Model File:', MODEL_FILE.name)
    customer = UserProfile(user_id='USR_904', usual_location='Mumbai', avg_tx_amount=500.0, trusted_devices=['MY_IPHONE'])
    datastore = DataStore(STATE_FILE)
    audit_logger = AuditLogger()
    if datastore.exists():
        try:
            account, recipient_registry, loaded_history, loaded_audit = datastore.load()
            audit_logger.events = loaded_audit
            print('\nSaved V7 backend state loaded.')
            print('Previous transactions:', len(loaded_history))
        except Exception as error:
            print('\nSaved state could not be loaded.')
            print('Reason:', error)
            print('Starting with clean demo data.')
            account = create_default_account()
            recipient_registry = create_default_registry()
            loaded_history = []
    else:
        account = create_default_account()
        recipient_registry = create_default_registry()
        loaded_history = []
        print('\nNo V7 state file found.')
        print('Starting clean backend.')
    risk_engine = RiskEngine(recipient_registry, ml_model)
    security_system = SmartHoldSystem(risk_engine, datastore, audit_logger, account)
    security_system.restore_history(loaded_history)
    expired = security_system.check_expired_holds()
    if expired > 0:
        print('\nSECURITY NOTICE:')
        print(expired, 'hold(s) expired and were escalated.')
    audit_logger.log('SYSTEM_STARTED', 'V7 backend started successfully.')
    security_system.save_state()
    while True:
        security_system.check_expired_holds()
        summary = security_system.get_account_summary()
        print('\n===================================')
        print(' MAIN MENU')
        print()
        print('Available Balance: ₹', summary['available_balance'])
        print('Reserved Balance: ₹', summary['reserved_balance'])
        print('Active Holds:', summary['active_holds'])
        print()
        print('1. NEW TRANSACTION')
        print('2. VIEW TRANSACTION HISTORY')
        print('3. VIEW BEHAVIOUR PROFILE')
        print('4. VIEW PENDING HOLDS')
        print('5. CUSTOMER VERIFY HOLD')
        print('6. SECURITY REVIEW ESCALATED HOLD')
        print('7. TEST HOLD TIMEOUT')
        print('8. VIEW ML FEATURE IMPORTANCE')
        print('9. VIEW SECURITY AUDIT LOG')
        print('10. RESET V7 DEMO DATA')
        print('11. EXIT')
        choice = input('\nEnter choice: ').strip()
        if choice == '1':
            print('\n===================================')
            print(' NEW TRANSACTION')
            print()
            print('Demo Recipient Accounts:')
            print('ACC_NORMAL_01   CLEAN')
            print('ACC_NORMAL_02   CLEAN')
            print('ACC_SUSPECT_22  SUSPECTED')
            print('ACC_FRAUD_88    BLACKLISTED')
            recipient = normalize_account_id(input('\nEnter recipient account: '))
            if not recipient:
                print('Recipient cannot be empty.')
                continue
            try:
                amount = float(input('Enter transaction amount: ₹'))
            except ValueError:
                print('Invalid amount.')
                continue
            if amount <= 0:
                print('Amount must be greater than zero.')
                continue
            if amount > 1000000000:
                print('Amount exceeds demo transaction limit.')
                continue
            location = normalize_location(input('Enter current location: '))
            if not location:
                print('Location cannot be empty.')
                continue
            device = normalize_device(input('Enter device ID: '))
            if not device:
                print('Device ID cannot be empty.')
                continue
            transaction = Transaction(sender_id=customer.user_id, recipient_account=recipient, amount=money(amount), location=location, device_id=device)
            history_before = list(security_system.transaction_history)
            result = security_system.process_transaction(transaction, customer)
            if result.risk_level != 'NOT_ANALYSED':
                display_analysis(result, risk_engine, customer, history_before)
            print('\n===================================')
            print(' AI TRANSACTION RESULT')
            print()
            print('Transaction ID:', result.transaction_id)
            print('Rule Score:', result.rule_score)
            print('ML Fraud Probability:', result.ml_probability)
            print('Final Hybrid Risk Score:', result.risk_score)
            print('Risk Level:', result.risk_level)
            print('Status:', result.status)
            print('Message:', result.message)
            print('Available Balance: ₹', account.available_balance)
            print('Reserved Balance: ₹', account.reserved_balance)
            if result.status == 'ON_HOLD':
                display_hold_alert(result)
                while True:
                    response = input('\nAPPROVE / DENY / LATER: ').strip().upper()
                    if response in ('APPROVE', 'DENY', 'LATER'):
                        break
                    print('Please enter APPROVE, DENY, or LATER.')
                if response == 'LATER':
                    print('\nTransaction remains under Smart Transit Hold.')
                else:
                    final_result, message = security_system.verify_transaction(result.transaction_id, response)
                    print('\n===================================')
                    print(' FINAL VERIFICATION RESULT')
                    print()
                    if final_result:
                        print('Status:', final_result.status)
                    print('Message:', message)
                    print('Available Balance: ₹', account.available_balance)
                    print('Reserved Balance: ₹', account.reserved_balance)
        elif choice == '2':
            security_system.show_transaction_history()
            input('\nPress ENTER to return...')
        elif choice == '3':
            security_system.show_behaviour_summary(customer)
            input('\nPress ENTER to return...')
        elif choice == '4':
            security_system.show_pending_holds()
            input('\nPress ENTER to return...')
        elif choice == '5':
            security_system.show_pending_holds()
            if not security_system.active_holds:
                continue
            tx_id = input('\nEnter Transaction ID: ').strip()
            tx = security_system.active_holds.get(tx_id)
            if tx is None:
                print('Transaction not found.')
                continue
            if tx.status == 'ESCALATED':
                print('Transaction is escalated.')
                print('Use security review.')
                continue
            action = input('Enter APPROVE or DENY: ').strip().upper()
            result, message = security_system.verify_transaction(tx_id, action)
            print('\nMessage:', message)
            if result:
                print('Status:', result.status)
                print('Available Balance: ₹', account.available_balance)
                print('Reserved Balance: ₹', account.reserved_balance)
        elif choice == '6':
            security_system.show_pending_holds()
            escalated_transactions = [tx for tx in security_system.active_holds.values() if tx.status == 'ESCALATED']
            if not escalated_transactions:
                print('\nNo escalated transactions require review.')
                continue
            tx_id = input('\nEnter escalated Transaction ID: ').strip()
            decision = input('Enter RELEASE or CANCEL: ').strip().upper()
            result, message = security_system.security_review(tx_id, decision)
            print('\nMessage:', message)
            if result:
                print('Status:', result.status)
                print('Available Balance: ₹', account.available_balance)
                print('Reserved Balance: ₹', account.reserved_balance)
        elif choice == '7':
            security_system.show_pending_holds()
            on_hold_transactions = [tx for tx in security_system.active_holds.values() if tx.status == 'ON_HOLD']
            if not on_hold_transactions:
                print('\nNo ON_HOLD transaction available.')
                print('Create a risky transaction and choose LATER first.')
                continue
            print('\nThis is a DEMO TEST.')
            print('It simulates the 15-minute hold expiring immediately.')
            tx_id = input('\nEnter ON_HOLD Transaction ID: ').strip()
            result, message = security_system.force_timeout_for_demo(tx_id)
            print('\nMessage:', message)
            if result:
                print('Status:', result.status)
                print('Escalated At:', result.escalated_at)
                print('Reserved Balance: ₹', account.reserved_balance)
                print('\nFunds remain protected until security review.')
        elif choice == '8':
            ml_model.show_feature_importance()
            input('\nPress ENTER to return...')
        elif choice == '9':
            audit_logger.show_logs()
            input('\nPress ENTER to return...')
        elif choice == '10':
            print('\n===================================')
            print(' RESET V7 DEMO DATA')
            print()
            print('This removes saved banking state.')
            print('The ML model file will remain.')
            confirm = input('\nType RESET to confirm: ').strip().upper()
            if confirm != 'RESET':
                print('Reset cancelled.')
                continue
            datastore.reset()
            print('\nV7 banking state deleted.')
            print('Run the program again for clean demo data.')
            raise SystemExit
        elif choice == '11':
            audit_logger.log('SYSTEM_STOPPED', 'V7 backend closed normally.')
            security_system.save_state()
            print('\n===================================')
            print(' SESSION ENDED')
            print()
            print('V7 backend state saved.')
            print('Available Balance: ₹', account.available_balance)
            print('Reserved Balance: ₹', account.reserved_balance)
            print('Transactions:', len(security_system.transaction_history))
            print('Active Holds:', len(security_system.active_holds))
            print('\nState File:')
            print(STATE_FILE)
            print('\nML Model File:')
            print(MODEL_FILE)
            raise SystemExit
        else:
            print('\nInvalid choice.')
            print('Enter a number from 1 to 11.')
