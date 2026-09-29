# Smart Transit Hold

Smart Transit Hold is an AI-powered banking security prototype that detects when a suspicious phone call may be influencing a customer’s payment decision.

The system combines call-scam intelligence, transaction-risk analysis, and risk fusion to place suspicious transfers under Smart Transit Hold before settlement.

## Main Flow

1. Customer receives a suspicious call.
2. Customer taps “Suspect Spam/Fraud” in the mobile report simulation.
3. The call recording is uploaded and analysed.
4. The customer attempts a money transfer.
5. Risk Fusion combines call risk and transaction risk.
6. High-risk transfers are placed under Smart Transit Hold.
7. The customer can cancel, send to security review, or release after independent OTP verification.

## Tech Stack

- Python
- Flask
- Faster-Whisper
- scikit-learn
- HTML/CSS/JavaScript
- Smart Transit Hold risk-fusion logic

## Run Locally

Install dependencies:

```bash
py -m pip install -r requirements.txt