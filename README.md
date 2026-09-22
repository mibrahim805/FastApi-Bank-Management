# ATM Banking Web App

A small multi-user ATM-style app built with FastAPI, Jinja2, SQLAlchemy, and SQLite.

## Run it

```bash
python3 -m pip install -r requirements.txt
python3 -m uvicorn app:app --reload
```

Open http://127.0.0.1:8000 in your browser.

The app creates `atm.db` automatically. It includes these demo accounts:

- `ibrahim` / `1345`
- `demo` / `2468`

Demo phone numbers are `+15555550101` and `+15555550102`. Phone numbers must use international format, such as `+923001234567`.

Users can also create accounts from the registration page. PINs are stored as salted PBKDF2 hashes, and balances are stored in integer cents.

This is a learning project, not a production banking system. A real deployment would also need HTTPS, CSRF protection, rate limiting, audit controls, a production database, and proper banking/payment integrations.

## Real SMS OTPs with Amazon SNS

Without AWS credentials, the app uses development mode: the OTP is logged in the terminal and shown on the verification page. To send real SMS messages through Amazon SNS, install the requirements and configure an AWS identity with the `sns:Publish` permission. Boto3 can use `aws configure` or these environment variables:

```bash
export AWS_ACCESS_KEY_ID="your-access-key-id"
export AWS_SECRET_ACCESS_KEY="your-secret-access-key"
export AWS_DEFAULT_REGION="us-east-1"
```

Amazon SNS requires phone numbers in E.164 format. New AWS accounts may be in the SMS sandbox, where only verified destination phone numbers can receive messages.
# FastApi-Bank-Management
