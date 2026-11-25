# AdaptIQ — Clerk Authentication Setup

## Overview

AdaptIQ uses Clerk as its authentication provider. This setup allows team members to use the same Clerk development application while working on separate GitHub branches.

## 1. Get the Clerk application credentials

1. Sign in to the Clerk Dashboard at https://dashboard.clerk.com/.
2. Select the AdaptIQ development application.
3. Navigate to API Keys.
4. Obtain the publishable key and secret key through approved team access.

Never commit the Clerk secret key to GitHub.

## 2. Configure your local environment

From the backend directory, create a local environment file:

```bash
cp .env.example .env
```

Update the local `.env` file with your PostgreSQL connection string and Clerk credentials:

```dotenv
DATABASE_URL=your_postgresql_connection_string
CLERK_PUBLISHABLE_KEY=your_publishable_key
CLERK_SECRET_KEY=your_secret_key
```

The `.env` file must remain excluded from Git.

## 3. Install backend dependencies

From the `backend` directory:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## 4. Start the Flask backend

```bash
python -m flask --app app:create_app run --debug --port 5000
```

The backend health endpoint is available at:

http://127.0.0.1:5000/api/health

## 5. Development responsibilities

- **Account & Sign-In:** Clerk registration, login, logout, and frontend integration.
- **A&P-2:** Clerk token verification, database identity validation, and protected Flask endpoints.
- **A&P-3:** Session refresh and expiration behavior, coordinated with Clerk's session management.


## Security

- Never commit Clerk secret keys or service credentials.
- Use only approved development credentials for local testing.
- Do not expose backend secret keys in frontend JavaScript.
- Use HTTPS for deployed authentication requests.
- Flask debug mode is for local development only.