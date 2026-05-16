# Z-Auth

Passwordless WebAuthn authentication app with React, Express, Prisma, and PostgreSQL.

## Features

- Username-based accounts.
- WebAuthn registration and login only.
- User verification is required, with a phone passkey/fingerprint-focused UI.
- Roles: `user` and `admin`.
- User passkey management for adding, renaming, and deleting extra devices.
- User and admin session management.
- Admin user management for roles, usernames, disabled status, passkey metadata, sessions, dashboard metrics, and audit logs.
- No Docker setup.

Browsers do not let web apps force fingerprint specifically. The app requires WebAuthn user verification and allows phone passkeys, so the phone may use fingerprint, PIN, face unlock, or another configured verifier.

## Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Create `.env` from `.env.example` and set `DATABASE_URL`.

3. Create the database schema:

   ```bash
   npm run prisma:migrate -- --name init
   ```

4. Seed the initial admin username:

   ```bash
   npm run seed
   ```

5. Start the API and frontend:

   ```bash
   npm run dev
   ```

The frontend runs at `http://localhost:5173` and the API runs at `http://localhost:4000`.

## First Admin Phone Passkey

The seed creates the admin user record only. Open the app, choose registration, enter the same username configured in `SEED_ADMIN_USERNAME`, and register a phone passkey when the browser shows the WebAuthn prompt.
