# Define Auth Service

TypeScript NestJS project that centralises authentication concerns for the Define platform. It supports traditional email/password sign‑in, Google OAuth, JWT access tokens, hashed refresh tokens backed by persisted sessions, password reset flows, and email verification.

## Features
- User registration with server-side validation, lower-cased emails, and verification token issuance.
- JWT access tokens (configurable expiry) plus database backed refresh tokens stored as bcrypt hashes.
- Session lifecycle management with revoke endpoints and automatic invalidation on password changes.
- Password reset flow that produces signed reset tokens for delivery by your notification layer.
- Email verification tokens with dedicated endpoint for flagging accounts as verified.
- Optional Google OAuth 2.0 strategy that onboards new users automatically.
- Swagger decorators on controller methods for automatic API documentation.

## Prerequisites
- Node.js v18+ and npm v9+.
- PostgreSQL 15 (use the included Docker Compose file for local development).
- TypeORM migrations rely on a reachable database defined through `DATABASE_URL`.

## Getting Started
1. **Install dependencies**
   ```bash
   npm install
   ```
2. **Launch PostgreSQL (optional)**
   ```bash
   docker-compose up -d
   ```
3. **Configure environment**
   - Duplicate `.env` or create a new one with the variables listed below.
   - Ensure `DATABASE_URL` points at your Postgres instance (when using Docker it already matches the compose service).
4. **Run pending migrations**
   ```bash
   npm run migration:run
   ```
5. **Start the API**
   ```bash
   npm run start:dev
   ```
6. **Open Swagger (optional)** – once the Nest app is running, mount Swagger and explore the `auth` and `sessions` routes.

## Environment Variables
| Key | Purpose |
| --- | --- |
| `DATABASE_URL` | Postgres connection string used by TypeORM. |
| `JWT_ACCESS_SECRET` | Secret for signing access tokens (used by both Nest `JwtModule` and manual token generation). |
| `ACCESS_TOKEN_EXPIRY` | Access token lifetime (default `15m`). |
| `REFRESH_TOKEN_EXPIRY_MS` | Refresh session lifetime in milliseconds (default `86400000`). |
| `JWT_PASSWORD_RESET_SECRET` | (Optional) Separate secret for password reset tokens; falls back to `JWT_ACCESS_SECRET` when omitted. |
| `PASSWORD_RESET_TOKEN_EXPIRY` | (Optional) Reset token validity (default `15m`). |
| `JWT_EMAIL_VERIFICATION_SECRET` | (Optional) Secret for email verification tokens; defaults to `JWT_ACCESS_SECRET`. |
| `EMAIL_VERIFICATION_TOKEN_EXPIRY` | (Optional) Verification token validity window (default `1d`). |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GOOGLE_CALLBACK_URL` | Google OAuth credentials used by the bundled Passport strategy. |
| `PORT` | Nest HTTP port (default `3002`). |

## Auth Flow Reference
- `POST /auth/register` – registers a new user. The response includes a `verificationToken` that can be emailed to the user and later confirmed via `/auth/verify-email`.
- `POST /auth/login` – authenticates email/password users, returning both access and refresh tokens alongside the verification flag.
- `POST /auth/refresh-token` – exchanges a valid refresh token for a fresh access token. Refresh tokens are hashed and matched against active database sessions.
- `POST /auth/logout` – revokes all active sessions for a user ID (useful for account-level sign out).
- `POST /auth/forgot-password` – generates a signed reset token for downstream delivery. For convenience the token is returned in the response during development.
- `POST /auth/change-password` – protected route that validates the existing password, enforces change, and revokes outstanding sessions.
- `POST /auth/verify-email` – validates an email verification token and marks the user as verified.
- `GET /auth/me` – protected route returning the authenticated user profile (id, email, name, roles, timestamps).
- `GET /auth/roles` – protected route returning the current user’s role assignments.
- `GET /auth/google/callback` – Google OAuth redirect handler; exchanges Google profile data for local JWTs and creates the account on first login.
- `GET /sessions/user/:userId` / `DELETE` endpoints – session inspector and revocation APIs for administrative tooling.

## Testing & Tooling
- `npm run test` – executes unit tests via Jest.
- `npm run lint` / `npm run format` – keep the code style consistent with ESLint and Prettier.
- `npm run migration:new my-description` – scaffold a timestamped TypeORM migration in `src/migrations`.

## Next Steps
- Integrate an email or notification service to deliver the password reset and verification tokens.
- Extend the `AuthService` specs to cover the new flows (mocking token issuance and repository interactions).
- Layer rate limiting or CAPTCHA on sensitive routes (`register`, `login`, `forgot-password`) before production use.
