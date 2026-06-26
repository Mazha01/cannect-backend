# Cannect Backend

Go backend for Cannect. Empty skeleton — infrastructure only, no business
endpoints yet. Structure and conventions mirror the `opero` service.

## Stack

- **Go 1.25**, [chi](https://github.com/go-chi/chi) router
- **MongoDB** ([mongo-driver](https://go.mongodb.org/mongo-driver)) — primary store
- **Redis** ([go-redis](https://github.com/redis/go-redis)) — sessions / cache
- `log/slog` structured logging, `caarlos0/env` config, `validator/v10`

## Layout

```
cmd/cannect/            — entrypoint (wiring + graceful shutdown)
internal/
  config/               — env-based configuration
  logger/               — slog setup
  database/             — MongoDB client + readiness ping
  redis/                — Redis client
  domain/               — shared error sentinels + ID value object
  transport/http/       — router, middleware, JSON response helpers
```

Business code grows along three layers as endpoints are added:
`transport/http` (handlers) → `service` (logic) → `repository` (Mongo access),
with entities defined in `domain`.

## Run

```bash
cp .env.example .env        # adjust if needed
make dev                    # go run ./cmd/cannect
# or the full stack (mongo + redis + app):
make docker-up
```

## Health checks

- `GET /healthz` — liveness (always 200 while the process is up)
- `GET /readyz`  — readiness (pings MongoDB)
- `GET /ping`    — chi heartbeat

## Auth

JWT (HS256, payload `{userId,email,role,type}`, access 7d), bcrypt passwords,
6-digit codes (1-minute TTL). Token is read from the `token` cookie first, then
`Authorization: Bearer`. Mirrors the cannect-web flow.

### User — `/auth/*`

| Method | Path | Notes |
|---|---|---|
| POST | `/auth/register` | email+password → emails a verification code |
| POST | `/auth/verify-email` | code → `{accessToken, user}` |
| POST | `/auth/resend-code` | resend code (1-min cooldown → 429) |
| POST | `/auth/login` | password → token; unverified → 403 `requiresVerification` |
| POST | `/auth/logout` | clears the cookie |
| POST | `/auth/forgot-password` | emails a reset code (never reveals existence) |
| POST | `/auth/reset-password` | code + newPassword |
| GET  | `/auth/me` | **auth required** |
| GET  | `/auth/google` | redirect to Google consent |
| GET  | `/auth/callback/google` | verifies identity, emails 2FA code |
| POST | `/auth/google/mobile` | `{idToken}` → emails 2FA code |
| POST | `/auth/google/verify` | code → `{accessToken, user}` |

**Google sign-in is two-factor**: Google confirms the identity (1st factor),
then a code is emailed (2nd factor) and completed via `/auth/google/verify`.

### Admin — `/admin/*` (separate flow, role `admin` only)

First factor is email+password; the second factor is **Telegram OIDC** (OpenID
Connect, Authorization Code + PKCE, RS256). The admin proves ownership of their
Telegram account, whose id must match the one linked to the admin (bound on
first successful login, TOFU).

| Method | Path | Notes |
|---|---|---|
| POST | `/admin/auth/login` | password → `{twoFactorToken}` (5-min pending in Redis) |
| GET  | `/admin/auth/oidc/start?twoFactorToken=…` | 302 → Telegram consent |
| GET  | `/admin/auth/oidc/callback?state=&code=` | verifies id_token → `{accessToken, user}` (or 302 to post-auth URL) |
| GET  | `/admin/auth/me` | **admin role required** |

Flow:

```
POST /admin/auth/login {email,password}
   → verify password → pending token in Redis (5 min) → {twoFactorToken}
GET  /admin/auth/oidc/start?twoFactorToken=…
   → mint state+nonce+PKCE (stashed in Redis) → 302 to oauth.telegram.org
← Telegram → GET /admin/auth/oidc/callback?state&code
   ├─ state → {twoFactorToken, nonce, verifier};  pending → adminID
   ├─ exchange code → id_token ; verify RS256 via JWKS + iss/aud/exp/nonce
   ├─ admin.telegramId == id_token.sub ? (bind on first use)
   └─ issue JWT, consume state + pending token
```

Why OIDC over the legacy Login Widget: the id_token is **RS256** signed by
Telegram, so the server verifies with public keys (JWKS) and can't forge a
login even if compromised; `state`/`nonce`/PKCE add CSRF + replay protection.
The password step and the Telegram step are tied by the Redis pending token, so
the second factor can't be completed without first passing the password.

Setup: in **@BotFather → Bot Settings → Web Login**, register the redirect URL
(`…/admin/auth/oidc/callback`) and copy the **Client ID** / **Client Secret**
into `TELEGRAM_OIDC_CLIENT_ID` / `TELEGRAM_OIDC_CLIENT_SECRET`.

> **Email** in dev is not sent for real — the `LogMailer` prints verification
> codes to the server log.

## Make targets

`make help` lists them. Common: `build`, `dev`, `test`, `test-race`, `lint`,
`fmt`, `vet`, `tidy`, `docker-up`, `docker-down`.
