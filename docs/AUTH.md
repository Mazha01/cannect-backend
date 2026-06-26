# Authentication & Authorization

Two independent systems, one shared JWT (HS256, `{userId,email,role,type}`, access 7d;
read from the `token` cookie then `Authorization: Bearer`). Passwords are bcrypt;
errors flow through `fault` (Kind → HTTP status). Users and admins live in the same
Mongo `users` collection; 2FA pending state lives in Redis.

---

## 1. User — email + password

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant API as backend /auth
    participant DB as Mongo
    participant M as Mailer (dev: log)

    C->>API: POST /register {email,password}
    API->>API: validate + bcrypt.hash
    API->>DB: insert user (emailVerified=false)
    API->>M: send 6-digit code (TTL 1m)
    API-->>C: {requiresVerification, email}

    C->>API: POST /verify-email {email, code}
    API->>API: check code + expiry
    API->>DB: emailVerified=true
    API-->>C: {accessToken, user} + Set-Cookie token

    C->>API: POST /login {email,password}
    API->>DB: find user
    API->>API: bcrypt.compare
    alt email not verified
        API-->>C: 403 {requiresVerification}
    else ok
        API-->>C: {accessToken, user}
    end

    C->>API: GET /auth/me (Bearer JWT)
    API->>API: verifyToken
    API->>DB: load user
    API-->>C: {user}
```

---

## 2. User — Google (two-factor)

Google confirms identity (1st factor); a code emailed to the user is the 2nd factor.

```mermaid
sequenceDiagram
    autonumber
    actor B as Browser
    participant API as backend /auth
    participant G as Google
    participant DB as Mongo
    participant M as Mailer (dev: log)

    B->>API: GET /auth/google
    API-->>B: 302 to Google consent
    B->>G: sign in
    G-->>B: 302 /auth/callback/google?code
    B->>API: GET /auth/callback/google?code
    API->>G: exchange code
    G-->>API: id_token
    API->>API: verify id_token (1st factor)
    API->>DB: upsert user
    API->>M: send 6-digit code (2nd factor)
    API-->>B: requires2FA (redirect to enter code)

    B->>API: POST /auth/google/verify {email, code}
    API->>API: check code
    API-->>B: {accessToken, user}
```

---

## 3. Admin — password + Telegram OIDC

OpenID Connect (Authorization Code + PKCE, RS256). Only `role: admin`. The password
and Telegram steps are tied by a Redis pending token.

```mermaid
sequenceDiagram
    autonumber
    actor B as Browser
    participant API as backend /admin
    participant R as Redis
    participant T as oauth.telegram.org
    participant DB as Mongo

    B->>API: POST /admin/auth/login {email,password}
    API->>DB: find admin (role=admin)
    API->>API: bcrypt.compare
    API->>R: SET admin:2fa:<tft> = adminID (TTL 5m)
    API-->>B: {twoFactorToken}

    B->>API: GET /admin/auth/oidc/start?twoFactorToken=<tft>
    API->>R: GET admin:2fa:<tft> (must exist)
    API->>API: gen state + nonce + PKCE
    API->>R: SET admin:oidc:<state> = {tft,nonce,verifier} (TTL 5m)
    API-->>B: 302 authorize(client_id, redirect_uri, scope, state, nonce, code_challenge S256)

    B->>T: consent
    T-->>B: 302 /admin/auth/oidc/callback?state&code
    B->>API: GET /admin/auth/oidc/callback?state&code
    API->>R: GET admin:oidc:<state> -> {tft,nonce,verifier}
    API->>R: GET admin:2fa:<tft> -> adminID
    API->>T: POST /token (code + code_verifier, Basic client_id:secret)
    T-->>API: id_token (JWT, RS256)
    API->>T: GET JWKS (public keys, cached)
    API->>API: verify RS256 + iss/aud/exp/nonce
    API->>DB: admin.telegramId == sub ? bind on first use : 403
    API->>R: DEL state + pending (one-time use)
    API-->>B: 302 .../dev/telegram-login#token=...  (or JSON)

    B->>API: GET /admin/auth/me (Bearer)
    API->>API: requireRole("admin")
    API-->>B: {user}
```

### Guarantees (admin flow)

| Mechanism | Protects against |
|---|---|
| password ⇄ Telegram tied by Redis pending token | completing 2FA without the password |
| id_token RS256, verified via Telegram JWKS (public key) | forged logins even if our server is compromised |
| `state` / `nonce` / PKCE | CSRF and replay |
| `admin.telegramId` (TOFU bind) | another Telegram account logging in as the admin |
| `DEL state + pending` after use | replaying the same `state`/code |
