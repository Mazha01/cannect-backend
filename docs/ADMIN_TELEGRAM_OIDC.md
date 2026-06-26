# Admin login via Telegram OIDC — пошаговая настройка

Админский вход = **пароль (1-й фактор) + Telegram OIDC (2-й фактор)**.
Telegram использует OpenID Connect (Authorization Code + PKCE, подпись RS256).
Ниже — как получить `client_id` / `client_secret` и запустить.

---

## 1. Создать бота в @BotFather

1. В Telegram открой **@BotFather** → `/start`.
2. `/newbot` → задай **имя** (напр. `Cannect Admin`) → **username**, оканчивающийся на `bot` (напр. `cannect_admin_bot`).
3. Сохрани присланный **bot token** (вид `123456789:AA...`). Для OIDC он напрямую не нужен, но пусть будет.

## 2. Включить Web Login и взять client_id / client_secret

> Web Login настраивается в **mini-app BotFather** (веб-интерфейс), а не в текстовом меню.

1. В чате с @BotFather: `/mybots` → выбери своего бота → **Bot Settings**.
2. Найди **Web Login** (может называться *Configure Web Login*).
   - Если в текстовом меню его нет — нажми **кнопку-меню** (☰ слева от поля ввода) → откроется **mini-app BotFather** → **Bot Settings → Web Login**.
3. В **Allowed URLs / Redirect URLs** добавь **точный** redirect (символ-в-символ):
   ```
   https://<твой-домен>/admin/auth/oidc/callback
   ```
   Локально нужен публичный домен (Telegram не принимает `localhost`) — см. раздел «Туннель».
4. BotFather покажет **Client ID** (обычно = id бота) и **Client Secret** — скопируй оба.

> Если пункта **Web Login** нет — у твоего бота фича OIDC недоступна (она новая). Тогда вход через Telegram OIDC технически не поднять.

## 3. (Локально) поднять публичный домен — туннель

Telegram редиректит браузер на твой `redirect_uri`, поэтому нужен HTTPS-домен.

```bash
# cloudflared (без аккаунта):
cloudflared tunnel --url http://localhost:8080
# или ngrok:
ngrok http 8080
```
Возьми выданный `https://…` домен и используй его и в **BotFather → Allowed URLs**, и в env ниже.

## 4. Прописать env и запустить

```bash
cd cannect-backend

# инфраструктура
docker compose up -d mongo redis      # или свой mongod/redis на localhost

# первый админ (пароль хэшируется автоматически)
go run ./cmd/seed --email admin@cannect.kz --password 'Passw0rd!'

# запуск с OIDC
TELEGRAM_OIDC_CLIENT_ID='<client_id>' \
TELEGRAM_OIDC_CLIENT_SECRET='<client_secret>' \
TELEGRAM_OIDC_REDIRECT_URL='https://<твой-домен>/admin/auth/oidc/callback' \
TELEGRAM_OIDC_POST_AUTH_URL='https://<твой-домен>/dev/telegram-login' \
LOG_FORMAT=text go run ./cmd/cannect
```

В логе должно появиться: `admin auth enabled (password + telegram OIDC 2FA)`.
Если вместо этого `admin auth disabled` — не заданы `CLIENT_ID` / `CLIENT_SECRET`.

> `redirect_uri` в env и в BotFather должны **совпадать точно**, иначе Telegram отклонит вход.

## 5. Проверить вход

Открой в браузере:
```
https://<твой-домен>/dev/telegram-login
```
1. **Шаг 1** — email `admin@cannect.kz` + пароль `Passw0rd!` → **Login**.
2. **Шаг 2** — **Login via Telegram** → подтверди в Telegram.
3. Вернёт на страницу с `{ "oidc": "success", "accessToken": "...", "me": { "user": { "role": "admin" } } }`.

Первый успешный вход **привязывает** твой Telegram (`sub` из id_token) к админу (TOFU).
Дальше вход возможен только с этого Telegram; чужой → `403 telegram account does not match`.

---

## Эндпоинты

| Метод | Путь | Назначение |
|---|---|---|
| POST | `/admin/auth/login` | пароль → `{ twoFactorToken }` (pending 5 мин в Redis) |
| GET | `/admin/auth/oidc/start?twoFactorToken=…` | 302 → Telegram consent |
| GET | `/admin/auth/oidc/callback?state=&code=` | проверка id_token → JWT |
| GET | `/admin/auth/me` | профиль (нужна роль `admin`) |

## Управление админами (в БД)

```bash
# создать ещё одного админа
go run ./cmd/seed --email admin2@cannect.kz --password 'Passw0rd!'

# перепривязать Telegram (следующий вход привяжет новый аккаунт)
mongosh "mongodb://localhost:27017/cannect" --eval \
  'db.users.updateOne({email:"admin2@cannect.kz"}, {$unset:{telegramId:""}})'

# снять роль / удалить
mongosh "mongodb://localhost:27017/cannect" --eval \
  'db.users.updateOne({email:"admin2@cannect.kz"}, {$set:{role:"user"}})'
```

## Переменные окружения (OIDC)

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `TELEGRAM_OIDC_CLIENT_ID` | — | Client ID из BotFather Web Login |
| `TELEGRAM_OIDC_CLIENT_SECRET` | — | Client Secret из BotFather Web Login |
| `TELEGRAM_OIDC_REDIRECT_URL` | `http://localhost:8080/admin/auth/oidc/callback` | должен совпадать с Allowed URL в BotFather |
| `TELEGRAM_OIDC_POST_AUTH_URL` | — | куда вернуть браузер после успеха (токен в `#fragment`); пусто → JSON |
| `TELEGRAM_OIDC_ISSUER` | `https://oauth.telegram.org` | issuer |
| `TELEGRAM_OIDC_AUTH_URL` | `https://oauth.telegram.org/auth` | authorization endpoint |
| `TELEGRAM_OIDC_TOKEN_URL` | `https://oauth.telegram.org/token` | token endpoint |
| `TELEGRAM_OIDC_JWKS_URI` | `https://oauth.telegram.org/.well-known/jwks.json` | публичные ключи (RS256) |

Эндпоинты Telegram подтверждены его discovery-документом
(`https://oauth.telegram.org/.well-known/openid-configuration`): issuer, `/auth`,
`/token`, `jwks_uri`, `client_secret_basic`, RS256, PKCE S256 — совпадают с дефолтами.
