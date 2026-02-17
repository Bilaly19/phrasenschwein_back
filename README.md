# phrasenschewein_backend

Express backend for Phrasenschwein. The active runtime is `server.js` and it boots `src/backend/app/createApp.js`.

This repository is backend-only. Legacy root modules and frontend scaffold files were removed in favor of `src/backend/*` as the single runtime source.

## Runtime entrypoints

- `server.js`: starts the HTTP server
- `src/backend/app/createApp.js`: builds the active backend app and wiring

## Install

```sh
npm install
```

## Local setup (required once)

1. Create env file from template:
```powershell
Copy-Item .env.example .env
```
2. Create local JSON storage files from templates:
```powershell
Copy-Item data.example.json data.json
Copy-Item users.example.json users.json
Copy-Item pigs.example.json pigs.json
```
3. Optional development seed user:
- Set `DEV_SEED_USER=1`
- Set `DEV_SEED_USERNAME` and `DEV_SEED_PASSWORD`
- Optional: set `DEV_SEED_IS_ADMIN=1` to seed with roles `['admin', 'user']`
- This only runs when `NODE_ENV=development` and is ignored in production.

`data.json`, `users.json`, `pigs.json`, and `.env` are local-only and ignored by git.

## Run

```sh
npm run dev
```

or

```sh
npm start
```

## Test

```sh
npm test
```

```sh
npm run test:contract
```

## CI-friendly checks

```sh
npm ci
npm test
npm run lint
```

## Production startup checklist

1. Set required environment variables:
- `NODE_ENV=production`
- `PORT` (for example `3000`)
- `CORS_ALLOWED_ORIGINS` (comma-separated allowlist, no wildcards in production), for example:
  `CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com`
2. Ensure local storage files exist before boot:
- `data.json` must exist
- `users.json` must exist
- `pigs.json` must exist
3. Confirm those storage files are not tracked by git:
- `data.json`, `users.json`, and `pigs.json` are ignored and should stay local-only
4. Start server:
```sh
npm start
```

## Environment variables

- `NODE_ENV` (default: `development`)
- `PORT` (default: `3000`)
- `CORS_ALLOWED_ORIGINS` (comma separated allowlist; preferred name)
- `CORS_ORIGINS` (legacy alias for `CORS_ALLOWED_ORIGINS`)
- `DATA_PATH` (default: `./data.json`)
- `USERS_PATH` (default: `./users.json`)
- `PIGS_PATH` (default: `./pigs.json`)
- `DEV_SEED_USER` (default: `0`; when set to `1` in development, creates a default user if missing)
- `DEV_SEED_IS_ADMIN` (default: `0`; when set to `1` with `DEV_SEED_USER=1`, seeds roles `['admin', 'user']`)
- `DEV_SEED_USERNAME` (required when `DEV_SEED_USER=1`)
- `DEV_SEED_PASSWORD` (required when `DEV_SEED_USER=1`)
- `SESSION_TTL_MINUTES` (default: `1440`)
- `SESSION_ROLLING` (default: `true`)
- `BCRYPT_ROUNDS` (default: `10`)
- `AUTH_RATE_LIMIT_WINDOW_MS` (default: `900000`)
- `AUTH_RATE_LIMIT_MAX` (default: `20`)
- `AUTH_ACCOUNT_RATE_LIMIT_MAX` (default: `AUTH_RATE_LIMIT_MAX`)
- `AUTH_LOGOUT_RATE_LIMIT_MAX` (default: `max(AUTH_RATE_LIMIT_MAX, 60)`)
- `PAYPAL_DONATION_URL` (optional)

## Auth endpoint notes

- `GET /api/session` requires `Authorization: Bearer <token>`.
  Without a valid header it returns `401` with `error.code = UNAUTHORIZED`.
- `POST /api/logout` also requires `Authorization: Bearer <token>`.
- Role storage is per user in `users.json` via `roles` array. For admin users use `roles: ['admin', 'user']`.
- `POST /api/register` creates accounts with default role `['user']`.
- `GET /api/users` lists users (authenticated).
- `POST /api/users` creates a user (authenticated):
  admins can set `roles`, normal users always create with `['user']`.
  Normal users can create only one additional user (`USER_CREATE_LIMIT_REACHED`).
- `PATCH /api/users/:username/roles` updates roles (admin only).

## Phrasenschwein (Pigs) endpoints

- `POST /api/pigs` creates a new pig (authenticated). The creator becomes pig admin.
- `GET /api/pigs` lists pigs for the authenticated user (includes membership role).
- `POST /api/pigs/:pigId/invites` creates a shareable invite token (pig admin only).
  The frontend can use `https://<app>/invite/<token>` for register/login + auto-join.
- `POST /api/invites/accept` accepts an invite token and joins the pig (authenticated).
- `GET /api/pigs/:pigId/names` returns the per-pig board (member only).
- `GET /api/pigs/:pigId/config` returns pig config (member only).
- `POST /api/pigs/:pigId/config` updates `valuePerClick` per pig (pig admin only).
- `POST /api/pigs/:pigId/increment/:username` increments own entry (member only, ownership enforced).
- `POST /api/pigs/:pigId/reset` resets own entry (member only).
- `DELETE /api/pigs/:pigId/delete/:username` deletes own entry (member only, ownership enforced).
