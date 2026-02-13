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
```

`data.json`, `users.json`, and `.env` are local-only and ignored by git.

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

## Environment variables

- `NODE_ENV` (default: `development`)
- `PORT` (default: `3000`)
- `CORS_ALLOWED_ORIGINS` (comma separated allowlist; preferred name)
- `CORS_ORIGINS` (legacy alias for `CORS_ALLOWED_ORIGINS`)
- `DATA_PATH` (default: `./data.json`)
- `USERS_PATH` (default: `./users.json`)
- `SESSION_TTL_MINUTES` (default: `1440`)
- `SESSION_ROLLING` (default: `true`)
- `BCRYPT_ROUNDS` (default: `10`)
- `AUTH_RATE_LIMIT_WINDOW_MS` (default: `900000`)
- `AUTH_RATE_LIMIT_MAX` (default: `20`)
- `AUTH_ACCOUNT_RATE_LIMIT_MAX` (default: `AUTH_RATE_LIMIT_MAX`)
- `PAYPAL_DONATION_URL` (optional)
