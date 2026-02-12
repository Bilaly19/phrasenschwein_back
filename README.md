# phrasenschewein_backend

Backend für das Phrasenschwein mit Express, Datei-Persistenz und Token-basierter Session-Verwaltung.

## Projektstruktur (aktuell)

- `app.js`: Baut die Express-App inkl. Routing und Middleware auf.
- `server.js`: Startet den HTTP-Server (Bootstrap/Entry Point).
- `services/namesService.js`: Geschäftslogik für Namen und Konfiguration.
- `services/authService.js`: Geschäftslogik für Registrierung, Login und Logout.
- `storage.js`: Lesen/Schreiben + Normalisierung der JSON-Dateien.
- `middleware/`: Auth, Error-Handling, Rate-Limiting.
- `test/`: Unit- und Integrations-Tests mit `node:test`.

## Project Setup

```sh
npm install
```

## Start

```sh
npm start
```

## Tests

```sh
npm test
```

## Environment Variables

- `PAYPAL_DONATION_URL` (optional): Public PayPal donation URL that is exposed via `GET /api/donation-link` for the frontend integration.
- `PORT` (optional): Port für den Server (Default: `3000`).
- `DATA_PATH` (optional): Pfad zur Daten-Datei (Default: `./data.json`).
- `USERS_PATH` (optional): Pfad zur User-Datei (Default: `./users.json`).
- `SESSION_TTL_MINUTES` (optional): Session-Lebensdauer in Minuten.
- `CORS_ORIGINS` (optional): Komma-separierte Liste erlaubter Origins.
