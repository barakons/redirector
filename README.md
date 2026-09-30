# redirector

Lite link redirector — zero dependencies, single `server.js` + SQLite (Node built-in `node:sqlite`).

- Public: `/{label}` → 302 redirect to target URL (clicks counted)
- `/admin` → login (username/password, session cookie, scrypt hashing)
- `/admin/links` → link management
  - fields: **label** (`domain.com/{custom-label}`), **url**, **notes**
  - labels auto-slugified: `My Cool Link!` → `my-cool-link` (lowercase, spaces/symbols → `-`)
  - each row has a **QR** button: popup with QR of the full short URL + Download PNG
  - regular `user` manages only own links, `admin` manages all
- `/admin/users` → user CRUD (`admin` / `user` roles), admin-only

## Run

Requires Node ≥ 22 (uses `node:sqlite`, no `npm install` needed).

```bash
node server.js
# or
npm start
```

## Run with PM2 (port 3461)

`ecosystem.config.cjs` runs the app on port **3461**:

```bash
pm2 start ecosystem.config.cjs
pm2 save
pm2 startup   # optional: resurrect on reboot
```

Useful commands: `pm2 logs redirector`, `pm2 restart redirector`, `pm2 stop redirector`.

Env:

| var | default | desc |
|---|---|---|
| `PORT` | `3000` | http port |
| `DB_PATH` | `./data.db` | sqlite file |
| `ADMIN_USER` / `ADMIN_PASS` | `admin` / `admin123` | seeded only when DB has zero users |

Open http://localhost:3000, login at http://localhost:3000/admin/login.

## Notes

- Labels: auto-slugged to `[a-z0-9-]{1,64}`; reserved words (`admin`, `login`, `logout`, `healthz`, `api`, `static`, …) blocked.
- Labels are unique (DB `UNIQUE` + explicit pre-check): reusing one shows `Label "/x" is already used → <target>`, and the form warns live (✓ available / ⚠ already used) as you type.
- QR: vendored `qrcode.min.js` (davidshimjs qrcodejs, MIT), served locally at `/qrcode.min.js` — no CDN needed.
- URLs must start with `http://` or `https://`.
- Guards: can't delete/demote yourself, can't remove the last admin.
- Sessions: random token in SQLite, `HttpOnly; SameSite=Lax`, 7-day expiry, per-session CSRF token on all POST forms.
