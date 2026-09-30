// redirector — lite link redirector, zero dependencies (Node >= 22, node:sqlite)
// req: /admin login (username/password), /admin/users (admin only CRUD),
//      /admin/links (user owns own, admin sees all), fields: label, url, notes.
// labels auto-slugified ("My Cool Link" -> "my-cool-link"); QR modal served
// via vendored qrcode.min.js (davidshimjs qrcodejs, MIT).

import http from "node:http";
import { DatabaseSync } from "node:sqlite";
import crypto from "node:crypto";
import fs from "node:fs";

// ---------- config ----------
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || "./data.db";
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000;

// vendored QR lib (davidshimjs qrcodejs, MIT) served at /qrcode.min.js
const QR_JS = (() => {
  try {
    return fs.readFileSync(new URL("./qrcode.min.js", import.meta.url));
  } catch {
    console.warn("[redirector] qrcode.min.js not found — QR buttons will not work");
    return null;
  }
})();

const RESERVED = new Set([
  "admin", "login", "logout", "healthz", "robots.txt",
  "favicon.ico", "api", "static",
]);

// ---------- db ----------
const db = new DatabaseSync(DB_PATH);
db.exec("PRAGMA journal_mode = WAL;");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','user')),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  label TEXT UNIQUE NOT NULL,
  url TEXT NOT NULL,
  notes TEXT NOT NULL DEFAULT '',
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  clicks INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
`);

function nowIso() {
  return new Date().toISOString();
}

// ---------- password (scrypt, stdlib only) ----------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `scrypt:${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  try {
    const [algo, salt, hash] = stored.split(":");
    if (algo !== "scrypt" || !salt || !hash) return false;
    const derived = crypto.scryptSync(password, salt, 64).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(derived, "hex"), Buffer.from(hash, "hex"));
  } catch {
    return false;
  }
}

// ---------- seed admin on first run ----------
{
  const row = db.prepare("SELECT COUNT(*) AS c FROM users").get();
  if (row.c === 0) {
    const u = process.env.ADMIN_USER || "admin";
    const p = process.env.ADMIN_PASS || "admin123";
    db.prepare("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)")
      .run(u, hashPassword(p), nowIso());
    console.log(`[redirector] seeded admin user "${u}" (change password after login)`);
  }
}

// ---------- helpers ----------
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function parseCookies(req) {
  const out = {};
  const h = req.headers.cookie;
  if (!h) return out;
  for (const part of h.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > 1_000_000) { reject(new Error("body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function setSessionCookie(res, token) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  res.setHeader("Set-Cookie", `session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${maxAge}`);
}
function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", "session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0");
}

function getAuth(req) {
  const { session } = parseCookies(req);
  if (!session) return null;
  const s = db.prepare("SELECT * FROM sessions WHERE token = ?").get(session);
  if (!s || s.expires_at < Date.now()) {
    if (s) db.prepare("DELETE FROM sessions WHERE token = ?").run(session);
    return null;
  }
  const user = db.prepare("SELECT id, username, role, created_at FROM users WHERE id = ?").get(s.user_id);
  if (!user) return null;
  return { session: s, user };
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const csrf = crypto.randomBytes(16).toString("hex");
  db.prepare("INSERT INTO sessions (token, user_id, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(token, userId, csrf, Date.now() + SESSION_TTL_MS, nowIso());
  return { token, csrf };
}

// ---------- validation ----------
const RE_LABEL = /^[A-Za-z0-9_-]{1,64}$/;
const RE_USER = /^[A-Za-z0-9_.-]{3,32}$/;

// "My Cool Link!" -> "my-cool-link" (spaces/caps/symbols auto-slugged)
function slugify(s) {
  return String(s ?? "")
    .trim()
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

function validLabel(l) {
  return RE_LABEL.test(l || "") && !RESERVED.has(l);
}
function validUrl(u) {
  if (!u || u.length > 2048) return false;
  try {
    const p = new URL(u);
    return p.protocol === "http:" || p.protocol === "https:";
  } catch {
    return false;
  }
}

// ---------- html ----------
const CSS = `
*{box-sizing:border-box}body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f7f9;color:#1a1a1a}
.wrap{max-width:900px;margin:0 auto;padding:24px}
nav{background:#111;color:#fff;padding:12px 24px;display:flex;gap:16px;align-items:center;justify-content:space-between}
nav a{color:#fff;text-decoration:none}nav a.dim{color:#bbb}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:16px;margin:16px 0}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px;border-bottom:1px solid #eee;vertical-align:top}
input,select,textarea{padding:8px 10px;border:1px solid #d1d5db;border-radius:8px;width:100%;font-size:14px}
button,.btn{background:#111;color:#fff;border:0;border-radius:8px;padding:8px 14px;cursor:pointer;font-size:14px;text-decoration:none;display:inline-block}
button.danger{background:#b91c1c}button.secondary,.btn.secondary{background:#e5e7eb;color:#111}
.row{display:flex;gap:8px;flex-wrap:wrap}.row>*{flex:1;min-width:160px}
.actions{display:flex;gap:6px}.muted{color:#666;font-size:13px}.error{background:#fee2e2;color:#991b1b;padding:10px;border-radius:8px}.ok{background:#dcfce7;color:#166534;padding:10px;border-radius:8px}
code{background:#eee;padding:2px 6px;border-radius:6px}
`;

function layout(title, body, user) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · redirector</title><style>${CSS}</style></head><body>
<nav><div><a href="/"><b>redirector</b></a>${user ? ` &nbsp;<a class="dim" href="/admin/links">links</a>${user.role === "admin" ? ` &nbsp;<a class="dim" href="/admin/users">users</a>` : ""}` : ""}</div>
<div>${user ? `<span class="dim">${esc(user.username)} (${esc(user.role)})</span> &nbsp;<a href="/admin/logout" onclick="event.preventDefault();document.getElementById('logout-form').submit()">logout</a>
<form id="logout-form" method="POST" action="/admin/logout" style="display:none"><input type="hidden" name="csrf" value="${esc(user.csrf)}"></form>`
    : `<a href="/admin/login">login</a>`}</div></nav>
<div class="wrap">${body}</div></body></html>`;
}

function loginPage(error = "") {
  return layout("login", `
<h2>Admin login</h2>
<div class="card"><form method="POST" action="/admin/login">
${error ? `<p class="error">${esc(error)}</p>` : ""}
<p><label>Username<br><input name="username" autocomplete="username" required></label></p>
<p><label>Password<br><input name="password" type="password" autocomplete="current-password" required></label></p>
<p><button type="submit">Login</button></p>
</form></div>`, null);
}

function linksPage(user, { links, editLink, error, msg, owners }) {
  const rows = links.map((l) => {
    const owner = owners.get(l.created_by) || (l.created_by == null ? "<i>deleted</i>" : l.created_by);
    return `<tr><td><code>/${esc(l.label)}</code><br><span class="muted">${esc(l.notes).slice(0, 80)}</span></td>
<td><a href="${esc(l.url)}" target="_blank" rel="noopener">${esc(l.url.slice(0, 60))}</a><br><span class="muted">${l.clicks} clicks</span></td>
<td>${owner}</td>
<td class="actions"><button type="button" class="secondary" onclick="showQR('${esc(l.label)}')">QR</button><a class="btn secondary" href="/admin/links?edit=${l.id}">edit</a>
<form method="POST" action="/admin/links/delete" onsubmit="return confirm('Delete /${esc(l.label)}?')"><input type="hidden" name="csrf" value="${esc(user.csrf)}"><input type="hidden" name="id" value="${l.id}"><button class="danger" type="submit">del</button></form></td></tr>`;
  }).join("");

  const form = editLink ? `
<h3>Edit /${esc(editLink.label)}</h3>
<form method="POST" action="/admin/links/update"><input type="hidden" name="csrf" value="${esc(user.csrf)}"><input type="hidden" name="id" value="${editLink.id}">
<div class="row"><p><label>Label (auto-slugged, e.g. My Cool Link → my-cool-link)<br><input name="label" value="${esc(editLink.label)}" required maxlength="64" oninput="document.getElementById('slug-prev').textContent=this.value.trim()?('→ /'+slugPrev(this.value)):''"></label><span class="muted" id="slug-prev"></span></p>
<p><label>URL for redirection<br><input name="url" value="${esc(editLink.url)}" required placeholder="https://..."></label></p></div>
<p><label>Notes<br><input name="notes" value="${esc(editLink.notes)}"></label></p>
<p><button type="submit">Save</button> <a class="btn secondary" href="/admin/links">cancel</a></p></form>`
    : `
<h3>New link</h3>
<form method="POST" action="/admin/links/create"><input type="hidden" name="csrf" value="${esc(user.csrf)}">
<div class="row"><p><label>Label (auto-slugged, e.g. My Cool Link → my-cool-link)<br><input name="label" required maxlength="64" placeholder="my cool link" oninput="document.getElementById('slug-prev').textContent=this.value.trim()?('→ /'+slugPrev(this.value)):''"></label><span class="muted" id="slug-prev"></span></p>
<p><label>URL for redirection<br><input name="url" required placeholder="https://example.com/..."></label></p></div>
<p><label>Notes<br><input name="notes" placeholder="optional"></label></p>
<p><button type="submit">Create</button></p></form>`;

  return layout("links", `
<h2>Links ${user.role === "admin" ? `<span class="muted">(all links)</span>` : `<span class="muted">(yours only)</span>`}</h2>
${error ? `<p class="error">${esc(error)}</p>` : ""}${msg ? `<p class="ok">${esc(msg)}</p>` : ""}
<div class="card">${form}</div>
<div class="card"><table><thead><tr><th>Label</th><th>Target</th><th>Owner</th><th></th></tr></thead><tbody>${rows || `<tr><td colspan="4" class="muted">no links yet</td></tr>`}</tbody></table></div>
<div id="qr-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);align-items:center;justify-content:center;z-index:50" onclick="if(event.target===this)closeQR()">
<div class="card" style="margin:0;text-align:center;min-width:280px"><h3 style="margin-top:0"><code id="qr-label"></code></h3>
<div id="qr-box" style="display:flex;justify-content:center;padding:8px"></div>
<p class="muted" id="qr-url" style="word-break:break-all"></p>
<p><button type="button" id="qr-dl">Download PNG</button> <button type="button" class="secondary" onclick="closeQR()">close</button></p></div></div>
<script src="/qrcode.min.js"></script>
<script>
function slugPrev(s){return s.trim().toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'').slice(0,64);}
function showQR(label){
  var full=location.origin+'/'+label;
  document.getElementById('qr-label').textContent='/'+label;
  document.getElementById('qr-url').textContent=full;
  var box=document.getElementById('qr-box');box.innerHTML='';
  try{new QRCode(box,{text:full,width:220,height:220,correctLevel:QRCode.CorrectLevel.M});}
  catch(e){box.innerHTML='<p class=error>QR lib failed to load</p>';}
  document.getElementById('qr-modal').style.display='flex';
  document.getElementById('qr-dl').onclick=function(){
    var img=box.querySelector('img'),canvas=box.querySelector('canvas'),src=null;
    if(img&&img.src)src=img.src;else if(canvas)src=canvas.toDataURL('image/png');
    if(!src)return;
    var a=document.createElement('a');a.href=src;a.download='qr-'+label+'.png';document.body.appendChild(a);a.click();a.remove();
  };
}
function closeQR(){document.getElementById('qr-modal').style.display='none';}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeQR();});
</script>`, user);
}

function usersPage(user, { users, error, msg }) {
  const rows = users.map((u) => `<tr><td>${esc(u.username)}${u.id === user.id ? ` <span class="muted">(you)</span>` : ""}</td>
<td>${esc(u.role)}</td><td class="muted">${esc(u.created_at.slice(0, 10))}</td>
<td><form method="POST" action="/admin/users/update" style="display:flex;gap:6px;align-items:center">
<input type="hidden" name="csrf" value="${esc(user.csrf)}"><input type="hidden" name="id" value="${u.id}">
<select name="role" style="width:auto"><option value="admin"${u.role === "admin" ? " selected" : ""}>admin</option><option value="user"${u.role === "user" ? " selected" : ""}>user</option></select>
<input name="password" type="password" placeholder="new password (optional)" style="width:180px">
<button type="submit">save</button>
</form></td>
<td>${u.id === user.id ? `<span class="muted">—</span>` : `<form method="POST" action="/admin/users/delete" onsubmit="return confirm('Delete user ${esc(u.username)}?')"><input type="hidden" name="csrf" value="${esc(user.csrf)}"><input type="hidden" name="id" value="${u.id}"><button class="danger" type="submit">del</button></form>`}</td></tr>`).join("");
  return layout("users", `
<h2>Users</h2>
${error ? `<p class="error">${esc(error)}</p>` : ""}${msg ? `<p class="ok">${esc(msg)}</p>` : ""}
<div class="card"><h3>New user</h3><form method="POST" action="/admin/users/create"><input type="hidden" name="csrf" value="${esc(user.csrf)}">
<div class="row"><p><label>Username<br><input name="username" required pattern="[A-Za-z0-9_.-]{3,32}"></label></p>
<p><label>Password<br><input name="password" type="password" required minlength="4"></label></p>
<p><label>Role<br><select name="role"><option value="user">user</option><option value="admin">admin</option></select></label></p></div>
<p><button type="submit">Create</button></p></form></div>
<div class="card"><table><thead><tr><th>Username</th><th>Role</th><th>Created</th><th>Edit</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`, user);
}

// ---------- responses ----------
function send(res, status, html) {
  res.writeHead(status, { "content-type": "text/html; charset=utf-8" });
  res.end(html);
}
function redir(res, to) {
  res.writeHead(302, { location: to });
  res.end();
}

// ---------- server ----------
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const path = url.pathname;
    const method = req.method;

    // health / robots
    if (path === "/healthz" && method === "GET") {
      res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); return;
    }
    if (path === "/robots.txt") {
      res.writeHead(200, { "content-type": "text/plain" }); res.end("User-agent: *\nDisallow: /admin\n"); return;
    }
    if (path === "/qrcode.min.js" && method === "GET") {
      if (!QR_JS) { res.writeHead(404); res.end("not found"); return; }
      res.writeHead(200, { "content-type": "application/javascript; charset=utf-8", "cache-control": "public, max-age=86400" });
      res.end(QR_JS); return;
    }

    // home
    if (path === "/" && method === "GET") {
      const auth = getAuth(req);
      const n = db.prepare("SELECT COUNT(*) AS c, COALESCE(SUM(clicks),0) AS s FROM links").get();
      send(res, 200, layout("home", `
<h2>redirector</h2>
<p class="muted">${n.c} links · ${n.s} total clicks</p>
<div class="card"><p>Short links look like <code>/{your-label}</code> and 302-redirect to the target URL.</p>
<p>${auth ? `<a class="btn" href="/admin/links">Manage links</a>` : `<a class="btn" href="/admin/login">Login to manage</a>`}</p></div>`,
        auth ? { ...auth.user, csrf: auth.session.csrf_token } : null));
      return;
    }

    // ---- /admin ----
    if (path === "/admin" && method === "GET") { redir(res, "/admin/links"); return; }

    if (path === "/admin/login") {
      if (method === "GET") {
        const auth = getAuth(req);
        if (auth) { redir(res, "/admin/links"); return; }
        send(res, 200, loginPage()); return;
      }
      if (method === "POST") {
        const body = new URLSearchParams(await readBody(req));
        const username = (body.get("username") || "").trim();
        const password = body.get("password") || "";
        const u = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
        if (!u || !verifyPassword(password, u.password_hash)) {
          send(res, 401, loginPage("Invalid username or password")); return;
        }
        const s = createSession(u.id);
        setSessionCookie(res, s.token);
        redir(res, "/admin/links"); return;
      }
    }

    if (path === "/admin/logout" && method === "POST") {
      const auth = getAuth(req);
      const body = new URLSearchParams(await readBody(req));
      if (!auth || body.get("csrf") !== auth.session.csrf_token) {
        res.writeHead(403); res.end("forbidden"); return;
      }
      db.prepare("DELETE FROM sessions WHERE token = ?").run(auth.session.token);
      clearSessionCookie(res);
      redir(res, "/admin/login"); return;
    }

    // all routes below require login
    const auth = getAuth(req);
    if (!auth && (path === "/admin/links" || path === "/admin/users" || path.startsWith("/admin/links/") || path.startsWith("/admin/users/"))) {
      redir(res, "/admin/login"); return;
    }
    const user = auth ? { ...auth.user, csrf: auth.session.csrf_token } : null;

    const checkCsrf = (params) => params.get("csrf") === auth.session.csrf_token;

    // ---- links ----
    if (path === "/admin/links" && method === "GET") {
      const params = url.searchParams;
      const links = user.role === "admin"
        ? db.prepare("SELECT * FROM links ORDER BY id DESC").all()
        : db.prepare("SELECT * FROM links WHERE created_by = ? ORDER BY id DESC").all(user.id);
      const owners = new Map(db.prepare("SELECT id, username FROM users").all().map((u) => [u.id, esc(u.username)]));
      let editLink = null;
      if (params.get("edit")) {
        const cand = db.prepare("SELECT * FROM links WHERE id = ?").get(params.get("edit"));
        if (cand && (user.role === "admin" || cand.created_by === user.id)) editLink = cand;
      }
      send(res, 200, linksPage(user, { links, editLink, error: params.get("error") || "", msg: params.get("msg") || "", owners }));
      return;
    }

    if (path === "/admin/links/create" && method === "POST") {
      const body = new URLSearchParams(await readBody(req));
      if (!checkCsrf(body)) { res.writeHead(403); res.end("bad csrf"); return; }
      const label = slugify(body.get("label"));
      const target = (body.get("url") || "").trim();
      const notes = (body.get("notes") || "").trim().slice(0, 500);
      if (!label) { redir(res, "/admin/links?error=" + encodeURIComponent("Label is empty after slugifying — use letters/numbers")); return; }
      if (!validLabel(label)) { redir(res, "/admin/links?error=" + encodeURIComponent(`Label "/${label}" is reserved`)); return; }
      if (!validUrl(target)) { redir(res, "/admin/links?error=" + encodeURIComponent("Invalid URL (must start with http:// or https://)")); return; }
      try {
        db.prepare("INSERT INTO links (label, url, notes, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
          .run(label, target, notes, user.id, nowIso(), nowIso());
      } catch (e) {
        redir(res, "/admin/links?error=" + encodeURIComponent("Label already taken")); return;
      }
      redir(res, "/admin/links?msg=" + encodeURIComponent(`Created /${label}`)); return;
    }

    if (path === "/admin/links/update" && method === "POST") {
      const body = new URLSearchParams(await readBody(req));
      if (!checkCsrf(body)) { res.writeHead(403); res.end("bad csrf"); return; }
      const link = db.prepare("SELECT * FROM links WHERE id = ?").get(body.get("id"));
      if (!link) { redir(res, "/admin/links?error=" + encodeURIComponent("Link not found")); return; }
      if (user.role !== "admin" && link.created_by !== user.id) { res.writeHead(403); res.end("forbidden"); return; }
      const label = slugify(body.get("label"));
      const target = (body.get("url") || "").trim();
      const notes = (body.get("notes") || "").trim().slice(0, 500);
      if (!label) { redir(res, "/admin/links?error=" + encodeURIComponent("Label is empty after slugifying — use letters/numbers")); return; }
      if (!validLabel(label)) { redir(res, "/admin/links?error=" + encodeURIComponent(`Label "/${label}" is reserved`)); return; }
      if (!validUrl(target)) { redir(res, "/admin/links?error=" + encodeURIComponent("Invalid URL")); return; }
      try {
        db.prepare("UPDATE links SET label = ?, url = ?, notes = ?, updated_at = ? WHERE id = ?")
          .run(label, target, notes, nowIso(), link.id);
      } catch {
        redir(res, "/admin/links?error=" + encodeURIComponent("Label already taken")); return;
      }
      redir(res, "/admin/links?msg=" + encodeURIComponent("Link updated")); return;
    }

    if (path === "/admin/links/delete" && method === "POST") {
      const body = new URLSearchParams(await readBody(req));
      if (!checkCsrf(body)) { res.writeHead(403); res.end("bad csrf"); return; }
      const link = db.prepare("SELECT * FROM links WHERE id = ?").get(body.get("id"));
      if (!link) { redir(res, "/admin/links"); return; }
      if (user.role !== "admin" && link.created_by !== user.id) { res.writeHead(403); res.end("forbidden"); return; }
      db.prepare("DELETE FROM links WHERE id = ?").run(link.id);
      redir(res, "/admin/links?msg=" + encodeURIComponent("Link deleted")); return;
    }

    // ---- users (admin only) ----
    const isUsersRoute = path === "/admin/users" || path.startsWith("/admin/users/");
    if (isUsersRoute) {
      if (user.role !== "admin") { res.writeHead(403); res.end("forbidden: admin only"); return; }

      if (path === "/admin/users" && method === "GET") {
        const users = db.prepare("SELECT id, username, role, created_at FROM users ORDER BY id").all();
        send(res, 200, usersPage(user, { users, error: url.searchParams.get("error") || "", msg: url.searchParams.get("msg") || "" }));
        return;
      }
      if (path === "/admin/users/create" && method === "POST") {
        const body = new URLSearchParams(await readBody(req));
        if (!checkCsrf(body)) { res.writeHead(403); res.end("bad csrf"); return; }
        const username = (body.get("username") || "").trim();
        const password = body.get("password") || "";
        const role = body.get("role") === "admin" ? "admin" : "user";
        if (!RE_USER.test(username)) { redir(res, "/admin/users?error=" + encodeURIComponent("Invalid username (3-32 chars: A-Z a-z 0-9 _ . -)")); return; }
        if (password.length < 4) { redir(res, "/admin/users?error=" + encodeURIComponent("Password min 4 chars")); return; }
        try {
          db.prepare("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)")
            .run(username, hashPassword(password), role, nowIso());
        } catch {
          redir(res, "/admin/users?error=" + encodeURIComponent("Username already taken")); return;
        }
        redir(res, "/admin/users?msg=" + encodeURIComponent(`User ${username} created`)); return;
      }
      if (path === "/admin/users/update" && method === "POST") {
        const body = new URLSearchParams(await readBody(req));
        if (!checkCsrf(body)) { res.writeHead(403); res.end("bad csrf"); return; }
        const target = db.prepare("SELECT * FROM users WHERE id = ?").get(body.get("id"));
        if (!target) { redir(res, "/admin/users?error=" + encodeURIComponent("User not found")); return; }
        const newRole = body.get("role") === "admin" ? "admin" : "user";
        const newPass = body.get("password") || "";
        // guards: no self-demote, no demoting last admin
        if (target.id === user.id && newRole !== target.role) {
          redir(res, "/admin/users?error=" + encodeURIComponent("You cannot change your own role")); return;
        }
        if (target.role === "admin" && newRole !== "admin") {
          const admins = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").get().c;
          if (admins <= 1) { redir(res, "/admin/users?error=" + encodeURIComponent("Cannot demote the last admin")); return; }
        }
        if (newPass) {
          if (newPass.length < 4) { redir(res, "/admin/users?error=" + encodeURIComponent("Password min 4 chars")); return; }
          db.prepare("UPDATE users SET role = ?, password_hash = ? WHERE id = ?").run(newRole, hashPassword(newPass), target.id);
        } else {
          db.prepare("UPDATE users SET role = ? WHERE id = ?").run(newRole, target.id);
        }
        redir(res, "/admin/users?msg=" + encodeURIComponent("User updated")); return;
      }
      if (path === "/admin/users/delete" && method === "POST") {
        const body = new URLSearchParams(await readBody(req));
        if (!checkCsrf(body)) { res.writeHead(403); res.end("bad csrf"); return; }
        const target = db.prepare("SELECT * FROM users WHERE id = ?").get(body.get("id"));
        if (!target) { redir(res, "/admin/users"); return; }
        if (target.id === user.id) { redir(res, "/admin/users?error=" + encodeURIComponent("You cannot delete yourself")); return; }
        if (target.role === "admin") {
          const admins = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").get().c;
          if (admins <= 1) { redir(res, "/admin/users?error=" + encodeURIComponent("Cannot delete the last admin")); return; }
        }
        db.prepare("DELETE FROM users WHERE id = ?").run(target.id);
        db.prepare("DELETE FROM sessions WHERE user_id = ?").run(target.id);
        redir(res, "/admin/users?msg=" + encodeURIComponent("User deleted")); return;
      }
    }

    // ---- public redirect /:label ----
    if (method === "GET") {
      const label = decodeURIComponent(path.slice(1)).split("/")[0].split("?")[0];
      if (label && !label.includes("/") && validLabel(label)) {
        const link = db.prepare("SELECT * FROM links WHERE label = ?").get(label);
        if (link) {
          db.prepare("UPDATE links SET clicks = clicks + 1 WHERE id = ?").run(link.id);
          res.writeHead(302, { location: link.url });
          res.end();
          return;
        }
      }
      res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
      res.end(layout("not found", `<h2>404</h2><p class="muted">No redirect for <code>/${esc(path.slice(1, 80))}</code></p><p><a href="/">home</a></p>`,
        auth ? { ...auth.user, csrf: auth.session.csrf_token } : null));
      return;
    }

    res.writeHead(404); res.end("not found");
  } catch (err) {
    console.error(err);
    try { res.writeHead(500); res.end("internal error"); } catch { /* noop */ }
  }
});

server.listen(PORT, () => {
  console.log(`[redirector] listening on http://localhost:${PORT} (db: ${DB_PATH})`);
});
