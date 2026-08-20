import express from "express";
import helmet from "helmet";
import Database from "better-sqlite3";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const db = new Database(path.join(__dirname, "..", "zulli.sqlite"));

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  admin_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT,
  address TEXT,
  interest TEXT NOT NULL,
  message TEXT,
  status TEXT NOT NULL DEFAULT 'New',
  admin_note TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const hash = value =>
  crypto.createHash("sha256").update(value).digest("hex");

if (!db.prepare("SELECT id FROM admins LIMIT 1").get()) {
  db.prepare(
    "INSERT INTO admins(username,password_hash) VALUES(?,?)"
  ).run("admin", hash("ZulliAdmin123!"));
}

app.use(helmet());
app.use(express.json({ limit: "100kb" }));

app.use(
  "/customer",
  express.static(path.join(__dirname, "..", "customer"))
);

app.use(
  "/admin",
  express.static(path.join(__dirname, "..", "admin"))
);

function auth(req, res, next) {
  const token = (req.headers.authorization || "")
    .replace(/^Bearer\s+/i, "");

  const session = db
    .prepare("SELECT * FROM sessions WHERE token=?")
    .get(token);

  if (!session || session.expires_at < Date.now()) {
    return res.status(401).json({
      error: "Session expired. Please log in again."
    });
  }

  next();
}

app.post("/api/admin/login", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  const admin = db
    .prepare("SELECT * FROM admins WHERE username=?")
    .get(username);

  if (!admin || hash(password) !== admin.password_hash) {
    return res.status(401).json({
      error: "Incorrect username or password."
    });
  }

  const token = crypto.randomBytes(32).toString("hex");

  db.prepare(
    "INSERT INTO sessions VALUES(?,?,?)"
  ).run(token, admin.id, Date.now() + 86400000);

  res.json({
    ok: true,
    token
  });
});

app.post("/api/admin/logout", auth, (req, res) => {
  const token = (req.headers.authorization || "")
    .replace(/^Bearer\s+/i, "");

  db.prepare("DELETE FROM sessions WHERE token=?").run(token);

  res.json({ ok: true });
});

app.post("/api/submissions", (req, res) => {
  const value = key => String(req.body[key] || "").trim();

  const name = value("fullName");
  const phone = value("phone");
  const email = value("email");
  const address = value("address");
  const interest = value("interest");
  const message = value("message");

  if (name.length < 2 || phone.length < 7 || interest.length < 2) {
    return res.status(400).json({
      error: "Please fill the required fields."
    });
  }

  const result = db.prepare(`
    INSERT INTO submissions
    (full_name,phone,email,address,interest,message)
    VALUES(?,?,?,?,?,?)
  `).run(
    name,
    phone,
    email || null,
    address || null,
    interest,
    message || null
  );

  res.status(201).json({
    ok: true,
    id: result.lastInsertRowid
  });
});

app.get("/api/admin/submissions", auth, (req, res) => {
  const q = String(req.query.q || "").trim();
  const status = String(req.query.status || "").trim();

  let sql = "SELECT * FROM submissions WHERE 1=1";
  const params = [];

  if (q) {
    sql += `
      AND (
        full_name LIKE ?
        OR phone LIKE ?
        OR email LIKE ?
        OR interest LIKE ?
      )
    `;

    const search = `%${q}%`;
    params.push(search, search, search, search);
  }

  if (["New", "Contacted", "Completed"].includes(status)) {
    sql += " AND status=?";
    params.push(status);
  }

  sql += " ORDER BY id DESC";

  res.json(db.prepare(sql).all(...params));
});

app.get("/api/admin/stats", auth, (req, res) => {
  res.json({
    total: db
      .prepare("SELECT COUNT(*) n FROM submissions")
      .get().n,

    newCount: db
      .prepare("SELECT COUNT(*) n FROM submissions WHERE status='New'")
      .get().n,

    contacted: db
      .prepare("SELECT COUNT(*) n FROM submissions WHERE status='Contacted'")
      .get().n,

    completed: db
      .prepare("SELECT COUNT(*) n FROM submissions WHERE status='Completed'")
      .get().n
  });
});

app.patch("/api/admin/submissions/:id", auth, (req, res) => {
  const status = String(req.body.status || "");
  const note = String(req.body.note || "").slice(0, 2000);

  if (!["New", "Contacted", "Completed"].includes(status)) {
    return res.status(400).json({
      error: "Invalid status"
    });
  }

  const result = db.prepare(`
    UPDATE submissions
    SET status=?, admin_note=?
    WHERE id=?
  `).run(status, note, req.params.id);

  if (!result.changes) {
    return res.status(404).json({
      error: "Not found"
    });
  }

  res.json({ ok: true });
});

app.delete("/api/admin/submissions/:id", auth, (req, res) => {
  const result = db
    .prepare("DELETE FROM submissions WHERE id=?")
    .run(req.params.id);

  if (!result.changes) {
    return res.status(404).json({
      error: "Not found"
    });
  }

  res.json({ ok: true });
});

app.get("/api/admin/export", auth, (req, res) => {
  const rows = db
    .prepare("SELECT * FROM submissions ORDER BY id DESC")
    .all();

  const keys = [
    "id",
    "full_name",
    "phone",
    "email",
    "address",
    "interest",
    "message",
    "status",
    "admin_note",
    "created_at"
  ];

  const csv = [
    keys,
    ...rows.map(row =>
      keys.map(key =>
        String(row[key] ?? "").replace(/"/g, '""')
      )
    )
  ]
    .map(row => row.map(value => `"${value}"`).join(","))
    .join("\n");

  res.setHeader("Content-Type", "text/csv");
  res.setHeader(
    "Content-Disposition",
    'attachment; filename="zulli-customers.csv"'
  );

  res.send(csv);
});

app.get("/", (req, res) => {
  res.redirect("/customer/");
});

app.get("/admin", (req, res) => {
  res.redirect("/admin/");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(
    `ZULLI running on port ${PORT}`
  );
});
