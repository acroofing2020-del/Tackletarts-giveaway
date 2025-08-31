
const path = require("path");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const Stripe = require("stripe");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 10000;

// Trust proxy for secure cookies on Render/https
app.set("trust proxy", 1);

// ---- Stripe ----
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;

// ---- DB ----
const db = new sqlite3.Database(path.join(__dirname, "tackletarts.db"));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    address TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS competitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    status TEXT DEFAULT 'open',
    max_tickets INTEGER,
    price REAL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    competition_id INTEGER,
    ticket_number INTEGER,
    instant_win INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(competition_id) REFERENCES competitions(id)
  )`);

  db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_ticket_unique
          ON tickets (competition_id, ticket_number)`);

  db.run(`CREATE TABLE IF NOT EXISTS competition_instant_numbers (
    competition_id INTEGER,
    ticket_number INTEGER,
    PRIMARY KEY (competition_id, ticket_number),
    FOREIGN KEY(competition_id) REFERENCES competitions(id)
  )`);
});

// ---- Static ----
app.use(express.static(path.join(__dirname, "public")));

// ---- SESSION (must be before JSON for routes using req.session) ----
app.use(
  session({
    secret: process.env.SESSION_SECRET || "tackletarts_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: "auto",
      sameSite: "lax"
    }
  })
);

// ---- WEBHOOK (raw body) must be BEFORE express.json() ----
app.post("/webhook", express.raw({ type: "application/json" }), (req, res) => {
  if (!STRIPE_WEBHOOK_SECRET) {
    console.warn("Webhook called but STRIPE_WEBHOOK_SECRET is not set");
    return res.status(400).send("Webhook misconfigured");
  }

  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("Webhook signature verification failed.", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const sess = event.data.object;
    const user_id = parseInt(sess.metadata.user_id, 10);
    const competition_id = parseInt(sess.metadata.competition_id, 10);
    const quantity = parseInt(sess.metadata.quantity, 10);

    assignTickets(user_id, competition_id, quantity, (err, results) => {
      if (err) console.error("Ticket assignment failed:", err);
      else console.log("Tickets assigned:", results.length);
    });
  }

  res.json({ received: true });
});

// ---- JSON parser (after webhook) ----
app.use(express.json());

// ---- Helpers ----
function ensureAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
  next();
}

function ensureAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Admins only" });
  }
  next();
}

function randomInt(min, max) {
  // secure-ish random between min & max inclusive
  const range = max - min + 1;
  const rand = crypto.randomInt(0, range);
  return min + rand;
}

function assignTickets(userId, compId, qty, cb) {
  db.get("SELECT max_tickets FROM competitions WHERE id=? AND status='open'", [compId], (err, comp) => {
    if (err || !comp) return cb(err || new Error("Competition not found or closed"));

    const maxTickets = comp.max_tickets;

    db.all("SELECT ticket_number FROM tickets WHERE competition_id=?", [compId], (err2, rows) => {
      if (err2) return cb(err2);

      const used = new Set(rows.map(r => r.ticket_number));
      const toInsert = [];

      let attempts = 0;
      while (toInsert.length < qty) {
        if (attempts > qty * 1000) return cb(new Error("Could not find enough free ticket numbers"));
        const n = randomInt(1, maxTickets);
        if (!used.has(n)) {
          used.add(n);
          toInsert.push(n);
        }
        attempts++;
      }

      // Check which are instant wins
      db.all(
        "SELECT ticket_number FROM competition_instant_numbers WHERE competition_id=? AND ticket_number IN (" +
          toInsert.map(() => "?").join(",") +
        ")",
        [compId, ...toInsert],
        (err3, instRows) => {
          if (err3) return cb(err3);

          const instSet = new Set(instRows.map(r => r.ticket_number));

          db.serialize(() => {
            db.run("BEGIN TRANSACTION");
            const stmt = db.prepare(
              "INSERT INTO tickets (user_id, competition_id, ticket_number, instant_win) VALUES (?, ?, ?, ?)"
            );
            for (const num of toInsert) {
              stmt.run(userId, compId, num, instSet.has(num) ? 1 : 0);
            }
            stmt.finalize(err4 => {
              if (err4) {
                db.run("ROLLBACK");
                return cb(err4);
              }
              db.run("COMMIT");
              cb(null, toInsert.map(n => ({ ticket_number: n, instant_win: instSet.has(n) ? 1 : 0 })));
            });
          });
        }
      );
    });
  });
}

function generateInstantNumbers(compId, maxTickets, count, cb) {
  const set = new Set();
  while (set.size < count) {
    set.add(randomInt(1, maxTickets));
  }
  const nums = Array.from(set);

  db.serialize(() => {
    db.run("BEGIN TRANSACTION");
    const stmt = db.prepare(
      "INSERT OR IGNORE INTO competition_instant_numbers (competition_id, ticket_number) VALUES (?, ?)"
    );
    for (const n of nums) stmt.run(compId, n);
    stmt.finalize(err => {
      if (err) {
        db.run("ROLLBACK");
        return cb(err);
      }
      db.run("COMMIT");
      cb(null, nums);
    });
  });
}

function ensureAdminAtBoot() {
  const email = process.env.ADMIN_EMAIL;
  const pass = process.env.ADMIN_PASSWORD;
  if (!email || !pass) {
    console.warn("ADMIN_EMAIL/ADMIN_PASSWORD not set. No admin seeded.");
    return;
  }
  db.get("SELECT id FROM users WHERE email=?", [email], (err, user) => {
    if (err) return console.error("Admin check error:", err);
    if (user) {
      db.run("UPDATE users SET role='admin' WHERE id=?", [user.id]);
      console.log("Admin ensured:", email);
      return;
    }
    const hashed = bcrypt.hashSync(pass, 10);
    db.run(
      "INSERT INTO users (email, password, role, address) VALUES (?, ?, 'admin', '')",
      [email, hashed],
      function (err2) {
        if (err2) console.error("Admin seed error:", err2);
        else console.log("Admin created:", email);
      }
    );
  });
}
ensureAdminAtBoot();

// ---- AUTH ----
app.post("/api/signup", (req, res) => {
  const { email, password, address } = req.body;
  if (!email || !password || !address) return res.status(400).json({ error: "Missing fields" });

  const hashed = bcrypt.hashSync(password, 10);
  db.run(
    "INSERT INTO users (email, password, role, address) VALUES (?, ?, 'user', ?)",
    [email, hashed, address],
    function (err) {
      if (err) return res.status(400).json({ error: "Email already in use" });
      req.session.user = { id: this.lastID, email, role: "user" };
      res.json({ success: true });
    }
  );
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  db.get("SELECT * FROM users WHERE email=?", [email], (err, user) => {
    if (err || !user) return res.status(400).json({ error: "Invalid credentials" });
    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: "Invalid credentials" });
    req.session.user = { id: user.id, email: user.email, role: user.role };
    res.json({ success: true, role: user.role });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

// ---- COMPETITIONS ----
app.post("/api/admin/competitions", ensureAdmin, (req, res) => {
  const { title, max_tickets, price } = req.body;
  const maxTickets = parseInt(max_tickets || 200000, 10);
  const p = parseFloat(price || 0.25);
  if (!title || maxTickets < 1 || p <= 0) return res.status(400).json({ error: "Invalid inputs" });

  db.run(
    "INSERT INTO competitions (title, max_tickets, price) VALUES (?, ?, ?)",
    [title, maxTickets, p],
    function (err) {
      if (err) return res.status(500).json({ error: "Failed to create competition" });
      const id = this.lastID;
      const count = parseInt(process.env.INSTANT_WIN_COUNT || "100", 10);
      generateInstantNumbers(id, maxTickets, count, (e) => {
        if (e) console.error("Instant wins generation failed:", e);
        res.json({ success: true, id });
      });
    }
  );
});

app.post("/api/admin/competitions/:id/close", ensureAdmin, (req, res) => {
  db.run("UPDATE competitions SET status='closed' WHERE id=?", [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: "Close failed" });
    res.json({ success: true });
  });
});

app.get("/api/competitions", (req, res) => {
  db.all("SELECT * FROM competitions WHERE status='open' ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ error: "Failed to load competitions" });
    res.json(rows);
  });
});

// ---- USER TICKETS / DASHBOARD ----
app.get("/api/me/tickets", ensureAuth, (req, res) => {
  db.all(
    `SELECT t.id, t.ticket_number, t.instant_win, t.created_at,
            c.title AS competition_title, c.id AS competition_id
     FROM tickets t
     JOIN competitions c ON c.id = t.competition_id
     WHERE t.user_id=?
     ORDER BY t.created_at DESC`,
    [req.session.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Failed to load tickets" });
      res.json(rows);
    }
  );
});

// ---- STRIPE CHECKOUT ----
app.post("/api/checkout", ensureAuth, (req, res) => {
  const { competition_id, quantity } = req.body;
  const qty = Math.max(1, parseInt(quantity || 1, 10));

  db.get("SELECT * FROM competitions WHERE id=? AND status='open'", [competition_id], async (err, comp) => {
    if (err || !comp) return res.status(404).json({ error: "Competition not found or closed" });

    try {
      const sess = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        mode: "payment",
        line_items: [
          {
            price_data: {
              currency: "gbp",
              product_data: { name: comp.title },
              unit_amount: Math.round(comp.price * 100) // pence
            },
            quantity: qty
          }
        ],
        metadata: {
          user_id: String(req.session.user.id),
          competition_id: String(competition_id),
          quantity: String(qty)
        },
        success_url: process.env.BASE_URL + "/success.html",
        cancel_url: process.env.BASE_URL + "/cancel.html"
      });

      res.json({ url: sess.url });
    } catch (e) {
      console.error("Stripe error", e);
      res.status(500).json({ error: "Stripe error" });
    }
  });
});

// ---- FALLBACKS ----
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});
// Serve competitions page with Stripe key injected
const fs = require("fs");
app.get("/competitions.html", (req, res) => {
  let html = fs.readFileSync("./public/competitions.html", "utf8");
  html = html.replace("{{STRIPE_PUBLISHABLE_KEY}}", process.env.STRIPE_PUBLISHABLE_KEY);
  res.send(html);
});
// ---- START ----
app.listen(PORT, () => {
  console.log(`🎣 TackleTarts running on port ${PORT}`);
});
