// v3 – minimal, with logging + auto-seed + Stripe checkout
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const Stripe = require("stripe");
const fs = require("fs");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 10000;
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// --- DB ---
const db = new sqlite3.Database("./tackletarts.db");
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    address TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS competitions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    status TEXT DEFAULT 'open',
    max_tickets INTEGER,
    price REAL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS tickets(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    competition_id INTEGER,
    ticket_number INTEGER,
    instant_win INTEGER DEFAULT 0
  )`);
});

// --- Middleware (order matters!) ---
app.set("trust proxy", 1);
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "tackletarts_secret",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: "auto" }
  })
);
app.use(express.static("public"));

// --- Helpers ---
const ensureAuth = (req, res, next) => {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
  next();
};
const ensureAdmin = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Admins only" });
  }
  next();
};

// --- Seed one open competition if none ---
function seedCompetitionIfNone() {
  db.get("SELECT COUNT(*) AS c FROM competitions WHERE status='open'", (err, row) => {
    if (err) return console.error("Seed check error:", err);
    if (row.c === 0) {
      db.run(
        "INSERT INTO competitions(title, status, max_tickets, price) VALUES(?,?,?,?)",
        ["Daily Draw (seeded)", "open", 200000, 0.25],
        function (e) {
          if (e) console.error("Seed insert error:", e);
          else console.log("✅ Seeded competition id:", this.lastID);
        }
      );
    }
  });
}
seedCompetitionIfNone();

// --- Routes ---
app.get("/api/health", (req, res) => res.json({ ok: true, time: new Date().toISOString() }));
app.get("/api/me", (req, res) => res.json({ user: req.session.user || null }));

app.post("/api/signup", (req, res) => {
  const { email, password, address } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email & password required" });
  const hashed = bcrypt.hashSync(password, 10);
  db.run(
    "INSERT INTO users(email, password, address) VALUES(?,?,?)",
    [email, hashed, address || ""],
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
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(400).json({ error: "Invalid credentials" });
    }
    req.session.user = { id: user.id, email: user.email, role: user.role };
    res.json({ success: true, role: user.role });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.post("/api/admin/competition", ensureAdmin, (req, res) => {
  const { title, max_tickets, price } = req.body;
  db.run(
    "INSERT INTO competitions(title,status,max_tickets,price) VALUES(?,?,?,?)",
    [title, "open", max_tickets, price],
    function (err) {
      if (err) return res.status(500).json({ error: "Failed to create competition" });
      res.json({ success: true, id: this.lastID });
    }
  );
});

app.get("/api/competitions", (req, res) => {
  db.all("SELECT * FROM competitions WHERE status='open'", (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows);
  });
});

// Stripe Checkout
app.post("/api/checkout", ensureAuth, (req, res) => {
  const { competition_id, quantity } = req.body;
  console.log("POST /api/checkout", { user: req.session.user, competition_id, quantity });

  if (!process.env.STRIPE_SECRET_KEY) {
    return res.status(500).json({ error: "Stripe secret key missing" });
  }
  db.get("SELECT * FROM competitions WHERE id=?", [competition_id], async (err, comp) => {
    if (err || !comp) return res.status(404).json({ error: "Competition not found" });
    try {
      const checkout = await stripe.checkout.sessions.create({
        mode: "payment",
        payment_method_types: ["card"],
        line_items: [
          {
            price_data: {
              currency: "gbp",
              product_data: { name: comp.title },
              unit_amount: Math.round(comp.price * 100)
            },
            quantity: Math.max(1, parseInt(quantity || 1, 10))
          }
        ],
        success_url: `${process.env.BASE_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.BASE_URL}/cancel.html`
      });
      return res.json({ url: checkout.url });
    } catch (e) {
      console.error("Stripe error:", e);
      return res.status(500).json({ error: "Stripe error creating checkout" });
    }
  });
});

// (Optional) dynamic injection if you ever need to pass keys into HTML
app.get("/competitions.html", (req, res) => {
  let html = fs.readFileSync("./public/competitions.html", "utf8");
  // Not strictly needed by this client, but helpful if you log it:
  html = html.replace("{{STRIPE_PUBLISHABLE_KEY}}", process.env.STRIPE_PUBLISHABLE_KEY || "");
  res.type("html").send(html);
});

// --- Start ---
app.listen(PORT, () => {
  console.log(`🎣 TackleTarts v3 running on port ${PORT}`);
});
