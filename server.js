const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const Stripe = require("stripe");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 10000;
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// Database setup
const db = new sqlite3.Database("./tackletarts.db");

// Create tables if not exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    address TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    competition_id INTEGER,
    ticket_number INTEGER,
    instant_win INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS competitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    status TEXT DEFAULT 'open',
    max_tickets INTEGER,
    price REAL
  )`);
});

// Middleware
app.use(bodyParser.json());
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "tackletarts_secret",
    resave: false,
    saveUninitialized: false,
  })
);

// ✅ Middleware: Check if logged in
function ensureAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Not logged in" });
  }
  next();
}

// ✅ Middleware: Check if admin
function ensureAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Forbidden: Admins only" });
  }
  next();
}

// ======================= ROUTES =======================

// Signup
app.post("/api/signup", (req, res) => {
  const { email, password, address } = req.body;
  const hashed = bcrypt.hashSync(password, 10);

  db.run(
    "INSERT INTO users (email, password, address) VALUES (?, ?, ?)",
    [email, hashed, address],
    function (err) {
      if (err) {
        return res.status(400).json({ error: "Email already in use" });
      }
      req.session.user = { id: this.lastID, email, role: "user" };
      res.json({ success: true });
    }
  );
});

// Login
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(400).json({ error: "Invalid credentials" });
    }
    req.session.user = { id: user.id, email: user.email, role: user.role };
    res.json({ success: true, role: user.role });
  });
});

// Logout
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// Admin: Create competition
app.post("/api/admin/competition", ensureAdmin, (req, res) => {
  const { title, max_tickets, price } = req.body;
  db.run(
    "INSERT INTO competitions (title, max_tickets, price) VALUES (?, ?, ?)",
    [title, max_tickets, price],
    function (err) {
      if (err) return res.status(500).json({ error: "Failed to create competition" });
      res.json({ success: true, id: this.lastID });
    }
  );
});

// Get competitions
app.get("/api/competitions", (req, res) => {
  db.all("SELECT * FROM competitions WHERE status='open'", (err, rows) => {
    res.json(rows);
  });
});

// Stripe checkout
app.post("/api/checkout", ensureAuth, async (req, res) => {
  const { competition_id, quantity } = req.body;

  db.get("SELECT * FROM competitions WHERE id = ?", [competition_id], async (err, comp) => {
    if (!comp) return res.status(404).json({ error: "Competition not found" });

    try {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        mode: "payment",
        line_items: [
          {
            price_data: {
              currency: "gbp",
              product_data: {
                name: comp.title,
              },
              unit_amount: comp.price * 100, // Stripe uses pence
            },
            quantity,
          },
        ],
        success_url: process.env.BASE_URL + "/success.html",
        cancel_url: process.env.BASE_URL + "/cancel.html",
      });

      res.json({ url: session.url });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Stripe error" });
    }
  });
});

// ✅ Start server
app.listen(PORT, () => {
  console.log(`🎣 TackleTarts running on port ${PORT}`);
});
