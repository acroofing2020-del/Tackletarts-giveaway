// server.js
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const bodyParser = require("body-parser");
const cors = require("cors");

// ====== CONFIG ======
const PORT = process.env.PORT || 10000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const stripeSecret = process.env.STRIPE_SECRET_KEY || "sk_test_xxx";
const stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET || "";
const stripe = require("stripe")(stripeSecret);

const app = express();
app.use(cors());
app.use(express.static(path.join(__dirname, "public")));

// IMPORTANT: Stripe webhook needs raw body BEFORE JSON parser
app.post("/webhook", express.raw({ type: "application/json" }), (req, res) => {
  if (!stripeWebhookSecret) return res.status(200).json({ received: true }); // dev fallback
  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, stripeWebhookSecret);
  } catch (err) {
    console.error("Webhook signature verification failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const { userId, competitionId, quantity } = session.metadata || {};
    const qty = parseInt(quantity || "0", 10);
    if (userId && competitionId && qty > 0) {
      allocateTickets(Number(userId), Number(competitionId), qty, session);
    }
  }
  res.json({ received: true });
});

app.use(bodyParser.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
  })
);

// ====== DB ======
const db = new sqlite3.Database("./database.sqlite", (err) => {
  if (err) console.error("DB error:", err);
  else console.log("✅ SQLite connected");
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      password TEXT,
      name TEXT,
      address TEXT,
      credit_cents INTEGER DEFAULT 0,
      is_admin INTEGER DEFAULT 0
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS competitions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      description TEXT,
      image_url TEXT,
      total_tickets INTEGER DEFAULT 200000,
      price_pence INTEGER DEFAULT 25,
      status TEXT DEFAULT 'open',
      instant_win_count INTEGER DEFAULT 100,
      instant_win_numbers TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      competition_id INTEGER,
      ticket_number INTEGER,
      is_instant_win INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE (competition_id, ticket_number)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      competition_id INTEGER,
      quantity INTEGER,
      amount_pence INTEGER,
      stripe_session_id TEXT,
      stripe_payment_intent TEXT,
      status TEXT DEFAULT 'created',
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // Seed admin from env
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
    db.run(
      `INSERT OR IGNORE INTO users (email, password, is_admin) VALUES (?, ?, 1)`,
      [ADMIN_EMAIL, hash]
    );
  }
});

// ====== HELPERS ======
function loggedIn(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  next();
}
function adminOnly(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  db.get(`SELECT is_admin FROM users WHERE id=?`, [req.session.userId], (e, r) => {
    if (e || !r || r.is_admin !== 1) return res.status(403).json({ error: "Admin only" });
    next();
  });
}
function sampleInstantWinNumbers(total, count) {
  count = Math.max(0, Math.min(count, total));
  const set = new Set();
  while (set.size < count) set.add(1 + Math.floor(Math.random() * total));
  return Array.from(set);
}
function allocateTickets(userId, competitionId, qty, stripeSession) {
  db.get(`SELECT * FROM competitions WHERE id=?`, [competitionId], (err, comp) => {
    if (err || !comp) return console.error("Webhook: comp not found");
    const instantSet = new Set(
      (comp.instant_win_numbers || "")
        .split(",")
        .map((x) => parseInt(x, 10))
        .filter((n) => !isNaN(n))
    );

    let assigned = 0;
    const assignOne = () => {
      if (assigned >= qty) {
        db.run(
          `UPDATE orders SET status='paid', stripe_payment_intent=? WHERE stripe_session_id=?`,
          [stripeSession.payment_intent || "", stripeSession.id]
        );
        return;
      }
      const n = 1 + Math.floor(Math.random() * comp.total_tickets);
      db.run(
        `INSERT INTO tickets (user_id, competition_id, ticket_number, is_instant_win)
         VALUES (?, ?, ?, ?)`,
        [userId, competitionId, n, instantSet.has(n) ? 1 : 0],
        function (e) {
          if (e) return assignOne(); // try another number (likely duplicate)
          if (instantSet.has(n)) {
            db.run(`UPDATE users SET credit_cents = credit_cents + 20 WHERE id=?`, [userId]);
          }
          assigned++;
          assignOne();
        }
      );
    };
    assignOne();
  });
}

// ====== AUTH ======
app.post("/api/signup", (req, res) => {
  const { email, password, name, address } = req.body;
  if (!email || !password || !address) {
    return res.status(400).json({ error: "Email, password, and address are required" });
  }
  const hash = bcrypt.hashSync(password, 10);
  db.run(
    `INSERT INTO users (email, password, name, address) VALUES (?, ?, ?, ?)`,
    [email, hash, name || "", address],
    function (err) {
      if (err) return res.status(400).json({ error: "Email already registered" });
      req.session.userId = this.lastID;
      res.json({ success: true });
    }
  );
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email=?`, [email], (err, u) => {
    if (err || !u) return res.status(400).json({ error: "Invalid login" });
    if (!bcrypt.compareSync(password, u.password)) return res.status(400).json({ error: "Invalid login" });
    req.session.userId = u.id;
    res.json({ success: true });
  });
});

app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ success: true })));

app.get("/api/me", (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  db.get(
    `SELECT id,email,name,address,credit_cents,is_admin FROM users WHERE id=?`,
    [req.session.userId],
    (e, u) => res.json({ user: u || null })
  );
});

// ====== COMPETITIONS ======
app.get("/api/competitions", (req, res) => {
  db.all(`SELECT * FROM competitions WHERE status='open'`, (e, rows) => {
    if (e) return res.status(500).json({ error: "Failed to load competitions" });
    res.json(rows);
  });
});

app.post("/api/admin/competitions", adminOnly, (req, res) => {
  const {
    title,
    description,
    image_url,
    total_tickets = 200000,
    price_pence = 25,
    instant_win_count = 100 // set 80 if you want exactly 0.04%
  } = req.body;
  const wins = sampleInstantWinNumbers(total_tickets, instant_win_count).join(",");
  db.run(
    `INSERT INTO competitions
     (title, description, image_url, total_tickets, price_pence, status, instant_win_count, instant_win_numbers)
     VALUES (?, ?, ?, ?, ?, 'open', ?, ?)`,
    [title, description || "", image_url || "", total_tickets, price_pence, instant_win_count, wins],
    function (err) {
      if (err) return res.status(500).json({ error: "Failed to create competition" });
      res.json({ success: true, id: this.lastID });
    }
  );
});

app.post("/api/admin/competitions/:id/close", adminOnly, (req, res) => {
  db.run(`UPDATE competitions SET status='closed' WHERE id=?`, [req.params.id], function (e) {
    if (e) return res.status(500).json({ error: "Failed to close competition" });
    res.json({ success: true });
  });
});

// ====== CHECKOUT ======
app.post("/api/checkout", loggedIn, (req, res) => {
  const { competitionId, quantity } = req.body;
  if (!competitionId || !quantity || quantity < 1) {
    return res.status(400).json({ error: "competitionId and quantity required" });
  }
  db.get(`SELECT * FROM competitions WHERE id=? AND status='open'`, [competitionId], async (e, c) => {
    if (e || !c) return res.status(400).json({ error: "Competition not found or closed" });

    try {
      const origin = req.headers["x-forwarded-proto"]
        ? `${req.headers["x-forwarded-proto"]}://${req.get("host")}`
        : `${req.protocol}://${req.get("host")}`;

      const session = await stripe.checkout.sessions.create({
        mode: "payment",
        payment_method_types: ["card"],
        line_items: [
          {
            price_data: {
              currency: "gbp",
              product_data: { name: c.title || `Competition #${c.id}` },
              unit_amount: c.price_pence
            },
            quantity
          }
        ],
        success_url: `${origin}/success.html`,
        cancel_url: `${origin}/cancel.html`,
        metadata: {
          userId: String(req.session.userId),
          competitionId: String(c.id),
          quantity: String(quantity)
        }
      });

      db.run(
        `INSERT INTO orders (user_id, competition_id, quantity, amount_pence, stripe_session_id, status)
         VALUES (?, ?, ?, ?, ?, 'created')`,
        [req.session.userId, c.id, quantity, c.price_pence * quantity, session.id]
      );

      res.json({ url: session.url });
    } catch (err) {
      console.error("Stripe error:", err);
      res.status(500).json({ error: "Stripe failed" });
    }
  });
});

// ====== USER DASHBOARD DATA ======
app.get("/api/my-overview", loggedIn, (req, res) => {
  const userId = req.session.userId;
  db.get(`SELECT credit_cents, email, name, address FROM users WHERE id=?`, [userId], (e, user) => {
    if (e || !user) return res.status(500).json({ error: "User not found" });

    db.all(
      `SELECT t.ticket_number, t.is_instant_win, t.created_at, c.title
       FROM tickets t JOIN competitions c ON c.id=t.competition_id
       WHERE t.user_id = ?
       ORDER BY t.created_at DESC LIMIT 500`,
      [userId],
      (e2, tickets) => {
        if (e2) return res.status(500).json({ error: "Failed to load tickets" });
        db.all(
          `SELECT o.id, o.quantity, o.amount_pence, o.status, o.created_at, c.title
           FROM orders o JOIN competitions c ON c.id=o.competition_id
           WHERE o.user_id=? ORDER BY o.created_at DESC LIMIT 200`,
          [userId],
          (e3, orders) => {
            if (e3) return res.status(500).json({ error: "Failed to load orders" });
            res.json({
              account: {
                email: user.email,
                name: user.name,
                address: user.address,
                credit_cents: user.credit_cents
              },
              tickets,
              orders,
              instantWins: tickets.filter(t => t.is_instant_win === 1).length
            });
          }
        );
      }
    );
  });
});

// ====== STATIC ROUTES ======
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/success", (req, res) => res.sendFile(path.join(__dirname, "public", "success.html")));
app.get("/cancel", (req, res) => res.sendFile(path.join(__dirname, "public", "cancel.html")));

// ====== START ======
app.listen(PORT, () => {
  console.log(`🎣 TackleTart Giveaways running on port ${PORT}`);
  console.warn("Warning: MemoryStore sessions are not for production scale.");
});
