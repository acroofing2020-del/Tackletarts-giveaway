// server.js (FULL)
// Environment vars required in Render:
// STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, SESSION_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD, BASE_URL (e.g. https://yourapp.onrender.com)

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const Stripe = require("stripe");

const app = express();
const PORT = process.env.PORT || 10000;

// --- Stripe ---
if (!process.env.STRIPE_SECRET_KEY || !process.env.STRIPE_PUBLISHABLE_KEY) {
  console.warn("⚠️ Set STRIPE_SECRET_KEY and STRIPE_PUBLISHABLE_KEY in your environment.");
}
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || "sk_test_dummy");

// --- DB ---
const db = new sqlite3.Database("./tackletarts.db");

// Create tables
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      full_name TEXT,
      address1 TEXT,
      address2 TEXT,
      city TEXT,
      postcode TEXT,
      country TEXT,
      role TEXT DEFAULT 'user'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS purchases(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      quantity INTEGER NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

// Seed/ensure admin from env
async function ensureAdmin() {
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPass = process.env.ADMIN_PASSWORD;
  if (!adminEmail || !adminPass) {
    console.warn("⚠️ Set ADMIN_EMAIL and ADMIN_PASSWORD env vars to auto-create admin.");
    return;
  }
  db.get("SELECT id FROM users WHERE email = ?", [adminEmail], async (err, row) => {
    if (err) return console.error("Admin check error:", err);
    if (row) return; // exists
    const hash = await bcrypt.hash(adminPass, 10);
    db.run(
      `INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, 'admin')`,
      [adminEmail, hash, "Site Admin"],
      (e) => {
        if (e) console.error("Admin create error:", e);
        else console.log("✅ Admin user created from env ADMIN_EMAIL");
      }
    );
  });
}
ensureAdmin();

// --- Middleware ---
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production", // Render is HTTPS -> true in prod
      sameSite: "lax"
    }
  })
);
app.use(express.static(path.join(__dirname, "public")));

// --- Helpers ---
function ensureLoggedIn(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
  next();
}
function ensureAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Admins only" });
  }
  next();
}

// --- Auth API ---
app.post("/api/signup", async (req, res) => {
  const {
    email, password, fullName,
    address1, address2, city, postcode, country
  } = req.body;

  if (!email || !password) return res.status(400).json({ error: "Email and password required" });

  try {
    const hash = await bcrypt.hash(password, 10);
    db.run(
      `INSERT INTO users (email, password, full_name, address1, address2, city, postcode, country, role)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'user')`,
      [email, hash, fullName || "", address1 || "", address2 || "", city || "", postcode || "", country || ""],
      function (err) {
        if (err) {
          if (String(err).includes("UNIQUE")) {
            return res.status(400).json({ error: "Email already registered" });
          }
          return res.status(500).json({ error: "Database error" });
        }
        req.session.user = { id: this.lastID, email, role: "user" };
        res.json({ ok: true, role: "user" });
      }
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Signup failed" });
  }
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) return res.status(500).json({ error: "Database error" });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Invalid credentials" });

    req.session.user = { id: user.id, email: user.email, role: user.role };
    res.json({ ok: true, role: user.role });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

// --- Config endpoint (expose publishable key to frontend) ---
app.get("/api/config", (req, res) => {
  res.json({
    publishableKey: process.env.STRIPE_PUBLISHABLE_KEY || "pk_test_dummy",
    baseUrl: process.env.BASE_URL || ""
  });
});

// --- Stripe Checkout ---
app.post("/api/create-checkout-session", ensureLoggedIn, async (req, res) => {
  try {
    const quantity = Math.max(1, Math.min(200000, parseInt(req.body.quantity || "1", 10)));

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "gbp",
            product_data: { name: "TackleTarts Ticket(s)" },
            unit_amount: 25 // 25 pence
          },
          quantity
        }
      ],
      success_url: `${process.env.BASE_URL}/success.html`,
      cancel_url: `${process.env.BASE_URL}/cancel.html`,
      metadata: {
        userId: String(req.session.user.id),
        quantity: String(quantity)
      }
    });

    res.json({ id: session.id });
  } catch (e) {
    console.error("Stripe error:", e);
    res.status(500).json({ error: "Stripe checkout failed" });
  }
});

// (Optional) Webhook skeleton – uncomment after adding STRIPE_WEBHOOK_SECRET and endpoint in Stripe
// const bodyParser = require("body-parser");
// app.post("/webhook", bodyParser.raw({ type: "application/json" }), (req, res) => {
//   const sig = req.headers["stripe-signature"];
//   let event;
//   try {
//     event = Stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
//   } catch (err) {
//     console.error("Webhook signature error:", err.message);
//     return res.status(400).send(`Webhook Error: ${err.message}`);
//   }
//   // Handle events (checkout.session.completed etc.)
//   res.json({ received: true });
// });

// --- Page routes ---
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "public/index.html")));
app.get("/dashboard", ensureLoggedIn, (req, res) => {
  if (req.session.user.role === "admin") {
    return res.redirect("/admin.html");
  }
  res.sendFile(path.join(__dirname, "public/dashboard.html"));
});
app.get("/admin", ensureAdmin, (_req, res) => {
  res.sendFile(path.join(__dirname, "public/admin.html"));
});

app.listen(PORT, () => {
  console.log(`🎣 TackleTarts running on port ${PORT}`);
});
