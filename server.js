const express = require("express");
const cors = require("cors");
const axios = require("axios");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const Stripe = require("stripe");

const app = express();
app.use(cors());
app.use(express.json());

const BASE = process.env.FAKESTORE_BASE_URL || "https://fakestoreapi.com";
// const PORT = Number(process.env.PORT || 5001);
const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on", PORT);
});
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

// Stripe: keep backend running even if STRIPE_SECRET_KEY missing
const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

// In-memory users (demo)
const users = []; // { id, name, email, passwordHash }

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (e) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// Health
app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "backend", time: new Date().toISOString() });
});

// AUTH
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ message: "name, email, password required" });
    }

    const exists = users.find(
      (u) => u.email.toLowerCase() === String(email).toLowerCase()
    );
    if (exists) return res.status(409).json({ message: "Email already registered" });

    const passwordHash = await bcrypt.hash(password, 10);

    const user = {
      id: String(Date.now()),
      name,
      email,
      passwordHash,
    };
    users.push(user);

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    return res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (e) {
    return res.status(500).json({ message: "Register failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: "email, password required" });
    }

    const user = users.find(
      (u) => u.email.toLowerCase() === String(email).toLowerCase()
    );
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    return res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (e) {
    return res.status(500).json({ message: "Login failed" });
  }
});

app.get("/api/auth/me", authMiddleware, (req, res) => {
  return res.json({ user: req.user });
});

// PRODUCTS (proxy fakestore)
app.get("/api/products", async (req, res) => {
  try {
    const { data } = await axios.get(`${BASE}/products`);
    return res.json(data);
  } catch (err) {
    return res.status(500).json({ message: "Failed to fetch products" });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const { data } = await axios.get(`${BASE}/products/${req.params.id}`);
    return res.json(data);
  } catch (err) {
    return res.status(500).json({ message: "Failed to fetch product" });
  }
});

// STRIPE CHECKOUT (requires login)
app.post("/api/checkout/create-session", authMiddleware, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(500).json({
        message: "Stripe key missing. Add STRIPE_SECRET_KEY in backend/.env",
      });
    }

    const { cartItems } = req.body || {};
    if (!Array.isArray(cartItems) || cartItems.length === 0) {
      return res.status(400).json({ message: "Cart is empty" });
    }

    const line_items = cartItems.map((item) => ({
      quantity: Math.max(1, Number(item.qty || 1)),
      price_data: {
        currency: "usd",
        product_data: {
          name: String(item.title || "Product"),
          images: item.image ? [String(item.image)] : [],
        },
        unit_amount: Math.round(Number(item.price || 0) * 100),
      },
    }));

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items,
      success_url: `${FRONTEND_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_URL}/cart`,
    });

    return res.json({ url: session.url });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Stripe session creation failed" });
  }
});

// IMPORTANT: keep this at bottom
app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});
