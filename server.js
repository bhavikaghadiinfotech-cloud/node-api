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

/**
 * AUTO-SWITCH PRODUCT API
 * - Local → FakeStore
 * - Render → DummyJSON (FakeStore blocks Render IPs with 403)
 */
const isRender = !!process.env.RENDER;

const BASE =
  process.env.FAKESTORE_BASE_URL ||
  (isRender ? "https://dummyjson.com" : "https://fakestoreapi.com");

// Render provides PORT automatically
const PORT = Number(process.env.PORT) || 5001;

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

// Stripe (optional)
const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

// In-memory users (demo only)
const users = [];

/**
 * Axios helper with browser-like headers
 */
function upstreamGet(url) {
  return axios.get(url, {
    timeout: 20000,
    headers: {
      Accept: "application/json",
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
    },
  });
}

/**
 * AUTH MIDDLEWARE
 */
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) return res.status(401).json({ message: "No token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

/**
 * HEALTH
 */
app.get("/health", (req, res) => res.send("OK"));

/**
 * AUTH
 */
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ message: "Missing fields" });
    }

    if (users.find((u) => u.email === email)) {
      return res.status(409).json({ message: "Email exists" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = { id: Date.now().toString(), name, email, passwordHash };
    users.push(user);

    const token = jwt.sign(user, JWT_SECRET, { expiresIn: "2h" });

    res.json({ token, user: { id: user.id, name, email } });
  } catch (e) {
    res.status(500).json({ message: "Register failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = users.find((u) => u.email === email);
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(user, JWT_SECRET, { expiresIn: "2h" });

    res.json({ token, user: { id: user.id, name: user.name, email } });
  } catch {
    res.status(500).json({ message: "Login failed" });
  }
});

app.get("/api/auth/me", authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

/**
 * PRODUCTS
 * Works for FakeStore + DummyJSON
 */
app.get("/api/products", async (req, res) => {
  try {
    const { data } = await upstreamGet(`${BASE}/products`);
    res.json(Array.isArray(data) ? data : data.products);
  } catch (err) {
    res.status(502).json({
      message: "Upstream API failed",
      upstream: `${BASE}/products`,
      error: err.message,
      status: err.response?.status,
    });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const { data } = await upstreamGet(`${BASE}/products/${req.params.id}`);
    res.json(data);
  } catch (err) {
    res.status(502).json({
      message: "Upstream API failed",
      upstream: `${BASE}/products/${req.params.id}`,
      error: err.message,
      status: err.response?.status,
    });
  }
});

/**
 * STRIPE CHECKOUT
 */
app.post("/api/checkout/create-session", authMiddleware, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(500).json({ message: "Stripe not configured" });
    }

    const { cartItems } = req.body || [];
    if (!cartItems.length) {
      return res.status(400).json({ message: "Cart empty" });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      line_items: cartItems.map((item) => ({
        quantity: item.qty || 1,
        price_data: {
          currency: "usd",
          unit_amount: Math.round(item.price * 100),
          product_data: { name: item.title },
        },
      })),
      success_url: `${FRONTEND_URL}/success`,
      cancel_url: `${FRONTEND_URL}/cart`,
    });

    res.json({ url: session.url });
  } catch {
    res.status(500).json({ message: "Stripe failed" });
  }
});

/**
 * START SERVER (ONLY ONCE)
 */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend running on port ${PORT}`);
  console.log("Using API:", BASE);
});
