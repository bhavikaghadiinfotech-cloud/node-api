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
 * NOTE:
 * fakestoreapi.com is returning 403 from Render in your case.
 * So we add browser-like headers to avoid 403.
 *
 * If it STILL returns 403 (because of Render IP blocking), switch BASE to:
 * https://dummyjson.com
 * (kept as default fallback below)
 */

// Prefer env if you want. Otherwise use DummyJSON (more reliable on cloud hosting).
// To use Fakestore again, set FAKESTORE_BASE_URL=https://fakestoreapi.com in Render env.
const BASE = process.env.FAKESTORE_BASE_URL || "https://dummyjson.com";

// Render/hosting will provide PORT. For local, fallback can be 5001.
const PORT = Number(process.env.PORT) || 5001;

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

// Stripe: keep backend running even if STRIPE_SECRET_KEY missing
const stripe = process.env.STRIPE_SECRET_KEY
  ? new Stripe(process.env.STRIPE_SECRET_KEY)
  : null;

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

// In-memory users (demo)
const users = []; // { id, name, email, passwordHash }

/**
 * Upstream fetch helper (adds headers that often prevent 403)
 */
function upstreamGet(url) {
  return axios.get(url, {
    timeout: 20000,
    headers: {
      Accept: "application/json",
      // Browser-like UA to reduce 403 blocks
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      // These help some upstreams
      Referer: "https://fakestoreapi.com/",
      Origin: "https://fakestoreapi.com",
    },
  });
}

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
app.get("/health", (req, res) => res.status(200).send("OK"));

/**
 * AUTH
 */
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ message: "name, email, password required" });
    }

    const exists = users.find(
      (u) => u.email.toLowerCase() === String(email).toLowerCase()
    );
    if (exists) {
      return res.status(409).json({ message: "Email already registered" });
    }

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

    return res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (e) {
    console.error("Register failed:", e);
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

    return res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (e) {
    console.error("Login failed:", e);
    return res.status(500).json({ message: "Login failed" });
  }
});

app.get("/api/auth/me", authMiddleware, (req, res) => {
  return res.json({ user: req.user });
});

/**
 * PRODUCTS
 * Works with:
 * - Fakestore: returns an array
 * - DummyJSON: returns { products: [...] }
 */
app.get("/api/products", async (req, res) => {
  const url = `${BASE}/products`;

  try {
    const { data } = await upstreamGet(url);

    // DummyJSON returns { products: [...] }, Fakestore returns array
    const list = Array.isArray(data) ? data : data?.products || data;

    return res.json(list);
  } catch (err) {
    console.error("UPSTREAM /products FAILED", {
      url,
      message: err.message,
      code: err.code,
      status: err.response?.status,
      responseData: err.response?.data,
    });

    return res.status(502).json({
      message: "Upstream API failed",
      upstream: url,
      error: err.message,
      code: err.code,
      upstreamStatus: err.response?.status || null,
    });
  }
});

app.get("/api/products/:id", async (req, res) => {
  const url = `${BASE}/products/${req.params.id}`;

  try {
    const { data } = await upstreamGet(url);

    // DummyJSON returns product object, Fakestore returns product object
    return res.json(data);
  } catch (err) {
    console.error("UPSTREAM /products/:id FAILED", {
      url,
      message: err.message,
      code: err.code,
      status: err.response?.status,
      responseData: err.response?.data,
    });

    return res.status(502).json({
      message: "Upstream API failed",
      upstream: url,
      error: err.message,
      code: err.code,
      upstreamStatus: err.response?.status || null,
    });
  }
});

/**
 * STRIPE CHECKOUT (requires login)
 */
app.post("/api/checkout/create-session", authMiddleware, async (req, res) => {
  try {
    if (!stripe) {
      return res.status(500).json({
        message: "Stripe key missing. Add STRIPE_SECRET_KEY in environment.",
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
    console.error("Stripe session creation failed:", err);
    return res.status(500).json({ message: "Stripe session creation failed" });
  }
});

// START SERVER (only once)
const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend running on port ${PORT}`);
  console.log("BASE:", BASE);
});

server.on("error", (err) => {
  console.error("Server failed to start:", err);
  process.exit(1);
});
