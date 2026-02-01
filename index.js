"use strict";

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();

// -------------------- MIDDLEWARE --------------------
app.use(
  cors({
    origin: true, // laat alle origins toe (ok voor demo); later beperken tot stempeler.com
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.options("*", cors());
app.use(express.json({ limit: "256kb" }));

// -------------------- CONFIG --------------------
const STAMP_CAP = 10; // max 10 stempels
const EURO_PER_STAMP = 10; // 10€ = 1 stempel
const MAX_AMOUNT_CENTS = 50000; // demo: max 500€
const RATE_MAX_PER_MIN = 20;

// -------------------- STORES --------------------
const STORES = [
  { id: "s1", name: "Shop A" },
  { id: "s2", name: "Shop B" },
];

// -------------------- USERS (PER STORE) --------------------
// username is alleen uniek binnen dezelfde store
const USERS = [
  // Shop A
  { id: "u1", storeId: "s1", username: "staff1", password: "1234", role: "staff" },
  { id: "u2", storeId: "s1", username: "manager1", password: "1234", role: "manager" },

  // Shop B
  { id: "u3", storeId: "s2", username: "staff1", password: "1234", role: "staff" },
  { id: "u4", storeId: "s2", username: "manager1", password: "1234", role: "manager" },
];

// -------------------- IN-MEMORY STATE (DEMO) --------------------
// token -> session
const TOKENS = new Map();

// storeId -> Map(walletId -> { stamps })
const ledgerByStore = new Map();

// storeId -> audit entries array
const auditByStore = new Map();

// `${storeId}:${userId}` -> { startMs, count }
const rateByKey = new Map();

// -------------------- HELPERS --------------------
function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

function nowIso() {
  return new Date().toISOString();
}

function getStore(storeId) {
  return STORES.find((s) => s.id === storeId) || null;
}

function getStoreLedger(storeId) {
  if (!ledgerByStore.has(storeId)) ledgerByStore.set(storeId, new Map());
  return ledgerByStore.get(storeId);
}

function getStoreAudit(storeId) {
  if (!auditByStore.has(storeId)) auditByStore.set(storeId, []);
  return auditByStore.get(storeId);
}

function calcStampsFromAmountCents(amountCents) {
  const euros = amountCents / 100;
  return Math.floor(euros / EURO_PER_STAMP);
}

function allowRate(storeId, userId) {
  const key = `${storeId}:${userId}`;
  const now = Date.now();
  const windowMs = 60 * 1000;

  let bucket = rateByKey.get(key);
  if (!bucket || now - bucket.startMs > windowMs) {
    bucket = { startMs: now, count: 0 };
  }

  bucket.count += 1;
  rateByKey.set(key, bucket);

  return bucket.count <= RATE_MAX_PER_MIN;
}

// -------------------- AUTH MIDDLEWARE --------------------
function auth(req, res, next) {
  const header = req.headers["authorization"] || "";
  const [kind, token] = header.split(" ");

  if (kind !== "Bearer" || !token) {
    return res.status(401).json({ error: "Missing Bearer token" });
  }

  const session = TOKENS.get(token);
  if (!session) return res.status(401).json({ error: "Invalid token" });

  req.user = session;
  req.token = token;
  next();
}

function requireManager(req, res, next) {
  if (req.user.role !== "manager") {
    return res.status(403).json({ error: "Manager only" });
  }
  next();
}

// -------------------- ROUTES --------------------
app.get("/", (req, res) => {
  res.send("Backend OK ✅");
});

// --- Stores list (public) ---
app.get("/stores", (req, res) => {
  res.json({ stores: STORES });
});

// --- Store-first login (public) ---
app.post("/auth/login", (req, res) => {
  const { storeId, username, password } = req.body || {};

  if (!storeId || !username || !password) {
    return res.status(400).json({ error: "storeId/username/password required" });
  }

  const store = getStore(storeId);
  if (!store) return res.status(400).json({ error: "Unknown storeId" });

  const user = USERS.find(
    (u) => u.storeId === storeId && u.username === username && u.password === password
  );
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const token = createToken();
  const session = {
    userId: user.id,
    storeId: user.storeId,
    username: user.username,
    role: user.role,
    createdAt: Date.now(),
  };

  TOKENS.set(token, session);

  res.json({
    token,
    store: { id: store.id, name: store.name },
    user: { id: user.id, username: user.username, role: user.role },
  });
});

// --- Logout (protected) ---
app.post("/auth/logout", auth, (req, res) => {
  TOKENS.delete(req.token);
  res.json({ ok: true });
});

// --- Me (protected) ---
app.get("/me", auth, (req, res) => {
  const store = getStore(req.user.storeId);
  res.json({ user: req.user, store });
});

// --- Public ledger for customer (requires storeId query) ---
app.get("/ledger/:walletId", (req, res) => {
  const { walletId } = req.params;
  const storeId = req.query.storeId;

  if (!walletId || typeof walletId !== "string") {
    return res.status(400).json({ error: "walletId required" });
  }
  if (!storeId || typeof storeId !== "string") {
    return res.status(400).json({ error: "storeId query required" });
  }

  const store = getStore(storeId);
  if (!store) return res.status(400).json({ error: "Unknown storeId" });

  const storeLedger = getStoreLedger(storeId);
  const entry = storeLedger.get(walletId) || { stamps: 0 };

  res.json({
    walletId,
    storeId,
    stamps: entry.stamps,
    stampCap: STAMP_CAP,
  });
});

// --- Earn stamps (protected) ---
// storeId komt uit token (dus staff kan niet cross-store)
app.post("/earn", auth, (req, res) => {
  const { walletId, amountCents } = req.body || {};
  if (!walletId || typeof walletId !== "string") {
    return res.status(400).json({ error: "walletId missing" });
  }
  if (typeof amountCents !== "number" || Number.isNaN(amountCents)) {
    return res.status(400).json({ error: "amountCents must be a number" });
  }

  const storeId = req.user.storeId;

  // Basic validation / fraud demo
  if (amountCents <= 0) return res.status(400).json({ error: "amount must be > 0" });
  if (amountCents > MAX_AMOUNT_CENTS) return res.status(400).json({ error: "amount too high (demo)" });

  // Rate limit per staff per store
  if (!allowRate(storeId, req.user.userId)) {
    return res.status(429).json({ error: "Rate limit exceeded" });
  }

  const stampsAdded = calcStampsFromAmountCents(amountCents);
  const storeLedger = getStoreLedger(storeId);

  const current = storeLedger.get(walletId) || { stamps: 0 };
  const next = Math.min(STAMP_CAP, Math.max(0, current.stamps + stampsAdded));
  storeLedger.set(walletId, { stamps: next });

  const entry = {
    id: crypto.randomBytes(8).toString("hex"),
    ts: nowIso(),
    type: "EARN",
    storeId,
    walletId,
    amountCents,
    stampsAdded,
    stampsAfter: next,
    staff: {
      userId: req.user.userId,
      username: req.user.username,
      role: req.user.role,
    },
  };

  const storeAudit = getStoreAudit(storeId);
  storeAudit.unshift(entry);
  if (storeAudit.length > 200) storeAudit.length = 200;

  res.json({
    ok: true,
    ...entry,
    stampCap: STAMP_CAP,
  });
});

// --- Audit (manager only, own store only) ---
app.get("/audit", auth, requireManager, (req, res) => {
  const storeId = req.user.storeId;
  res.json({ storeId, items: getStoreAudit(storeId) });
});

// --- Reset wallet (manager only, own store only) ---
app.post("/wallet/reset", auth, requireManager, (req, res) => {
  const { walletId } = req.body || {};
  if (!walletId || typeof walletId !== "string") {
    return res.status(400).json({ error: "walletId missing" });
  }

  const storeId = req.user.storeId;
  const storeLedger = getStoreLedger(storeId);
  storeLedger.set(walletId, { stamps: 0 });

  const entry = {
    id: crypto.randomBytes(8).toString("hex"),
    ts: nowIso(),
    type: "RESET",
    storeId,
    walletId,
    by: { userId: req.user.userId, username: req.user.username, role: req.user.role },
  };

  const storeAudit = getStoreAudit(storeId);
  storeAudit.unshift(entry);
  if (storeAudit.length > 200) storeAudit.length = 200;

  res.json({ ok: true, storeId, walletId, stamps: 0, stampCap: STAMP_CAP });
});

// -------------------- START (Cloud Run compatible) --------------------
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log("Backend running on port", PORT);
});
