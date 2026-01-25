const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.options(/.*/, cors());
app.use(express.json());

// -------------------- STORES --------------------
const STORES = [
  { id: "s1", name: "Shop A" },
  { id: "s2", name: "Shop B" },
];

// -------------------- USERS (PER STORE) --------------------
// username is alleen uniek binnen store
const USERS = [
  // Shop A
  { id: "u1", storeId: "s1", username: "staff1", password: "1234", role: "staff" },
  { id: "u2", storeId: "s1", username: "manager1", password: "1234", role: "manager" },

  // Shop B
  { id: "u3", storeId: "s2", username: "staff1", password: "1234", role: "staff" },
  { id: "u4", storeId: "s2", username: "manager1", password: "1234", role: "manager" },
];

// -------------------- SESSIONS --------------------
const TOKENS = new Map(); // token -> session
function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

function auth(req, res, next) {
  const header = req.headers["authorization"] || "";
  const [kind, token] = header.split(" ");
  if (kind !== "Bearer" || !token) return res.status(401).json({ error: "Missing Bearer token" });

  const session = TOKENS.get(token);
  if (!session) return res.status(401).json({ error: "Invalid token" });

  req.user = session;
  req.token = token;
  next();
}

function requireManager(req, res, next) {
  if (req.user.role !== "manager") return res.status(403).json({ error: "Manager only" });
  next();
}

// -------------------- LEDGER + AUDIT (PER STORE) --------------------
const ledgerByStore = new Map(); // storeId -> Map(walletId -> { stamps })
const auditByStore = new Map();  // storeId -> array

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
  return Math.floor(euros / 10); // 10€ = 1 stempel
}

// -------------------- RATE LIMIT (BASIC) --------------------
const RATE_MAX_PER_MIN = 20;
const rate = new Map(); // `${storeId}:${userId}` -> { startMs, count }

function allowRate(storeId, userId) {
  const key = `${storeId}:${userId}`;
  const now = Date.now();
  const minute = 60 * 1000;

  let w = rate.get(key);
  if (!w || now - w.startMs > minute) w = { startMs: now, count: 0 };
  w.count += 1;
  rate.set(key, w);

  return w.count <= RATE_MAX_PER_MIN;
}

// -------------------- ROUTES --------------------
app.get("/", (req, res) => res.send("Backend OK ✅"));

app.get("/stores", (req, res) => {
  res.json({ stores: STORES });
});

// Store-first login
app.post("/auth/login", (req, res) => {
  const { storeId, username, password } = req.body || {};
  if (!storeId || !username || !password) {
    return res.status(400).json({ error: "storeId/username/password required" });
  }

  const store = STORES.find((s) => s.id === storeId);
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

app.post("/auth/logout", auth, (req, res) => {
  TOKENS.delete(req.token);
  res.json({ ok: true });
});

app.get("/me", auth, (req, res) => {
  const store = STORES.find((s) => s.id === req.user.storeId);
  res.json({ user: req.user, store });
});

// Public ledger (customer) — vereist storeId
app.get("/ledger/:walletId", (req, res) => {
  const { walletId } = req.params;
  const storeId = req.query.storeId;
  if (!storeId || typeof storeId !== "string") {
    return res.status(400).json({ error: "storeId query required" });
  }

  const storeLedger = getStoreLedger(storeId);
  const entry = storeLedger.get(walletId) || { stamps: 0 };

  res.json({ walletId, storeId, stamps: entry.stamps, stampCap: 10 });
});

// Earn (protected) — storeId komt uit token (niet uit body!)
app.post("/earn", auth, (req, res) => {
  const { walletId, amountCents } = req.body || {};
  if (!walletId || typeof walletId !== "string") return res.status(400).json({ error: "walletId missing" });
  if (typeof amountCents !== "number") return res.status(400).json({ error: "amountCents must be number" });

  const storeId = req.user.storeId;

  // basic fraud/rate
  if (amountCents <= 0) return res.status(400).json({ error: "amount must be > 0" });
  if (amountCents > 50000) return res.status(400).json({ error: "amount too high (demo)" });
  if (!allowRate(storeId, req.user.userId)) return res.status(429).json({ error: "Rate limit exceeded" });

  const stampsAdded = calcStampsFromAmountCents(amountCents);
  const storeLedger = getStoreLedger(storeId);

  const current = storeLedger.get(walletId) || { stamps: 0 };
  const next = Math.min(10, Math.max(0, current.stamps + stampsAdded));
  storeLedger.set(walletId, { stamps: next });

  const entry = {
    id: crypto.randomBytes(8).toString("hex"),
    ts: new Date().toISOString(),
    storeId,
    walletId,
    amountCents,
    stampsAdded,
    stampsAfter: next,
    staff: { userId: req.user.userId, username: req.user.username, role: req.user.role },
  };

  const storeAudit = getStoreAudit(storeId);
  storeAudit.unshift(entry);
  if (storeAudit.length > 200) storeAudit.length = 200;

  res.json({ ok: true, ...entry, stampCap: 10 });
});

// Audit (manager only) — alleen eigen store
app.get("/audit", auth, requireManager, (req, res) => {
  const storeId = req.user.storeId;
  res.json({ storeId, items: getStoreAudit(storeId) });
});

// Reset (manager only) — alleen eigen store
app.post("/wallet/reset", auth, requireManager, (req, res) => {
  const { walletId } = req.body || {};
  if (!walletId || typeof walletId !== "string") return res.status(400).json({ error: "walletId missing" });

  const storeId = req.user.storeId;
  const storeLedger = getStoreLedger(storeId);
  storeLedger.set(walletId, { stamps: 0 });

  const entry = {
    id: crypto.randomBytes(8).toString("hex"),
    ts: new Date().toISOString(),
    type: "RESET",
    storeId,
    walletId,
    by: { userId: req.user.userId, username: req.user.username },
  };
  const storeAudit = getStoreAudit(storeId);
  storeAudit.unshift(entry);

  res.json({ ok: true, storeId, walletId, stamps: 0 });
});

app.listen(3000, () => console.log("Backend running on http://localhost:3000"));

const port = process.env.PORT || 8080;
app.listen(port, () => console.log("Running on", port));
