// server.js
// Auth server using Wasabi (S3-compatible) with a SINGLE users file:
//   users/users.json  -> { users: [ {name, mobile, dob, gender, passwordHash, createdAt} ] }
// Signup: name, mobile, dob(YYYY-MM-DD), gender, password  (age >= 18)
// Login:  mobile + password
// Routes: /signup /login /me /users

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
  HeadObjectCommand,
} = require('@aws-sdk/client-s3');

const app = express();

/* ---------- CORS (allow web + Capacitor WebView) ---------- */
app.use(cors({
  origin: '*', // tighten to your domains in production
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.options('*', cors());

/* ---------- JSON parsing ---------- */
app.use(express.json({ limit: '1mb' }));

/* ---------- ENV ---------- */
const {
  PORT = 3000,
  JWT_SECRET = 'dev-secret-change-me',
  WASABI_ACCESS_KEY_ID,
  WASABI_SECRET_ACCESS_KEY,
  WASABI_BUCKET,
  WASABI_REGION = 'ap-northeast-1',                 // Tokyo
  WASABI_ENDPOINT = 'https://s3.ap-northeast-1.wasabisys.com',
} = process.env;

if (!WASABI_ACCESS_KEY_ID || !WASABI_SECRET_ACCESS_KEY || !WASABI_BUCKET) {
  console.warn('[WARN] Missing Wasabi env vars: WASABI_ACCESS_KEY_ID, WASABI_SECRET_ACCESS_KEY, WASABI_BUCKET');
}

/* ---------- Wasabi client ---------- */
const s3 = new S3Client({
  region: WASABI_REGION,
  endpoint: WASABI_ENDPOINT,
  forcePathStyle: true,
  credentials: {
    accessKeyId: WASABI_ACCESS_KEY_ID,
    secretAccessKey: WASABI_SECRET_ACCESS_KEY,
  },
});

/* ---------- Consts & helpers ---------- */
const USERS_KEY = 'users/users.json';

function isValidMobile(m) {
  return /^\+?[0-9]{10,15}$/.test(String(m || ''));
}
function calcAgeFromDOB(dobStr) {
  const dob = new Date(dobStr);
  if (isNaN(dob.getTime())) return null;
  const t = new Date();
  let age = t.getFullYear() - dob.getFullYear();
  const mm = t.getMonth() - dob.getMonth();
  if (mm < 0 || (mm === 0 && t.getDate() < dob.getDate())) age--;
  return age;
}
async function objectExists(Key) {
  try {
    await s3.send(new HeadObjectCommand({ Bucket: WASABI_BUCKET, Key }));
    return true;
  } catch {
    return false;
  }
}
async function streamToString(stream) {
  // Node >=18: res.Body is a web stream; fallback to async iterator
  const chunks = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf-8');
}
async function getObjectText(Key) {
  const res = await s3.send(new GetObjectCommand({ Bucket: WASABI_BUCKET, Key }));
  return streamToString(res.Body);
}
async function writeJson(Key, obj) {
  const Body = Buffer.from(JSON.stringify(obj, null, 2));
  await s3.send(new PutObjectCommand({
    Bucket: WASABI_BUCKET,
    Key,
    Body,
    ContentType: 'application/json',
    ACL: 'private',
  }));
}
async function readUsers() {
  if (!(await objectExists(USERS_KEY))) return { users: [] };
  try {
    const txt = await getObjectText(USERS_KEY);
    const parsed = JSON.parse(txt || '{"users":[]}');
    if (!parsed || !Array.isArray(parsed.users)) return { users: [] };
    return parsed;
  } catch {
    return { users: [] };
  }
}
async function writeUsers(index) {
  await writeJson(USERS_KEY, index);
}

/* ---------- First-run initializer (creates users/users.json if missing) ---------- */
(async () => {
  try {
    const exists = await objectExists(USERS_KEY);
    if (!exists) {
      await writeUsers({ users: [] });
      console.log('Initialized empty users file at', USERS_KEY);
    }
  } catch (e) {
    console.warn('Init users file failed:', e.message);
  }
})();

/* ---------- Routes ---------- */
app.get('/', (_req, res) => {
  res.json({ status: 'ok', message: 'Wasabi auth (single users.json)' });
});

/* ----- SIGNUP -> update users/users.json ----- */
app.post('/signup', async (req, res) => {
  try {
    const { name, mobile, dob, gender, password } = req.body;

    if (!name || !mobile || !dob || !gender || !password) {
      return res.status(400).json({ error: 'name, mobile, dob, gender, password are required' });
    }
    if (!isValidMobile(mobile)) {
      return res.status(400).json({ error: 'Invalid mobile number format' });
    }
    const age = calcAgeFromDOB(dob);
    if (age === null) return res.status(400).json({ error: 'Invalid dob (use YYYY-MM-DD)' });
    if (age < 18) return res.status(400).json({ error: 'You must be at least 18 years old' });

    // Read-modify-write with basic retry (reduces race risk)
    const MAX_RETRIES = 5;
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      const idx = await readUsers();

      if (idx.users.some(u => u.mobile === mobile)) {
        return res.status(409).json({ error: 'Mobile already registered' });
      }

      const passwordHash = await bcrypt.hash(password, 10);
      idx.users.push({
        name: String(name).trim(),
        mobile: String(mobile).trim(),
        dob,
        gender,
        passwordHash,
        createdAt: new Date().toISOString(),
      });

      // Keep deterministic order
      idx.users.sort((a, b) => a.name.localeCompare(b.name));

      try {
        await writeUsers(idx);
        return res.status(201).json({ message: 'Signup successful' });
      } catch (e) {
        // brief backoff then retry
        await new Promise(r => setTimeout(r, 100 + attempt * 100));
        if (attempt === MAX_RETRIES) throw e;
      }
    }
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Signup failed', details: err.message });
  }
});

/* ----- LOGIN -> search users.json by mobile ----- */
app.post('/login', async (req, res) => {
  try {
    const { mobile, password } = req.body;
    if (!mobile || !password) {
      return res.status(400).json({ error: 'mobile and password are required' });
    }

    const idx = await readUsers();
    const user = idx.users.find(u => u.mobile === String(mobile).trim());
    if (!user) return res.status(404).json({ error: 'User not found' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { sub: user.mobile, name: user.name },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed', details: err.message });
  }
});

/* ----- Auth middleware ----- */
function authenticateJWT(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing token' });
  }
  try {
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid/expired token' });
  }
}

/* ----- Profile -> read user by mobile in token ----- */
app.get('/me', authenticateJWT, async (req, res) => {
  try {
    const idx = await readUsers();
    const user = idx.users.find(u => u.mobile === req.user.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { passwordHash, ...publicUser } = user;
    res.json(publicUser);
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Failed to load profile', details: err.message });
  }
});

/* ----- Users list (public projection) ----- */
app.get('/users', async (_req, res) => {
  try {
    const idx = await readUsers();
    const list = idx.users.map(({ name, mobile, gender, createdAt }) => ({
      name, mobile, gender, createdAt
    }));
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load users', details: e.message });
  }
});

/* ----- Error handler ----- */
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(400).json({ error: err.message || 'Bad Request' });
});

/* ----- Start ----- */
app.listen(PORT, () => {
  console.log(`✅ Wasabi auth running (single users.json) on http://localhost:${PORT}`);
});

