// server.js
// Auth server using Wasabi (S3-compatible) with a SINGLE users file:
//   users/users.json  -> { users: [ {name, mobile, dob, gender, passwordHash, createdAt} ] }
// Signup: name, mobile, dob(YYYY-MM-DD), gender, password  (age >= 18)
// Login:  mobile + password
// Routes: /signup /login /me /users

require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
  HeadObjectCommand,
} = require('@aws-sdk/client-s3');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*', methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'Authorization'] }));

// ====== ENV ======
const {
  PORT = 3000,
  JWT_SECRET = 'dev-secret-change-me',
  WASABI_ACCESS_KEY_ID,
  WASABI_SECRET_ACCESS_KEY,
  WASABI_BUCKET,
  WASABI_REGION = 'ap-northeast-1',
  WASABI_ENDPOINT = 'https://s3.ap-northeast-1.wasabisys.com',
} = process.env;

if (!WASABI_ACCESS_KEY_ID || !WASABI_SECRET_ACCESS_KEY || !WASABI_BUCKET) {
  console.warn('[WARN] Missing Wasabi env vars');
}

// ====== Wasabi client ======
const s3 = new S3Client({
  region: WASABI_REGION,
  endpoint: WASABI_ENDPOINT,
  forcePathStyle: true,
  credentials: {
    accessKeyId: WASABI_ACCESS_KEY_ID,
    secretAccessKey: WASABI_SECRET_ACCESS_KEY,
  },
});

// ====== Helpers ======
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
async function getObjectText(Key) {
  const res = await s3.send(new GetObjectCommand({ Bucket: WASABI_BUCKET, Key }));
  const chunks = [];
  for await (const c of res.Body) chunks.push(c);
  return Buffer.concat(chunks).toString('utf-8');
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
  const Body = Buffer.from(JSON.stringify(index, null, 2));
  await s3.send(
    new PutObjectCommand({
      Bucket: WASABI_BUCKET,
      Key: USERS_KEY,
      Body,
      ContentType: 'application/json',
      ACL: 'private',
    })
  );
}

// ====== Routes ======
app.get('/', (_req, res) => {
  res.json({ status: 'ok', message: 'Wasabi auth (single users.json)' });
});

// SIGNUP -> update users/users.json
app.post('/signup', async (req, res) => {
  try {
    const { name, mobile, dob, gender, password } = req.body;

    if (!name || !mobile || !dob || !gender || !password)
      return res.status(400).json({ error: 'name, mobile, dob, gender, password are required' });
    if (!isValidMobile(mobile))
      return res.status(400).json({ error: 'Invalid mobile number format' });

    const age = calcAgeFromDOB(dob);
    if (age === null) return res.status(400).json({ error: 'Invalid dob (use YYYY-MM-DD)' });
    if (age < 18) return res.status(400).json({ error: 'You must be at least 18 years old' });

    const idx = await readUsers();
    if (idx.users.some((u) => u.mobile === mobile))
      return res.status(409).json({ error: 'Mobile already registered' });

    const passwordHash = await bcrypt.hash(password, 10);
    idx.users.push({
      name,
      mobile,
      dob,
      gender,
      passwordHash,
      createdAt: new Date().toISOString(),
    });

    idx.users.sort((a, b) => a.name.localeCompare(b.name));

    await writeUsers(idx);
    res.status(201).json({ message: 'Signup successful' });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Signup failed', details: err.message });
  }
});

// LOGIN -> search users.json by mobile
app.post('/login', async (req, res) => {
  try {
    const { mobile, password } = req.body;
    if (!mobile || !password)
      return res.status(400).json({ error: 'mobile and password are required' });

    const idx = await readUsers();
    const user = idx.users.find((u) => u.mobile === mobile);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ sub: user.mobile, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed', details: err.message });
  }
});

// Auth middleware
function authenticateJWT(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer '))
    return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid/expired token' });
  }
}

// Profile -> read user from users.json by mobile in token
app.get('/me', authenticateJWT, async (req, res) => {
  try {
    const idx = await readUsers();
    const user = idx.users.find((u) => u.mobile === req.user.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { passwordHash, ...publicUser } = user;
    res.json(publicUser);
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Failed to load profile', details: err.message });
  }
});

// Users list (public view)
app.get('/users', async (_req, res) => {
  try {
    const idx = await readUsers();
    const list = idx.users.map(({ name, mobile, gender, createdAt }) => ({
      name,
      mobile,
      gender,
      createdAt,
    }));
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load users', details: e.message });
  }
});

// ---- Safe fallback for all unknown routes ----
app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.originalUrl}` });
});

// ---- Error handler ----
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(400).json({ error: err.message || 'Bad Request' });
});

// ---- Start ----
app.listen(PORT, () => {
  console.log(`✅ Wasabi auth running (single users.json) on http://localhost:${PORT}`);
});