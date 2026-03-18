require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const fetch   = require('node-fetch');
const users   = require('./users');

const app = express();
app.use(express.json());
app.use(cors());

// ─── הגדרות ────────────────────────────────────────
const PRIORITY_BASE = process.env.PRIORITY_BASE_URL;
const PRIORITY_USER = process.env.PRIORITY_USER;
const PRIORITY_PASS = process.env.PRIORITY_PASS;
const JWT_SECRET    = process.env.JWT_SECRET || 'fallback-secret-change-me';
const PORT          = process.env.PORT || 3000;

// כותרת Authorization לפריורטי (Basic Auth)
const priorityAuth = 'Basic ' + Buffer.from(`${PRIORITY_USER}:${PRIORITY_PASS}`).toString('base64');

// ─── Middleware: אימות טוקן ────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'לא מורשה' });
  }
  try {
    const token = header.slice(7);
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'טוקן לא תקף' });
  }
}

// ─── עזר: קריאה לפריורטי ──────────────────────────
async function priorityGet(path) {
  const url = `${PRIORITY_BASE}/${path}`;
  const res = await fetch(url, {
    headers: {
      'Authorization': priorityAuth,
      'Content-Type':  'application/json'
    }
  });
  if (!res.ok) throw new Error(`Priority error: ${res.status}`);
  return res.json();
}

async function priorityPost(path, body) {
  const url = `${PRIORITY_BASE}/${path}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': priorityAuth,
      'Content-Type':  'application/json'
    },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(`Priority error: ${res.status}`);
  return res.json();
}

async function priorityPatch(path, body) {
  const url = `${PRIORITY_BASE}/${path}`;
  const res = await fetch(url, {
    method: 'PATCH',
    headers: {
      'Authorization': priorityAuth,
      'Content-Type':  'application/json'
    },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(`Priority error: ${res.status}`);
  return res.json();
}

// ════════════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════════════

// POST /api/login — כניסה למערכת
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'יש למלא שם משתמש וסיסמה' });
  }

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ error: 'שם משתמש או סיסמה שגויים' });
  }

  // תומך גם בטקסט רגיל וגם ב-bcrypt
  let valid = false;
  if (user.password.startsWith('$2')) {
    valid = await bcrypt.compare(password, user.password);
  } else {
    valid = (password === user.password);
  }
  if (!valid) {
    return res.status(401).json({ error: 'שם משתמש או סיסמה שגויים' });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, display: user.display, role: user.role },
    JWT_SECRET,
    { expiresIn: '12h' }
  );

  res.json({ token, display: user.display, role: user.role });
});

// GET /api/me — בדיקת טוקן
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ════════════════════════════════════════════════════
// VEHICLE ROUTES — כרטיס רכב (SERNUMBERS)
// ════════════════════════════════════════════════════

// GET /api/vehicle/:regnum — חיפוש רכב לפי מספר
app.get('/api/vehicle/:regnum', requireAuth, async (req, res) => {
  try {
    const regnum = req.params.regnum;
    // שליפת כרטיס רכב מ-SERNUMBERS
    const data = await priorityGet(
      `SERNUMBERS?$filter=SERNUM eq '${regnum}'&$select=SERNUM,PARTNAME,PARTDES,SERDES,STATUSDESC`
    );
    if (!data.value || data.value.length === 0) {
      return res.status(404).json({ error: 'רכב לא נמצא' });
    }
    res.json(data.value[0]);
  } catch (err) {
    console.error('vehicle error:', err.message);
    res.status(500).json({ error: 'שגיאה בשליפת נתוני רכב' });
  }
});

// ════════════════════════════════════════════════════
// PARTS ROUTES — חלקים לפירוק (QAMF_SERNMECLOL)
// ════════════════════════════════════════════════════

// GET /api/parts/:regnum — רשימת חלקים לפי מספר רכב
app.get('/api/parts/:regnum', requireAuth, async (req, res) => {
  try {
    const regnum = req.params.regnum;
    const data = await priorityGet(
      `QAMF_SERNMECLOL?$filter=SERNUM eq '${regnum}'&$select=SERNUM,PARTNAME,PARTDES,MECLOL,DISMANTLED`
    );
    res.json(data.value || []);
  } catch (err) {
    console.error('parts error:', err.message);
    res.status(500).json({ error: 'שגיאה בשליפת חלקים' });
  }
});

// POST /api/parts/dismantle — סימון חלקים לפירוק ובניית מק"ט
app.post('/api/parts/dismantle', requireAuth, async (req, res) => {
  try {
    const { regnum, parts } = req.body;
    // parts = [{ partname, meclol }, ...]
    // שליחה לפריורטי — פריורטי בונה מק"ט לפי קוד מכלול + מספר רכב
    const results = [];
    for (const part of parts) {
      const result = await priorityPost('QAMF_SERNMECLOL', {
        SERNUM:     regnum,
        PARTNAME:   part.partname,
        MECLOL:     part.meclol,
        DISMANTLED: 'Y'
      });
      results.push(result);
    }
    res.json({ success: true, results });
  } catch (err) {
    console.error('dismantle error:', err.message);
    res.status(500).json({ error: 'שגיאה בסימון פירוק' });
  }
});

// PATCH /api/parts/undo — ביטול פירוק חלק
app.patch('/api/parts/undo', requireAuth, async (req, res) => {
  try {
    const { regnum, partname } = req.body;
    const result = await priorityPatch(
      `QAMF_SERNMECLOL(SERNUM='${regnum}',PARTNAME='${partname}')`,
      { DISMANTLED: '' }
    );
    res.json({ success: true, result });
  } catch (err) {
    console.error('undo error:', err.message);
    res.status(500).json({ error: 'שגיאה בביטול פירוק' });
  }
});

// ════════════════════════════════════════════════════
// ORDERS ROUTES — הזמנות לקוח (ORDERS)
// ════════════════════════════════════════════════════

// GET /api/orders — שליפת הזמנות עם סטטוס "לפירוק"
app.get('/api/orders', requireAuth, async (req, res) => {
  try {
    const data = await priorityGet(
      `ORDERS?$filter=QAMF_STATUS ne 'פורק'&$select=ORDNAME,CDES,CURDATE,QAMF_STATUS&$expand=ORDERITEMS($select=PARTNAME,PARTDES,TQUANT)`
    );
    res.json(data.value || []);
  } catch (err) {
    console.error('orders error:', err.message);
    res.status(500).json({ error: 'שגיאה בשליפת הזמנות' });
  }
});

// PATCH /api/orders/:ordname/status — עדכון סטטוס הזמנה
app.patch('/api/orders/:ordname/status', requireAuth, async (req, res) => {
  try {
    const { ordname } = req.params;
    const { status } = req.body; // 'לפירוק' | 'בעבודה' | 'פורק'
    const result = await priorityPatch(
      `ORDERS('${ordname}')`,
      { QAMF_STATUS: status }
    );
    res.json({ success: true, result });
  } catch (err) {
    console.error('status error:', err.message);
    res.status(500).json({ error: 'שגיאה בעדכון סטטוס' });
  }
});

// ════════════════════════════════════════════════════
// ADMIN ROUTES — ניהול משתמשים
// ════════════════════════════════════════════════════

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'גישה מותרת למנהלים בלבד' });
    }
    next();
  });
}

// GET /api/admin/users — רשימת כל המשתמשים
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const safe = users.map(u => ({
    id: u.id, username: u.username, display: u.display, role: u.role
  }));
  res.json(safe);
});

// POST /api/admin/users — הוסף משתמש
app.post('/api/admin/users', requireAdmin, (req, res) => {
  const { username, display, password, role } = req.body;
  if (!username || !display || !password) {
    return res.status(400).json({ error: 'יש למלא את כל השדות' });
  }
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'שם המשתמש כבר קיים' });
  }
  const newId = Math.max(...users.map(u => u.id)) + 1;
  const newUser = { id: newId, username, display, password, role: role || 'worker' };
  users.push(newUser);
  res.json({ success: true, user: { id: newId, username, display, role: newUser.role } });
});

// PATCH /api/admin/users/:id — עדכן משתמש
app.patch('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const u = users.find(x => x.id === id);
  if (!u) return res.status(404).json({ error: 'משתמש לא נמצא' });
  const { username, display, password, role } = req.body;
  if (username) u.username = username;
  if (display) u.display = display;
  if (password) u.password = password;
  if (role) u.role = role;
  res.json({ success: true, user: { id: u.id, username: u.username, display: u.display, role: u.role } });
});

// DELETE /api/admin/users/:id — מחק משתמש
app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const u = users.find(x => x.id === id);
  if (!u) return res.status(404).json({ error: 'משתמש לא נמצא' });
  if (u.role === 'admin') return res.status(400).json({ error: 'לא ניתן למחוק מנהל' });
  const idx = users.indexOf(u);
  users.splice(idx, 1);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════
// HEALTH CHECK
// ════════════════════════════════════════════════════
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`✅ שרת פירוקייה רץ על פורט ${PORT}`);
  console.log(`   Priority URL: ${PRIORITY_BASE}`);
});
