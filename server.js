require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const fetch   = require('node-fetch');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());
app.use(cors());

const PRIORITY_BASE = process.env.PRIORITY_BASE_URL;
const PRIORITY_USER = process.env.PRIORITY_USER;
const PRIORITY_PASS = process.env.PRIORITY_PASS;
const JWT_SECRET    = process.env.JWT_SECRET || 'fallback-secret';
const PORT          = process.env.PORT || 3000;

// Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

const priorityAuth = 'Basic ' + Buffer.from(`${PRIORITY_USER}:${PRIORITY_PASS}`).toString('base64');

// ── Middleware ──────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ error: 'לא מורשה' });
  try { req.user = jwt.verify(header.slice(7), JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'טוקן לא תקף' }); }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'גישה למנהלים בלבד' });
    next();
  });
}

// ── Priority helpers ────────────────────────────────
async function priorityGet(path) {
  const res = await fetch(`${PRIORITY_BASE}/${path}`, {
    headers: { 'Authorization': priorityAuth, 'Content-Type': 'application/json' }
  });
  if (!res.ok) throw new Error(`Priority error: ${res.status}`);
  return res.json();
}

async function priorityPost(path, body) {
  const res = await fetch(`${PRIORITY_BASE}/${path}`, {
    method: 'POST',
    headers: { 'Authorization': priorityAuth, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(`Priority error: ${res.status}`);
  return res.json();
}

async function priorityPatch(path, body) {
  const res = await fetch(`${PRIORITY_BASE}/${path}`, {
    method: 'PATCH',
    headers: { 'Authorization': priorityAuth, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!res.ok) throw new Error(`Priority error: ${res.status}`);
  return res.json();
}

// ════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'יש למלא שם משתמש וסיסמה' });

  const { data: users, error } = await supabase
    .from('users')
    .select('*')
    .eq('username', username)
    .limit(1);

  if (error || !users || users.length === 0)
    return res.status(401).json({ error: 'שם משתמש או סיסמה שגויים' });

  const user = users[0];
  let valid = false;
  if (user.password.startsWith('$2')) {
    valid = await bcrypt.compare(password, user.password);
  } else {
    valid = (password === user.password);
  }
  if (!valid) return res.status(401).json({ error: 'שם משתמש או סיסמה שגויים' });

  const token = jwt.sign(
    { id: user.id, username: user.username, display: user.display, role: user.role },
    JWT_SECRET,
    { expiresIn: '12h' }
  );
  res.json({ token, display: user.display, role: user.role });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ user: req.user }));

// ════════════════════════════════════════════════════
// ADMIN — ניהול משתמשים
// ════════════════════════════════════════════════════

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('id, username, display, role, created_at')
    .order('id');
  if (error) return res.status(500).json({ error: 'שגיאה בשליפת משתמשים' });
  res.json(data);
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  const { username, display, password, role } = req.body;
  if (!username || !display || !password) return res.status(400).json({ error: 'יש למלא את כל השדות' });
  const { data, error } = await supabase
    .from('users')
    .insert([{ username, display, password, role: role || 'worker' }])
    .select('id, username, display, role');
  if (error) return res.status(400).json({ error: error.message.includes('unique') ? 'שם המשתמש כבר קיים' : 'שגיאה ביצירת משתמש' });
  res.json({ success: true, user: data[0] });
});

app.patch('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const { username, display, password, role } = req.body;
  const updates = {};
  if (username) updates.username = username;
  if (display)  updates.display  = display;
  if (password) updates.password = password;
  if (role)     updates.role     = role;
  const { data, error } = await supabase
    .from('users')
    .update(updates)
    .eq('id', req.params.id)
    .select('id, username, display, role');
  if (error) return res.status(500).json({ error: 'שגיאה בעדכון משתמש' });
  res.json({ success: true, user: data[0] });
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const { data: users } = await supabase.from('users').select('role').eq('id', req.params.id).limit(1);
  if (users && users[0]?.role === 'admin') return res.status(400).json({ error: 'לא ניתן למחוק מנהל' });
  const { error } = await supabase.from('users').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: 'שגיאה במחיקת משתמש' });
  res.json({ success: true });
});

// ════════════════════════════════════════════════════
// VEHICLE
// ════════════════════════════════════════════════════

app.get('/api/vehicle/:regnum', requireAuth, async (req, res) => {
  try {
    const data = await priorityGet(`SERNUMBERS?$filter=QAMF_LICENSEPLATE eq '${req.params.regnum}'&$select=SERNUM,SERN,PARTNAME,PARTDES,QAMF_LICENSEPLATE,QAMF_STATDES,QAMF_TOZAR,CDES,ODATE`);
    if (!data.value || data.value.length === 0) return res.status(404).json({ error: 'רכב לא נמצא' });
    res.json(data.value[0]);
  } catch (err) { console.error('VEHICLE ERROR:', err.message); res.status(500).json({ error: 'שגיאה בשליפת נתוני רכב', details: err.message }); }
});

app.get('/api/parts/:regnum', requireAuth, async (req, res) => {
  try {
    // קודם מצא את ה-SERN לפי מספר רישוי
    const vdata = await priorityGet(
      `SERNUMBERS?$filter=QAMF_LICENSEPLATE eq '${req.params.regnum}'&$select=SERN,SERNUM`
    );
    if (!vdata.value || vdata.value.length === 0) return res.json([]);
    const sern = vdata.value[0].SERN;
    const sernum = vdata.value[0].SERNUM;
    const data = await priorityGet(`QAMF_SERNMECLOL?$filter=SERN eq ${sern}&$select=SERN,PARTNAME,PARTDES,MECLOL,DISMANTLED`);
    res.json(data.value || []);
  } catch (err) { console.error('PARTS ERROR:', err.message); res.status(500).json({ error: 'שגיאה בשליפת חלקים', details: err.message }); }
});

app.post('/api/parts/dismantle', requireAuth, async (req, res) => {
  try {
    const { regnum, parts } = req.body;
    const results = [];
    for (const part of parts) {
      const result = await priorityPost('QAMF_SERNMECLOL', { SERNUM: regnum, PARTNAME: part.partname, MECLOL: part.meclol, DISMANTLED: 'Y' });
      results.push(result);
    }
    res.json({ success: true, results });
  } catch (err) { res.status(500).json({ error: 'שגיאה בסימון פירוק' }); }
});

app.patch('/api/parts/undo', requireAuth, async (req, res) => {
  try {
    const { regnum, partname } = req.body;
    const result = await priorityPatch(`QAMF_SERNMECLOL(SERNUM='${regnum}',PARTNAME='${partname}')`, { DISMANTLED: '' });
    res.json({ success: true, result });
  } catch (err) { res.status(500).json({ error: 'שגיאה בביטול פירוק' }); }
});

// ════════════════════════════════════════════════════
// ORDERS
// ════════════════════════════════════════════════════

app.get('/api/orders', requireAuth, async (req, res) => {
  try {
    const data = await priorityGet(`ORDISINGLE?$filter=ORDSTATUSDES eq 'לפירוק'&$select=ORDNAME,CDES,CURDATE,ORDSTATUSDES,ORDISTATUSDES,PARTNAME,PDES,TQUANT,QAMF_LICENSEPLATE,SPEC2,SPEC4,SPEC18&$top=100`);
    res.json(data.value || []);
  } catch (err) { console.error('ORDERS ERROR:', err.message); res.status(500).json({ error: 'שגיאה בשליפת הזמנות', details: err.message }); }
});

app.patch('/api/orders/:ordname/status', requireAuth, async (req, res) => {
  try {
    const { status, ordi } = req.body;
    let result;
    if (ordi) {
      // עדכון סטטוס שורה
      result = await priorityPatch(`ORDISINGLE(${ordi})`, { ORDISTATUSDES: status });
    } else {
      // עדכון סטטוס הזמנה
      result = await priorityPatch(`ORDERS('${req.params.ordname}')`, { ORDSTATUSDES: status });
    }
    res.json({ success: true, result });
  } catch (err) { console.error('STATUS ERROR:', err.message); res.status(500).json({ error: 'שגיאה בעדכון סטטוס', details: err.message }); }
});

// ════════════════════════════════════════════════════
// HEALTH
// ════════════════════════════════════════════════════

app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

app.listen(PORT, () => {
  console.log(`✅ שרת פירוקייה רץ על פורט ${PORT}`);
});
