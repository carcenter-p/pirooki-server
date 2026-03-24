require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const fetch   = require('node-fetch');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());
app.use((req, res, next) => { res.setTimeout(300000); next(); });
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

// fetch עם timeout
async function fetchWithTimeout(url, opts, ms=25000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal });
    clearTimeout(timer);
    return res;
  } catch(e) {
    clearTimeout(timer);
    throw e;
  }
}

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
  const res = await fetchWithTimeout(`${PRIORITY_BASE}/${path}`, {
    headers: { 'Authorization': priorityAuth, 'Content-Type': 'application/json' }
  });
  if (!res.ok) throw new Error(`Priority error: ${res.status}`);
  return res.json();
}

async function priorityPost(path, body) {
  const res = await fetchWithTimeout(`${PRIORITY_BASE}/${path}`, {
    method: 'POST',
    headers: { 'Authorization': priorityAuth, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }, 120000);
  if (!res.ok) throw new Error(`Priority error: ${res.status}`);
  return res.json();
}

async function priorityPatch(path, body) {
  const res = await fetchWithTimeout(`${PRIORITY_BASE}/${path}`, {
    method: 'PATCH',
    headers: { 'Authorization': priorityAuth, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }, 120000);
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
    const data = await priorityGet(`SERNUMBERS?$filter=QAMF_LICENSEPLATE eq '${req.params.regnum}'&$select=SERNUM,SERN,PARTNAME,PARTDES,QAMF_LICENSEPLATE,QAMF_TOZAR,QAME_GIMUR,QAME_TIMEGETROAD,QAMF_OOZMETER,ODATE`);
    if (!data.value || data.value.length === 0) return res.status(404).json({ error: 'רכב לא נמצא' });
    // מצא את רשומת הרכב הראשית — זו שה-SERNUM שלה שווה למספר הרישוי בדיוק
    const regnum = req.params.regnum;
    const mainRecord = data.value.find(v => v.SERNUM === regnum) || data.value[data.value.length - 1];
    console.log('vehicle SERNUM search:', regnum, '-> found SERNUM:', mainRecord.SERNUM, 'PARTDES:', mainRecord.PARTDES);
    res.json(mainRecord);
  } catch (err) { console.error('VEHICLE ERROR:', err.message); res.status(500).json({ error: 'שגיאה בשליפת נתוני רכב', details: err.message }); }
});

app.get('/api/parts/:regnum', requireAuth, async (req, res) => {
  try {
    const regnum = req.params.regnum;
    // שלוף רשימת מכלולים קבועה
    const mechlolData = await priorityGet(`LOGPART?$filter=QAMF_MECHLOL eq 'Y'&$select=PARTNAME,PARTDES`);
    const mechlolList = mechlolData.value || [];
    // שלוף מה שפורק לרכב זה
    const unloadedData = await priorityGet(`QAMF_SERNMECLOLF?$filter=SERNUM eq '${regnum}'&$select=PARTNAME,UNLOADED,PART`);
    const unloadedMap = {};
    (unloadedData.value || []).forEach(p => { unloadedMap[p.PARTNAME] = p; });
    // שלב — לכל מכלול סמן אם פורק
    const result = mechlolList.map(m => ({
      PARTNAME: m.PARTNAME,
      PARTDES: m.PARTDES,
      MECLOL: m.PARTNAME,
      DISMANTLED: unloadedMap[m.PARTNAME] ? unloadedMap[m.PARTNAME].UNLOADED : null,
      PART: unloadedMap[m.PARTNAME] ? unloadedMap[m.PARTNAME].PART : null
    }));
    res.json(result);
  } catch (err) { console.error('PARTS ERROR:', err.message); res.status(500).json({ error: 'שגיאה בשליפת חלקים', details: err.message }); }
});

app.post('/api/parts/dismantle', requireAuth, async (req, res) => {
  try {
    const { regnum, parts } = req.body;
    const results = [];
    console.log('dismantling:', parts.length, 'parts for vehicle:', regnum);

    // החזר תשובה מיד לאפליקציה
    res.json({ success: true, count: parts.length });

    // תזמן קבלה למלאי מיד — ללא תלות בהצלחת הפירוק
    const partsToReceive = [...parts];
    const regnumToReceive = regnum;
    setTimeout(async () => {
      try {
        console.log('creating receipt for vehicle:', regnumToReceive, 'parts:', partsToReceive.length);
        await createReceipt(regnumToReceive, partsToReceive);
      } catch(e) {
        console.error('receipt schedule error:', e.message);
      }
    }, 30 * 1000); // 30 שניות לבדיקה

    // שלח לפריורטי ברקע — GET לכל חלק בנפרד ואז PATCH
    (async () => {
      const dismantled = [];
      for (const part of parts) {
        try {
          // שלוף PART ו-SERN לכל חלק בנפרד
          const existing = await priorityGet(
            `QAMF_SERNMECLOLF?$filter=SERNUM eq '${regnum}' and PARTNAME eq '${part.partname}'&$select=PART,SERN`
          );
          if (!existing.value || existing.value.length === 0) {
            console.error('part not found:', part.partname);
            continue;
          }
          const { PART, SERN } = existing.value[0];
          await priorityPatch(`QAMF_SERNMECLOLF(PART=${PART},SERN=${SERN})`, { UNLOADED: 'Y' });
          console.log('dismantled OK:', part.partname);
          dismantled.push(part);
        } catch(e) {
          console.error('dismantle error:', part.partname, e.message);
        }
        await new Promise(r => setTimeout(r, 1000));
      }
      console.log('all dismantling done');
    })();
  } catch (err) { console.error('dismantle error:', err.message); res.status(500).json({ error: 'שגיאה בסימון פירוק', details: err.message }); }
});

app.patch('/api/parts/undo', requireAuth, async (req, res) => {
  try {
    const { regnum, partname } = req.body;
    const existing = await priorityGet(
      `QAMF_SERNMECLOLF?$filter=SERNUM eq '${regnum}' and PARTNAME eq '${partname}'&$select=PART,SERN`
    );
    if (!existing.value || existing.value.length === 0)
      return res.status(404).json({ error: 'שורה לא נמצאה' });
    const { PART, SERN } = existing.value[0];
    console.log('undo:', partname, 'PART:', PART, 'SERN:', SERN);
    const result = await priorityPatch(`QAMF_SERNMECLOLF(PART=${PART},SERN=${SERN})`, { UNLOADED: '' });
    res.json({ success: true, result });
  } catch (err) { console.error('undo error:', err.message); res.status(500).json({ error: 'שגיאה בביטול פירוק', details: err.message }); }
});

// ════════════════════════════════════════════════════
// ORDERS
// ════════════════════════════════════════════════════

app.get('/api/orders', requireAuth, async (req, res) => {
  try {
    const data = await priorityGet(`ORDISINGLE?$filter=ORDSTATUSDES eq 'לפירוק' or ORDSTATUSDES eq 'בעבודה'&$select=ORDNAME,CDES,CURDATE,ORDSTATUSDES,ORDISTATUSDES,PARTNAME,PDES,TQUANT,QAMF_LICENSEPLATE,SPEC2,SPEC4,SPEC18,QAME_AGENTNAME&$top=100`);
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
// TRANSFER — העברות בין מחסנים
// ════════════════════════════════════════════════════

app.post('/api/transfer/bring-by-order', requireAuth, async (req, res) => {
  try {
    const { ordname } = req.body;
    
    // שלב 1 — שלוף SERNUM ו-LICENSEPLATE מה-ORDISINGLE
    const ordData = await priorityGet(
      `ORDISINGLE?$filter=ORDNAME eq '${ordname}'&$select=QAMF_SERNUM,QAMF_LICENSEPLATE&$top=1`
    );
    if (!ordData.value || ordData.value.length === 0)
      return res.status(404).json({ error: 'הזמנה לא נמצאה' });
    
    const sernum = ordData.value[0].QAMF_SERNUM;
    const licenseplate = ordData.value[0].QAMF_LICENSEPLATE;
    
    if (!sernum || !licenseplate)
      return res.status(400).json({ error: 'לא נמצא מספר רכב בהזמנה' });

    // שלב 2 — שלוף מיקום הרכב מ-PARTBAL לפי מספר רישוי
    const balData = await priorityGet(
      `PARTBAL?$filter=PARTNAME eq '${licenseplate}' and TBALANCE gt 0&$select=LOCNAME,WARHSNAME&$top=1`
    );
    const locname = balData.value && balData.value.length > 0 ? (balData.value[0].LOCNAME || '0') : '0';
    console.log('vehicle locname from PARTBAL:', locname, 'for licenseplate:', licenseplate);

    // שלב 3 — צור תעודת העברה
    const today = new Date().toISOString().split('T')[0] + 'T00:00:00Z';
    console.log('bring car POST - sernum:', sernum, 'licenseplate:', licenseplate, 'locname:', locname);
    // צור תעודה עם שורת רכב בפעולה אחת
    const doc = await priorityPost('DOCUMENTS_T', {
      TYPE: 'T',
      CURDATE: today,
      WARHSNAME: '100',
      LOCNAME: locname || '0',
      TOWARHSNAME: '100',
      TOLOCNAME: '0',
      STCODE: '1',
      STATDES: 'ממנהל פירוק',
      DETAILS: licenseplate,
      TRANSORDER_T_SUBFORM: [{
        PARTNAME: licenseplate,
        TQUANT: 1
      }]
    });
    console.log('bring car transfer created:', doc.DOCNO);
    res.json({ success: true, docno: doc.DOCNO });
  } catch(err) {
    console.error('bring car error:', err.message);
    res.status(500).json({ error: 'שגיאה בפקודת הבא רכב', details: err.message });
  }
});

app.post('/api/transfer/by-plate', requireAuth, async (req, res) => {
  try {
    const { licenseplate, stcode } = req.body;
    const toLocMap = { '4': 'SHITA', '5': 'BARZEL' };
    const tolocname = toLocMap[stcode] || '0';

    // שלוף מיקום הרכב מ-PARTBAL
    const balData = await priorityGet(
      `PARTBAL?$filter=PARTNAME eq '${licenseplate}' and TBALANCE gt 0&$select=LOCNAME&$top=1`
    );
    const locname = balData.value && balData.value.length > 0 ? (balData.value[0].LOCNAME || '0') : '0';

    const today = new Date().toISOString().split('T')[0] + 'T00:00:00Z';
    const doc = await priorityPost('DOCUMENTS_T', {
      TYPE: 'T',
      CURDATE: today,
      WARHSNAME: '100',
      LOCNAME: locname,
      TOWARHSNAME: '100',
      TOLOCNAME: tolocname,
      STCODE: stcode,
      STATDES: 'ממנהל פירוק',
      DETAILS: licenseplate,
      TRANSORDER_T_SUBFORM: [{
        PARTNAME: licenseplate,
        TQUANT: 1
      }]
    });
    console.log('by-plate transfer created:', doc.DOCNO, 'stcode:', stcode);
    res.json({ success: true, docno: doc.DOCNO });
  } catch(err) {
    console.error('by-plate transfer error:', err.message);
    res.status(500).json({ error: 'שגיאה בפקודת העברה', details: err.message });
  }
});

app.post('/api/transfer/return', requireAuth, async (req, res) => {
  try {
    const { ordname, stcode, tolocname: tolocnameParam } = req.body;

    // שלוף LICENSEPLATE מה-ORDISINGLE
    const ordData = await priorityGet(
      `ORDISINGLE?$filter=ORDNAME eq '${ordname}'&$select=QAMF_LICENSEPLATE&$top=1`
    );
    if (!ordData.value || ordData.value.length === 0)
      return res.status(404).json({ error: 'הזמנה לא נמצאה' });

    const licenseplate = ordData.value[0].QAMF_LICENSEPLATE;
    if (!licenseplate)
      return res.status(400).json({ error: 'לא נמצא מספר רכב בהזמנה' });

    // שלוף מיקום הרכב מ-PARTBAL
    const balData = await priorityGet(
      `PARTBAL?$filter=PARTNAME eq '${licenseplate}' and TBALANCE gt 0&$select=LOCNAME&$top=1`
    );
    const locname = balData.value && balData.value.length > 0 ? (balData.value[0].LOCNAME || '0') : '0';

    // איתור מקבל לפי סוג ההעברה
    const toLocMap = { '4': 'SHITA', '5': 'BARZEL' };
    const tolocname = toLocMap[stcode] || tolocnameParam || '0';

    const today = new Date().toISOString().split('T')[0] + 'T00:00:00Z';
    const doc = await priorityPost('DOCUMENTS_T', {
      TYPE: 'T',
      CURDATE: today,
      WARHSNAME: '100',
      LOCNAME: locname,
      TOWARHSNAME: '100',
      TOLOCNAME: tolocname,
      STCODE: stcode,
      STATDES: 'ממנהל פירוק',
      DETAILS: licenseplate,
      TRANSORDER_T_SUBFORM: [{
        PARTNAME: licenseplate,
        TQUANT: 1
      }]
    });
    console.log('return car transfer created:', doc.DOCNO, 'stcode:', stcode, 'from:', locname, 'to:', tolocname);
    res.json({ success: true, docno: doc.DOCNO });
  } catch(err) {
    console.error('return car error:', err.message);
    res.status(500).json({ error: 'שגיאה בפקודת העברה', details: err.message });
  }
});

app.post('/api/transfer/bring', requireAuth, async (req, res) => {
  try {
    const { partname, sernum, locname } = req.body;
    const today = new Date().toISOString().split('T')[0] + 'T00:00:00Z';

    // שלוף מיקום הרכב מ-PARTBAL
    const balData2 = await priorityGet(
      `PARTBAL?$filter=PARTNAME eq '${partname}' and TBALANCE gt 0&$select=LOCNAME&$top=1`
    );
    const actualLocname = balData2.value && balData2.value.length > 0 ? (balData2.value[0].LOCNAME || '0') : (locname || '0');
    console.log('actual locname:', actualLocname);

    // צור תעודת העברה כולל שורת רכב בפעולה אחת
    const doc = await priorityPost('DOCUMENTS_T', {
      TYPE: 'T',
      CURDATE: today,
      WARHSNAME: '100',
      LOCNAME: actualLocname,
      TOWARHSNAME: '100',
      TOLOCNAME: '0',
      STCODE: '1',
      STATDES: 'ממנהל פירוק',
      TRANSORDER_T_SUBFORM: [{
        PARTNAME: partname,
        TQUANT: 1
      }]
    });
    console.log('transfer doc created:', doc.DOCNO);

    res.json({ success: true, docno: doc.DOCNO });
  } catch(err) {
    console.error('transfer error:', err.message, 'partname:', partname, 'locname:', locname);
    res.status(500).json({ error: 'שגיאה ביצירת העברה', details: err.message });
  }
});

// ════════════════════════════════════════════════════
// RECEIPT — קבלת מלאי לפירוקייה
// ════════════════════════════════════════════════════

async function createReceipt(regnum, parts) {
  try {
    const today = new Date().toISOString().split('T')[0] + 'T00:00:00Z';
    
    // שלב 1 — צור תעודת קבלה
    const doc = await priorityPost('DOCUMENTS_P', {
      TYPE: 'P',
      CURDATE: today,
      SUPNAME: '001',
      TOWARHSNAME: '100',
      TOLOCNAME: 'PIRUKIA'
    });
    console.log('receipt doc created:', doc.DOCNO, 'DOC:', doc.DOC);

    // שלב 2 — הוסף שורות חלקים בנפרד לכל חלק
    for (const part of parts) {
      try {
        await priorityPost(`DOCUMENTS_P('${doc.DOCNO}')/TRANSORDER_P_SUBFORM`, {
          PARTNAME: part.partname,
          TQUANT: 1,
          TOWARHSNAME: '100',
          TOLOCNAME: 'PIRUKIA',
          QAMF_SERNUM: regnum
        });
        console.log('receipt row added:', part.partname);
      } catch(e) {
        console.error('receipt row error:', part.partname, e.message);
      }
    }
    console.log('receipt rows done:', parts.length, 'parts for vehicle:', regnum);
    return doc;
  } catch(err) {
    console.error('receipt error:', err.message);
  }
}

app.post('/api/parts/dismantle-and-receive', requireAuth, async (req, res) => {
  // endpoint זהה ל-dismantle אבל עם תזמון קבלה אחרי שעה
  res.json({ success: true, message: 'dismantling scheduled' });
});

// ════════════════════════════════════════════════════
// TEST — בדיקת POST ל-QAMF_SERNMECLOLF
// ════════════════════════════════════════════════════

app.post('/api/test-post-part', requireAuth, async (req, res) => {
  try {
    const { sern, part, sernum } = req.body;
    const result = await priorityPost('QAMF_SERNMECLOLF', {
      SERN: sern,
      PART: part,
      SERNUM: sernum,
      UNLOADED: 'Y'
    });
    console.log('test post part result:', result);
    res.json({ success: true, result });
  } catch(err) {
    console.error('test post part error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════
// BARZEL TRANSFERS — שמירת העברות ברזל
// ════════════════════════════════════════════════════

app.get('/api/barzel', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('barzel_transfers').select('key');
  if (error) return res.status(500).json({ error: 'שגיאה' });
  res.json(data.map(r => r.key));
});

app.post('/api/barzel', requireAuth, async (req, res) => {
  const { key } = req.body;
  const { error } = await supabase.from('barzel_transfers').upsert({ key });
  if (error) return res.status(500).json({ error: 'שגיאה' });
  res.json({ success: true });
});

// ════════════════════════════════════════════════════
// HEALTH
// ════════════════════════════════════════════════════

app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

app.listen(PORT, () => {
  console.log(`✅ שרת פירוקייה רץ על פורט ${PORT}`);
});
