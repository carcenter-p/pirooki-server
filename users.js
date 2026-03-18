// ─── ניהול משתמשים ───────────────────────────────────
// כאן מוגדרים משתמשי המערכת.
// סיסמאות מוצפנות עם bcrypt (לא שמורות בטקסט גלוי).
//
// כדי להוסיף משתמש חדש:
//   1. הרץ: node hash-password.js YOUR_PASSWORD
//   2. הדבק את הפלט בשדה password למטה
// ─────────────────────────────────────────────────────

const users = [
  {
    id: 1,
    username: 'ישראל',
    // סיסמה: 1234
    password: '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
    display: 'ישראל כ.',
    role: 'worker'
  },
  {
    id: 2,
    username: 'משה',
    // סיסמה: 1234
    password: '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
    display: 'משה ל.',
    role: 'worker'
  },
  {
    id: 3,
    username: 'דוד',
    // סיסמה: 1234
    password: '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
    display: 'דוד מ.',
    role: 'worker'
  },
  {
    id: 4,
    username: 'admin',
    // סיסמה: admin123
    password: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
    display: 'מנהל',
    role: 'admin'
  }
];

module.exports = users;
