# שרת פירוקייה 🔧

שרת ביניים בין אפליקציית הפירוקייה לבין פריורטי.

---

## הצעדים להעלאה ל-Railway

### שלב 1 — העלאה ל-GitHub

1. היכנס ל [github.com](https://github.com)
2. לחץ על **"New repository"** (כפתור ירוק)
3. שם: `pirooki-server`
4. סמן **Private** (פרטי)
5. לחץ **"Create repository"**
6. גרור את כל הקבצים האלה לתוך הדף
7. לחץ **"Commit changes"**

---

### שלב 2 — העלאה ל-Railway

1. היכנס ל [railway.app](https://railway.app)
2. לחץ **"New Project"**
3. בחר **"Deploy from GitHub repo"**
4. בחר את `pirooki-server`
5. Railway יתחיל לבנות אוטומטית ✅

---

### שלב 3 — הגדרת משתנים סביבתיים

ב-Railway לחץ על הפרויקט → **Variables** → הוסף:

| שם משתנה | ערך |
|----------|-----|
| `PRIORITY_BASE_URL` | `https://p.priority-connect.online/odata/Priority/tabb0864.ini/acr2025` |
| `PRIORITY_USER` | שם המשתמש שתקבל מהספק |
| `PRIORITY_PASS` | הסיסמה שתקבל מהספק |
| `JWT_SECRET` | כל מחרוזת ארוכה ואקראית |

---

### שלב 4 — קבלת כתובת השרת

ב-Railway לחץ **Settings** → **Domains** → **Generate Domain**
תקבל כתובת כמו: `https://pirooki-server-production.up.railway.app`

---

### שלב 5 — חיבור האפליקציה לשרת

שלח לי את הכתובת שקיבלת ואני אעדכן את האפליקציה.

---

## הוספת משתמש חדש

```bash
node hash-password.js הסיסמה_החדשה
```
העתק את הפלט ל-`users.js`

---

## בדיקה שהשרת עובד

פתח בדפדפן: `https://YOUR-SERVER.up.railway.app/health`

אמור להופיע: `{"status":"ok",...}`
