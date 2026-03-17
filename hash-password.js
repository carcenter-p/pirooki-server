// כלי עזר ליצירת סיסמה מוצפנת
// שימוש: node hash-password.js YOUR_PASSWORD
const bcrypt = require('bcryptjs');
const password = process.argv[2];
if (!password) {
  console.log('שימוש: node hash-password.js YOUR_PASSWORD');
  process.exit(1);
}
const hash = bcrypt.hashSync(password, 10);
console.log('\nהסיסמה המוצפנת שלך:');
console.log(hash);
console.log('\nהדבק את השורה הזו בקובץ users.js');
