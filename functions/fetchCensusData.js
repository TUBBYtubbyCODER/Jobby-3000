// fetchCensusData.js
// Import and connect to your DB
const sqlite3 = require('sqlite3').verbose();
let db = new sqlite3.Database('path_to_your_db.sqlite');

db.all("SELECT * FROM NAICS_Data WHERE NAICS_Code = '611500'", (err, rows) => {
  if (err) throw err;
  // Rows is your queried data
  // Pass it to your front-end/visualization
});
