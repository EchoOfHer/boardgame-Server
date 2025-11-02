// db.js
// USE mysql2/promise for async/await functionality
const mysql = require("mysql2/promise");

// Use createPool for better connection management and promise support
const con = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '', // Use your password if set, otherwise leave as ''
    database: 'boardgame'
});

module.exports = con;