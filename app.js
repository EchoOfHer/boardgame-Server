const express = require('express');
const app = express();


app.use(express.json());
app.use(express.urlencoded({ extended: true }));


const con = require('./db');
// ---------- authentication ---------


// ---------- dashboard ---------


// ---------- borrow-history ---------


// ---------- Check request ---------


// ---------- Request borrowing ---------




// ---------- Server starts here ---------
const PORT = 3000;
app.listen(PORT, () => {
    console.log('Server is running at ' + PORT);
});
