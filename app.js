const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'mySecretKey123';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));


const con = require('./db');

// ---------- authentication ---------

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const role = 'borrower'; 

    if (!username || !password) {
        return res.status(400).json({ message: 'โปรดระบุ Username และ Password ให้ครบถ้วน' });
    }

    try {
        // ตรวจสอบ Username ซ้ำ
        const [existingUsers] = await con.query(
            'SELECT user_id FROM users WHERE username = ?', 
            [username]
        );

        if (existingUsers.length > 0) {
            return res.status(409).json({ message: 'Username นี้มีผู้ใช้แล้ว' });
        }

        // เข้ารหัสรหัสผ่าน (Hashing)
        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(password, salt); 

        // บันทึกผู้ใช้ใหม่
        const [result] = await con.query(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            [username, password_hash, role]
        );

        res.status(201).json({ 
            message: 'ลงทะเบียนสำเร็จ',
            user_id: result.insertId,
            username: username
        });

    } catch (error) {
        console.error('Registration Error:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการลงทะเบียน', error: error.message });
    }
});

// POST /api/login - เข้าสู่ระบบและรับ JWT Token
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'โปรดระบุ Username และ Password' });
    }

    try {
        // 1. ค้นหาผู้ใช้ด้วย Username ในฐานข้อมูล
        // ใช้ username ที่ผู้ใช้ส่งมาในการค้นหา
        const [users] = await con.query(
            'SELECT user_id, username, password_hash, role FROM users WHERE username = ?', 
            [username]
        );

        if (users.length === 0) {
            // ไม่พบผู้ใช้
            return res.status(401).json({ message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
        }

        const user = users[0];

        // 2. เปรียบเทียบรหัสผ่านที่กรอกมากับ Hash ในฐานข้อมูล
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            // รหัสผ่านไม่ตรงกัน
            return res.status(401).json({ message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
        }

        // 3. สร้าง JWT Payload
        const payload = {
            user_id: user.user_id,
            username: user.username,
            role: user.role
        };

        // 4. สร้าง Token
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }); // Token หมดอายุใน 1 ชั่วโมง

        // 5. ส่ง Token และข้อมูลผู้ใช้กลับไปยัง Client
        res.json({ 
            message: 'เข้าสู่ระบบสำเร็จ',
            token: token,
            user_id: user.user_id,
            username: user.username,
            role: user.role
        });

    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ', error: error.message });
    }
});

// Middleware สำหรับตรวจสอบ JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(403).json({ message: 'ไม่พบ Token: กรุณาเข้าสู่ระบบ' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(401).json({ message: 'Token ไม่ถูกต้องหรือหมดอายุ' });
        }
        req.user = user; 
        next(); 
    });
};

// GET /api/dashboard - ตัวอย่าง route ที่ต้องการการยืนยันตัวตน
app.get('/api/dashboard', authenticateToken, (req, res) => {
    res.json({
        message: 'ยินดีต้อนรับสู่ Dashboard (เข้าถึงได้ด้วย Token เท่านั้น)',
        user_info: req.user 
    });
});

// GET /api/dashboard - ตัวอย่าง route ที่ต้องการการยืนยันตัวตน
app.get('/api/dashboard', authenticateToken, (req, res) => {
    res.json({
        message: 'ยินดีต้อนรับสู่ Dashboard (เข้าถึงได้ด้วย Token เท่านั้น)',
        user_info: req.user 
    });
});




// ---------- dashboard ---------


// ---------- borrow-history ---------


// ---------- Check request ---------


// ---------- Request borrowing ---------




// ---------- Server starts here ---------
const PORT = 3000;
app.listen(PORT, () => {
    console.log('Server is running at ' + PORT);
});
