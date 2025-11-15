const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'mySecretKey123';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));


const con = require('./db');
// ---------- image in server local storage ---------
app.use('/image', express.static('images'));

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
    const [users] = await con.query(
      'SELECT user_id, username, password_hash, role FROM users WHERE username = ?', 
      [username]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
    }

    const user = users[0];

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
    }

    const payload = {
      user_id: user.user_id,
      username: user.username,
      role: user.role
    };

    console.log('JWT Payload:', payload); // เพิ่ม log เพื่อตรวจสอบ payload

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

    let landingPage = 'student.main';
    if (user.role === 'lender') {
      landingPage = 'lender.main';
    } else if (user.role === 'staff') {
      landingPage = 'staff.main';
    }

    res.json({ 
      message: 'เข้าสู่ระบบสำเร็จ',
      token,
      user_id: user.user_id,
      username: user.username,
      role: user.role,
      landingPage
    });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ', error: error.message });
  }
});


// Middleware สำหรับตรวจสอบ JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>
    if (!token) return res.status(401).json({ message: 'Token ไม่ถูกต้องหรือหมดอายุ' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token ไม่ถูกต้อง' });
        req.user = user; // user_id, username, role
        next();
    });
};

// Middleware ตรวจสอบ role
const authorizeRole = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'คุณไม่มีสิทธิ์เข้าถึงข้อมูลนี้' });
        }
        next();
    };
};

// Dashboard สำหรับทุก role
app.get('/api/dashboard', authenticateToken, (req, res) => {
    res.json({
        message: `ยินดีต้อนรับสู่ Dashboard ของ ${req.user.role}`,
        user_info: req.user
    });
});

// Dashboard สำหรับ Student / Borrower เท่านั้น
app.get('/api/student/dashboard', authenticateToken, authorizeRole(['borrower']), (req, res) => {
    res.json({
        message: 'ยินดีต้อนรับสู่ Student Dashboard',
        student_info: req.user
    });
});

// Dashboard สำหรับ Lender เท่านั้น
app.get('/api/lender/dashboard', authenticateToken, authorizeRole(['lender']), (req, res) => {
    res.json({
        message: 'ยินดีต้อนรับสู่ Lender Dashboard',
        lender_info: req.user
    });
});

// Dashboard สำหรับ Staff เท่านั้น
app.get('/api/staff/dashboard', authenticateToken, authorizeRole(['staff']), (req, res) => {
    res.json({
        message: 'ยินดีต้อนรับสู่ Staff Dashboard',
        staff_info: req.user
    });
});


// POST /api/logout - ออกจากระบบ
app.post('/api/logout', (req, res) => {
    res.status(200).json({ 
        message: 'ออกจากระบบสำเร็จ',
        info: 'Client ต้องลบ JWT Token ที่จัดเก็บไว้ด้วยตนเอง'
    });
});



// ---------- dashboard ---------
app.get('/api/games', async (req, res) => {
    console.log('Received GET request for /api/games');
    try {
        const sql = `
            SELECT
                gi.inventory_id, -- Used to uniquely identify each physical copy
                g.game_id,
                g.game_name AS gameName,
                COALESCE(gs.style_name, 'Unknown Style') AS gameStyle,
                g.game_pic_path AS picPath,
                g.game_min_player AS minP,
                g.game_max_player AS maxP,
                g.game_time AS gTime,
                g.game_link_howto AS g_link,
                g.game_name AS gameGroup,
                gi.status AS status 
            FROM
                game_inventory gi
            JOIN game g ON gi.game_id = g.game_id
            LEFT JOIN game_style gs 
                ON g.style_id = gs.style_id
            ORDER BY 
                g.game_name, gi.inventory_id;
        `;

        // Execute the query
        const [results] = await con.query(sql);

        // Map to clean structure
        const gameList = results.map(row => ({
            inventory_id: row.inventory_id,
            game_id: row.game_id,
            gameName: row.gameName,
            gameStyle: row.gameStyle,
            picPath: row.picPath,
            status: row.status, // real-time game status
            minP: row.minP,
            maxP: row.maxP,
            gTime: row.gTime,
            g_link: row.g_link,
            gameGroup: row.gameGroup
        }));

        res.status(200).json(gameList);
    } catch (err) {
        console.error('🚨 Error fetching games:', err);
        res.status(500).json({
            message: 'Failed to retrieve game list from database.',
            error: err.message
        });
    }
});


// ---------- borrow-history (CLEANED AND FIXED) ---------
app.get('/borrow-history', async (req, res) => {
  console.log('[HIT] /borrow-history', req.query);

  try {
    // Validate borrower_id
    const borrowerId = parseInt(req.query.borrower_id, 10);
    if (!Number.isInteger(borrowerId) || borrowerId <= 0) {
      return res.status(400).json({
        success: false,
        message: 'borrower_id is required and must be a positive integer',
      });
    }

    // Optional query params
    const q = String(req.query.q || '').trim();
    const statusFilter = String(req.query.status || '').trim().toLowerCase();
    const limitRaw = parseInt(req.query.limit || '100', 10);
    const limit = Math.min(Math.max(Number.isInteger(limitRaw) ? limitRaw : 100, 1), 200);

    // SQL Query - Reverted to only use DATE for display and sorting (no raw time field)
    const sql = `
      SELECT
        b.borrow_id AS id,
        g.game_name AS game,
        CASE
          WHEN b.status='approved'    THEN 'Approve'
          WHEN b.status='disapproved' THEN 'Disapprove'
          WHEN b.status='returned'    THEN 'Returned'
          WHEN b.status='cancelled'   THEN 'Cancelled'
          WHEN b.status='returning'   THEN 'Returning'
          ELSE 'Pending'
        END AS status,
        uL.username AS approvedBy,
        uS.username AS returnedTo,
        DATE_FORMAT(b.from_date, '%d %b %Y') AS borrowedDate, /* ✅ ส่งแค่ วัน/เดือน/ปี */
        DATE_FORMAT(b.return_date, '%d %b %Y') AS returnedDate,
        b.reason AS reason
      FROM borrow b
      JOIN game g ON g.game_id = b.game_id
      JOIN users uB ON uB.user_id = b.borrower_id
      LEFT JOIN users uL ON uL.user_id = b.lender_id
      LEFT JOIN users uS ON uS.user_id = b.staff_id
      WHERE b.borrower_id = ?
        AND b.status IN ('approved', 'disapproved', 'returned', 'cancelled','returning')
        ${statusFilter ? 'AND LOWER(b.status) = ?' : ''}
        AND (
          ? = '' OR
          LOWER(g.game_name) LIKE CONCAT('%', LOWER(?), '%') OR
          LOWER(uL.username) LIKE CONCAT('%', LOWER(?), '%') OR
          LOWER(uS.username) LIKE CONCAT('%', LOWER(?), '%') OR
          LOWER(b.status)    LIKE CONCAT('%', LOWER(?), '%') OR
          CAST(b.borrow_id AS CHAR) LIKE CONCAT('%', ?, '%')
        )
      ORDER BY b.from_date DESC /* เรียงตามวันที่ (และถ้าเป็น DATETIME ก็จะเรียงตามเวลาด้วย แต่ Frontend จะไม่ใช้) */
      LIMIT ?
    `;

    // Build params
    const params = [borrowerId];
    if (statusFilter) params.push(statusFilter);
    params.push(q, q, q, q, q, q);
    params.push(limit);

    // Execute
    const [rows] = await con.query(sql, params);

    // Response
    return res.status(200).json({
      success: true,
      count: rows.length,
      items: rows,
      borrower_id: borrowerId,
      q,
      status: statusFilter || undefined,
    });
  } catch (err) {
    console.error('[borrow-history] error:', err);
    return res.status(500).json({
      success: false,
      message: 'Internal Server Error',
      error: err instanceof Error ? err.message : String(err),
    });
  }
});

// ---------- Check request FIXED: Filter for Active Statuses Only ---------
app.get('/api/check-request/:user_id', async (req, res) => {
 const { user_id } = req.params;

 try {
 const sql = `
 SELECT 
 b.borrow_id,
b.status AS borrow_status,
b.from_date,
 b.return_date,
 g.game_name,
 g.game_pic_path,
 g.game_link_howto,
 gi.status AS game_inventory_status
 FROM borrow b
JOIN game g ON b.game_id = g.game_id
 JOIN game_inventory gi ON g.game_id = gi.game_id
WHERE b.borrower_id = ?
AND b.status IN ('pending', 'approved', 'returning')  /* 🔑 NEW: Filter active requests */
ORDER BY b.borrow_id DESC;
 `;

 const [results] = await con.query(sql, [user_id]);

 if (results.length === 0) {
 return res.status(200).json({
 message: 'ไม่พบคำขอยืมหรือประวัติการยืมของผู้ใช้นี้',
 data: []
 });
 }

 const formatted = results.map(item => ({
 borrow_id: item.borrow_id,
 game_name: item.game_name,
 pic_path: item.game_pic_path,
from_date: item.from_date,
return_date: item.return_date,
 borrow_status: item.borrow_status,
game_inventory_status: item.game_inventory_status,
 howto_link: item.game_link_howto
 }));

 res.status(200).json({
 message: 'ดึงข้อมูลคำขอยืมสำเร็จ',
data: formatted
 });
} catch (err) {
console.error('❌ Error fetching check request:', err);
res.status(500).json({
message: 'เกิดข้อผิดพลาดในการดึงข้อมูลคำขอยืม',
error: err.message
 });
 }
});

// ---------- Cancled borrowing ---------
app.put('/api/borrow/status/:borrowId', async (req, res) => {
    const { borrowId } = req.params;
    const { status } = req.body; 

    // 2. ตรวจสอบข้อมูล
    if (!status || !['cancelled', 'returning'].includes(status.toLowerCase())) {
        return res.status(400).json({ message: 'สถานะที่ส่งมาไม่ถูกต้อง (ต้องเป็น cancelled หรือ returning)' });
    }
    
    // 3. เตรียมคำสั่ง SQL
    try {
        let updateStatus = status.toLowerCase();
        
        // 4. ทำการอัปเดต (Cleaned SQL String)
        const sql = `
            UPDATE borrow
            SET status = ?
            WHERE borrow_id = ?;
        `;
        
        const [result] = await con.query(sql, [updateStatus, borrowId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'ไม่พบรายการยืมที่ต้องการอัปเดต' });
        }

        res.status(200).json({
            message: `อัปเดตสถานะการยืม ${borrowId} เป็น ${updateStatus} สำเร็จ`,
            borrow_id: borrowId,
            new_status: updateStatus
        });

    } catch (err) {
        console.error('❌ Error updating borrow status:', err);
        res.status(500).json({
            message: 'เกิดข้อผิดพลาดในการอัปเดตสถานะ',
            error: err.message
        });
    }
});


// ---------- Request borrowing ---------
// POST /request-borrowing
app.post('/request-borrowing', async (req, res) => {
    // 🔑 NOTE: คาดหวัง student_id จาก Flutter Client
    const { game_id, student_id, start_date, end_date } = req.body; 
    const initialStatus = 'pending'; 

    if (!game_id || !student_id || !start_date || !end_date) {
        return res.status(400).json({ message: 'Missing required fields.' });
    }

    try {
        // 1. Safety Check: Check if the user already has an active request (Enforce 1 active borrow rule)
        // ตรวจสอบสถานะ: 'pending', 'approved', 'returning'
        const [activeBorrows] = await con.query(
            "SELECT borrow_id FROM borrow WHERE borrower_id = ? AND status IN ('pending', 'approved', 'returning')",
            [student_id]
        );

        if (activeBorrows.length > 0) {
            // ส่งสถานะ 409 Conflict หากผู้ใช้มีรายการแอคทีฟอยู่แล้ว
            return res.status(409).json({ message: 'Borrow request failed: You already have an active request.' });
        }

        // 2. Insert new borrow record
        const sql = `
            INSERT INTO borrow (borrower_id, game_id, from_date, return_date, status)
            VALUES (?, ?, ?, ?, ?);
        `;

        const [result] = await con.query(sql, [
            student_id,
            game_id,
            start_date,
            end_date,
            initialStatus
        ]);
        
        // 3. Send success response
        res.status(200).json({
            message: 'Borrow request successfully created and is pending approval.',
            borrow_id: result.insertId,
            status: initialStatus
        });

    } catch (err) {
        console.error('❌ Error requesting borrowing:', err);
        res.status(500).json({
            message: 'เกิดข้อผิดพลาดในการสร้างคำขอยืม',
            error: err.message
        });
    }
});


// approve borrowing request ของ lender

app.post('/api/borrow/approval/:borrowId', authenticateToken, async (req, res) => {
    const { borrowId } = req.params;
    const { status, lender_id, reason } = req.body;

    const allowedStatuses = ['approved', 'disapproved'];
    if (!status || !allowedStatuses.includes(status.toLowerCase())) {
        return res.status(400).json({ message: 'สถานะต้องเป็น approved หรือ disapproved' });
    }

    if (!lender_id || isNaN(parseInt(lender_id))) {
        return res.status(400).json({ message: 'lender_id จำเป็น' });
    }

    const updateStatus = status.toLowerCase();
    const approverId = parseInt(lender_id, 10);
    const updateField = req.user.role === 'lender' ? 'lender_id' : 'staff_id';

    // ตรวจสอบ reason สำหรับ disapproved
    if (updateStatus === 'disapproved' && (!reason || reason.trim() === '')) {
        return res.status(400).json({ message: 'ต้องระบุเหตุผลสำหรับการไม่อนุมัติ' });
    }

    try {
        // 1. ตรวจสอบว่ายังเป็น pending อยู่
        const [borrowInfo] = await con.query(
            'SELECT status FROM borrow WHERE borrow_id = ?',
            [borrowId]
        );

        if (borrowInfo.length === 0 || borrowInfo[0].status !== 'pending') {
            return res.status(404).json({ message: 'ไม่พบคำขอหรือสถานะไม่ใช่ pending' });
        }

        // 2. อัปเดตเฉพาะใน borrow โดยใช้ borrow_id
        let sql, params;

        if (updateStatus === 'approved') {
            sql = `
                UPDATE borrow 
                SET status = ?, ${updateField} = ?
                WHERE borrow_id = ? AND status = 'pending'
            `;
            params = [updateStatus, approverId, borrowId];
        } else {
            sql = `
                UPDATE borrow 
                SET status = ?, ${updateField} = ?, reason = ?
                WHERE borrow_id = ? AND status = 'pending'
            `;
            params = [updateStatus, approverId, reason, borrowId];
        }

        const [result] = await con.query(sql, params);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'อัปเดตไม่สำเร็จ: สถานะอาจเปลี่ยนไปแล้ว' });
        }

        // สำเร็จ!
        res.status(200).json({
            message: `สถานะอัปเดตเป็น ${updateStatus} สำเร็จ`,
            borrow_id: borrowId,
            new_status: updateStatus
        });

    } catch (err) {
        console.error('Error in approval:', err);
        res.status(500).json({ message: 'เซิร์ฟเวอร์ error', error: err.message });
    }
});


app.get('/lender/pending', async (req, res) => {
  const sql = `
    SELECT 
      b.borrow_id AS id, 
      g.game_name,
      g.game_pic_path, 
      u.username AS borrower_name, 
      b.from_date, 
      b.return_date
    FROM borrow b
    LEFT JOIN game g ON b.game_id = g.game_id
    LEFT JOIN users u ON b.borrower_id = u.user_id
    WHERE b.status = 'pending'
    ORDER BY b.from_date ASC
  `;

  try {
    const [rows] = await con.query(sql);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});



app.post('/lender/approve/:id', async (req, res) => {
  const id = req.params.id;
  try {
    await con.query("UPDATE borrow SET status='approved' WHERE borrow_id=?", [id]);
    res.send({ message: 'Approved' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/lender/disapprove/:id', async (req, res) => {
  const id = req.params.id;
  const reason = req.body.reason;
  try {
    await con.query("UPDATE borrow SET status='disapproved', reason=? WHERE borrow_id=?", [reason, id]);
    res.send({ message: 'Disapproved' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// --- Lender History API ---
app.get('/HistoryLenderPage', async (req, res) => {
  console.log('[HIT] /HistoryLenderPage', req.query);

  try {
    const lenderId = parseInt(req.query.lender_id, 10);
    if (!Number.isInteger(lenderId) || lenderId <= 0) {
      return res.status(400).json({
        success: false,
        message: 'lender_id is required and must be a positive integer',
      });
    }

    const q = String(req.query.q || '').trim();
    const statusFilter = String(req.query.status || '').trim().toLowerCase();
    const limitRaw = parseInt(req.query.limit || '100', 10);
    const limit = Math.min(Math.max(Number.isInteger(limitRaw) ? limitRaw : 100, 1), 200);

    const sql = `
      SELECT
        b.borrow_id AS id,
        g.game_name AS game,
        CASE
          WHEN b.status='approved'    THEN 'Approve'
          WHEN b.status='disapproved' THEN 'Disapprove'
          WHEN b.status='returned'    THEN 'Returned'
          WHEN b.status='cancelled'   THEN 'Cancelled'
          WHEN b.status='returning'   THEN 'Returning'
          ELSE 'Pending'
        END AS status,
        uL.username AS borrowedBy,
        uS.username AS returnedTo,
        DATE_FORMAT(b.from_date, '%d %b %Y') AS borrowedDate,
        DATE_FORMAT(b.return_date, '%d %b %Y') AS returnedDate,
        b.reason AS reason
      FROM borrow b
      JOIN game g ON g.game_id = b.game_id
      LEFT JOIN users uL ON uL.user_id = b.borrower_id
      LEFT JOIN users uS ON uS.user_id = b.staff_id
      WHERE b.lender_id = ?
        AND b.status IN ('approved', 'disapproved', 'returned', 'cancelled', 'returning')
        ${statusFilter ? 'AND LOWER(b.status) = ?' : ''}
        AND (
          ? = '' OR
          LOWER(g.game_name) LIKE CONCAT('%', LOWER(?), '%') OR
          LOWER(uL.username) LIKE CONCAT('%', LOWER(?), '%') OR
          LOWER(uS.username) LIKE CONCAT('%', LOWER(?), '%') OR
          LOWER(b.status) LIKE CONCAT('%', LOWER(?), '%') OR
          CAST(b.borrow_id AS CHAR) LIKE CONCAT('%', ?, '%')
        )
      ORDER BY b.from_date DESC
      LIMIT ?
    `;

    const params = [lenderId];
    if (statusFilter) params.push(statusFilter);
    params.push(q, q, q, q, q, q);
    params.push(limit);

    // Using con.query (correct for mysql2/promise)
    const [rows] = await con.query(sql, params);

    res.json({
      success: true,
      count: rows.length,
      items: rows,
      lender_id: lenderId,
      q,
      status: statusFilter || undefined,
    });
  } catch (err) {
    console.error('[HistoryLenderPage] error:', err);
    res.status(500).json({
      success: false,
      message: 'Internal Server Error',
      error: err instanceof Error ? err.message : String(err),
    });
  }
});
// ---------- Lender status summary ---------
app.get('/api/status-summary', authenticateToken, async (req, res) => {
  try {
    // ดึง user จาก token
    const user = req.user;
    const userRole = user.role;
    const lenderId = user.user_id;

    // Logic ใหม่: ทุก Role (lender, staff, borrower)
    // จะเห็นสรุปสถานะรวมของเกมทั้งหมดใน game_inventory
    let sql = `
        SELECT
          SUM(CASE WHEN status = 'Borrowing' THEN 1 ELSE 0 END) AS borrowed,
          SUM(CASE WHEN status = 'Available' THEN 1 ELSE 0 END) AS available,
          SUM(CASE WHEN status = 'Disabled' THEN 1 ELSE 0 END) AS disabled
        FROM game_inventory;
    `;
    let params = [];

    const [rows] = await con.query(sql, params);
    const data = rows[0];

    res.status(200).json({
      success: true,
      message: 'ดึงข้อมูลสถานะวันนี้สำเร็จ',
      data: {
        // ตัวอย่างผลลัพธ์: borrowed: 1, available: 7, disabled: 1
        borrowed: data.borrowed || 0,
        available: data.available || 0,
        disabled: data.disabled || 0,
      },
      user_role: userRole,
      lender_id: userRole === 'lender' ? lenderId : null
    });
  } catch (err) {
    console.error('Error fetching today status:', err);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูลสถานะวันนี้',
      error: err.message,
    });
  }
});

<<<<<<< HEAD
app.get('/staff/games', async (req, res) => {
  try {
    const sql = `
      SELECT 
        g.game_id,
        g.game_name,
        g.style_id,
        g.game_time,
        g.game_min_player,
        g.game_max_player,
        g.game_link_howto,
        g.game_pic_path,
        
        COUNT(*) as total_copies,
        
        SUM(CASE WHEN gi.status = 'Available' THEN 1 ELSE 0 END) as enabled_count,
        SUM(CASE WHEN gi.status = 'Disabled' THEN 1 ELSE 0 END) as disabled_count,
        
        GROUP_CONCAT(gi.inventory_id) as item_ids,
        GROUP_CONCAT(gi.status) as item_statuses

      FROM game g
      JOIN game_inventory gi ON g.game_id = gi.game_id
      GROUP BY g.game_id, g.game_name, g.style_id, g.game_time, g.game_min_player, g.game_max_player, g.game_link_howto, g.game_pic_path
      ORDER BY g.game_name
    `;

    const [rows] = await con.query(sql);

    const games = rows.map(row => ({
      gameName: row.game_name,
      styleId: row.style_id,
      gameTime: row.game_time,
      minPlayers: row.game_min_player,
      maxPlayers: row.game_max_player,
      howToLink: row.game_link_howto,
      picPath: row.game_pic_path,
      totalCopies: parseInt(row.total_copies),
      enabledCount: parseInt(row.enabled_count || 0),
      disabledCount: parseInt(row.disabled_count || 0),
      itemIds: row.item_ids ? row.item_ids.split(',').map(id => id.trim()) : [],
      itemStatuses: row.item_statuses ? row.item_statuses.split(',').map(s => s.trim()) : []
    }));

    res.json({ success: true, games });
  } catch (err) {
    console.error("Games API Error:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.put('/staff/game/status/:inventoryId', authenticateToken, authorizeRole(['staff']), async (req, res) => {
  const { inventoryId } = req.params;
  const { status } = req.body;

  // ตรวจสอบสถานะที่อนุญาต
  const allowedStatuses = ['Available', 'Disabled', 'Borrowing'];
  if (!status || !allowedStatuses.includes(status)) {
    return res.status(400).json({ success: false, message: 'Invalid status. Use: Available, Disabled, Borrowing' });
  }

  try {
    const [result] = await con.query(
      'UPDATE game_inventory SET status = ? WHERE inventory_id = ?',
      [status, inventoryId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Game not found or status unchanged' });
    }

    res.json({ 
      success: true, 
      message: `Status updated to ${status}`,
      inventory_id: inventoryId,
      new_status: status
    });
  } catch (err) {
    console.error('Update game status error:', err);
    res.status(500).json({ success: false, message: err.message });
  }
});
=======
// ---------- Staff ---------
// ---------- Beam ---------
>>>>>>> 80c71b50d5237a5834b2c6deca2b1d17c6481872

// ---------- Gus ---------

// ---------- Peach ---------

// ---------- Pam ---------

// ---------- Tear ---------

// ---------- Server starts here ---------
const PORT = 3000;
app.listen(PORT, () => {
    console.log('Server is running at ' + PORT);
});
