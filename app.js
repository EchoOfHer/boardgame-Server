const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'mySecretKey123';
const multer = require('multer');
const fs = require('fs');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'images');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const fileExtension = file.originalname.split('.').pop();
        cb(null, uniqueSuffix + '.' + fileExtension);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 } 
});

const con = require('./db');
app.use('/image', express.static('images'));

// ----------
// MIDDLEWARE
// ----------

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token not provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('❌ JWT Verification Failed:', err.name, err.message);
            let errorMessage = 'Token is invalid';
            if (err.name === 'TokenExpiredError') {
                errorMessage = 'Token expired. Please log in again.';
            }
            return res.status(403).json({ message: errorMessage });
        }
        req.user = user;
        next();
    });
};

const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'You do not have permission' });
    }
    next();
  };
};

// ----------
// AUTHENTICATION ROUTES
// ----------

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  const role = 'borrower';

  if (!username || !password) {
    return res.status(400).json({ message: 'โปรดระบุ Username และ Password ให้ครบถ้วน' });
  }

  try {
    const [existingUsers] = await con.query('SELECT user_id FROM users WHERE username = ?', [username]);
    if (existingUsers.length > 0) {
      return res.status(409).json({ message: 'Username นี้มีผู้ใช้แล้ว' });
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const [result] = await con.query(
      'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
      [username, password_hash, role]
    );

    res.status(201).json({ message: 'ลงทะเบียนสำเร็จ', user_id: result.insertId, username: username });

  } catch (error) {
    console.error('Registration Error:', error);
    res.status(500).json({ message: 'เกิดข้อผิดพลาดในการลงทะเบียน', error: error.message });
  }
});

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

    const payload = { user_id: user.user_id, username: user.username, role: user.role };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '24h' });

    let landingPage = 'student.main';
    if (user.role === 'lender') landingPage = 'lender.main';
    else if (user.role === 'staff') landingPage = 'staff.main';

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

app.post('/api/logout', (req, res) => {
  res.status(200).json({ message: 'ออกจากระบบสำเร็จ', info: 'Client ต้องลบ JWT Token เอง' });
});

app.get('/api/username', function (req, res) {
    let token = req.headers['authorization'];
    if (!token) return res.status(400).send('No token');
    if (token.startsWith('Bearer ')) token = token.slice(7);

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(400).send('Incorrect token');
        res.send(decoded);
    });
});

// ----------
// DASHBOARD & GENERAL ROUTES
// ----------

app.get('/api/dashboard', authenticateToken, (req, res) => {
  res.json({ message: `Dashboard for ${req.user.role}`, user_info: req.user });
});

app.get('/api/student/dashboard', authenticateToken, authorizeRole(['borrower']), (req, res) => {
  res.json({ message: 'Student Dashboard', student_info: req.user });
});

app.get('/api/lender/dashboard', authenticateToken, authorizeRole(['lender']), (req, res) => {
  res.json({ message: 'Lender Dashboard', lender_info: req.user });
});

app.get('/api/staff/dashboard', authenticateToken, authorizeRole(['staff']), (req, res) => {
  res.json({ message: 'Staff Dashboard', staff_info: req.user });
});

app.get('/api/games', async (req, res) => {
  try {
    const sql = `
            SELECT
                gi.inventory_id, g.game_id, g.game_name AS gameName,
                COALESCE(gs.style_name, 'Unknown Style') AS gameStyle,
                g.game_pic_path AS picPath, g.game_min_player AS minP,
                g.game_max_player AS maxP, g.game_time AS gTime,
                g.game_link_howto AS g_link, g.game_name AS gameGroup,
                gi.status AS status 
            FROM game_inventory gi
            JOIN game g ON gi.game_id = g.game_id
            LEFT JOIN game_style gs ON g.style_id = gs.style_id
            ORDER BY g.game_name, gi.inventory_id;
        `;
    const [results] = await con.query(sql);
    
    const gameList = results.map(row => ({
      inventory_id: row.inventory_id,
      game_id: row.game_id,
      gameName: row.gameName,
      gameStyle: row.gameStyle,
      picPath: row.picPath,
      status: row.status,
      minP: row.minP,
      maxP: row.maxP,
      gTime: row.gTime,
      g_link: row.g_link,
      gameGroup: row.gameGroup
    }));
    res.status(200).json(gameList);
  } catch (err) {
    console.error('🚨 Error fetching games:', err);
    res.status(500).json({ message: 'Failed to retrieve games', error: err.message });
  }
});

app.get('/api/status-summary', authenticateToken, async (req, res) => {
  try {
    const sql = `
        SELECT
          SUM(CASE WHEN status = 'Borrowing' THEN 1 ELSE 0 END) AS borrowed,
          SUM(CASE WHEN status = 'Available' THEN 1 ELSE 0 END) AS available,
          SUM(CASE WHEN status = 'Disabled' THEN 1 ELSE 0 END) AS disabled
        FROM game_inventory;
    `;
    const [rows] = await con.query(sql);
    const data = rows[0];

    res.status(200).json({
      success: true,
      data: {
        borrowed: data.borrowed || 0,
        available: data.available || 0,
        disabled: data.disabled || 0,
      },
      user_role: req.user.role,
      lender_id: req.user.role === 'lender' ? req.user.user_id : null
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ----------
// STUDENT (BORROWER) ROUTES
// ----------

app.get('/borrow-history', authenticateToken, async (req, res) => {
    try {
        const borrowerId = req.user.user_id;
        const q = String(req.query.q || '').trim();
        const statusFilter = String(req.query.status || '').trim().toLowerCase();
        const limit = Math.min(Math.max(parseInt(req.query.limit || '100'), 1), 200);

        const sql = `
            SELECT
                b.borrow_id AS id, g.game_name AS game,
                CASE
                    WHEN b.status='approved'    THEN 'Approve'
                    WHEN b.status='disapproved' THEN 'Disapprove'
                    WHEN b.status='returned'    THEN 'Returned'
                    WHEN b.status='cancelled'   THEN 'Cancelled'
                    WHEN b.status='returning'   THEN 'Returning'
                    ELSE 'Pending'
                END AS status,
                uL.username AS approvedBy, uS.username AS returnedTo,
                DATE_FORMAT(b.from_date, '%d %b %Y') AS borrowedDate,
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
                    CAST(b.borrow_id AS CHAR) LIKE CONCAT('%', ?, '%')
                )
            ORDER BY b.from_date DESC LIMIT ?
        `;

        const params = [borrowerId];
        if (statusFilter) params.push(statusFilter);
        params.push(q, q, q, limit);

        const [rows] = await con.query(sql, params);
        res.status(200).json({ success: true, count: rows.length, items: rows });
    } catch (err) {
        console.error('[borrow-history] error:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get('/api/check-request/:user_id', async (req, res) => {
  const { user_id } = req.params;
  try {
    const sql = `
      SELECT b.borrow_id, b.status AS borrow_status, b.from_date, b.return_date,
      g.game_name, g.game_pic_path, g.game_link_howto, gi.status AS game_inventory_status
      FROM borrow b
      JOIN game g ON b.game_id = g.game_id
      JOIN game_inventory gi ON g.game_id = gi.game_id
      WHERE b.borrower_id = ? AND b.status IN ('pending', 'approved', 'returning')
      ORDER BY b.borrow_id DESC;
    `;
    const [results] = await con.query(sql, [user_id]);
    if (results.length === 0) return res.status(200).json({ message: 'ไม่พบคำขอยืม', data: [] });

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
    res.status(200).json({ message: 'Success', data: formatted });
  } catch (err) {
    res.status(500).json({ message: 'Error', error: err.message });
  }
});

app.put('/api/borrow/status/:borrowId', async (req, res) => {
  const { borrowId } = req.params;
  const { status } = req.body;

  if (!status || !['cancelled', 'returning'].includes(status.toLowerCase())) {
    return res.status(400).json({ message: 'Invalid status' });
  }

  try {
    const [result] = await con.query('UPDATE borrow SET status = ? WHERE borrow_id = ?', [status.toLowerCase(), borrowId]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Borrow ID not found' });
    res.status(200).json({ message: 'Updated successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error', error: err.message });
  }
});

app.post('/request-borrowing', async (req, res) => {
  const { game_id, student_id, start_date, end_date } = req.body;

  if (!game_id || !student_id || !start_date || !end_date) {
    return res.status(400).json({ message: 'Missing fields' });
  }

  try {
    const [active] = await con.query("SELECT borrow_id FROM borrow WHERE borrower_id = ? AND status IN ('pending', 'approved', 'returning')", [student_id]);
    if (active.length > 0) return res.status(409).json({ message: 'You already have an active request.' });

    const [result] = await con.query(
      'INSERT INTO borrow (borrower_id, game_id, from_date, return_date, status) VALUES (?, ?, ?, ?, ?)',
      [student_id, game_id, start_date, end_date, 'pending']
    );
    res.status(200).json({ message: 'Request created', borrow_id: result.insertId });
  } catch (err) {
    res.status(500).json({ message: 'Error', error: err.message });
  }
});

// ----------
// LENDER ROUTES (SECURED)
// ----------

// Lender: Approve/Disapprove
app.post('/api/borrow/approval/:borrowId', authenticateToken, async (req, res) => {
  const { borrowId } = req.params;
  const { status, reason } = req.body;

  const approverId = req.user.user_id; // ✅ ใช้ ID จาก Token
  const userRole = req.user.role;

  if (!['lender', 'staff'].includes(userRole)) {
      return res.status(403).json({ message: 'ไม่มีสิทธิ์ทำรายการนี้' });
  }

  if (!status || !['approved', 'disapproved'].includes(status.toLowerCase())) {
    return res.status(400).json({ message: 'Invalid status' });
  }

  const updateStatus = status.toLowerCase();
  const updateField = userRole === 'lender' ? 'lender_id' : 'staff_id';

  if (updateStatus === 'disapproved' && !reason) {
    return res.status(400).json({ message: 'Reason required for disapproval' });
  }

  try {
    const [info] = await con.query('SELECT status FROM borrow WHERE borrow_id = ?', [borrowId]);
    if (info.length === 0 || info[0].status !== 'pending') {
      return res.status(404).json({ message: 'Borrow request not found or not pending' });
    }

    let sql, params;
    if (updateStatus === 'approved') {
      sql = `UPDATE borrow SET status = ?, ${updateField} = ? WHERE borrow_id = ?`;
      params = [updateStatus, approverId, borrowId];
    } else {
      sql = `UPDATE borrow SET status = ?, ${updateField} = ?, reason = ? WHERE borrow_id = ?`;
      params = [updateStatus, approverId, reason, borrowId];
    }

    await con.query(sql, params);
    res.status(200).json({ message: `Updated to ${updateStatus}`, action_by: approverId });

  } catch (err) {
    res.status(500).json({ message: 'Error', error: err.message });
  }
});

// Lender: Get pending list
// ★ FIXED: เพิ่ม authenticateToken เพื่อป้องกันคนนอก
app.get('/lender/pending', authenticateToken, authorizeRole(['lender']), async (req, res) => {
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

// ❌ REMOVED: Route /lender/approve/:id และ /lender/disapprove/:id ที่ไม่ปลอดภัย (Legacy Code) ถูกลบออกแล้ว

// Lender: Get History
app.get('/HistoryLenderPage', authenticateToken, authorizeRole(['lender']), async (req, res) => {
    try {
        const lenderId = req.user.user_id;
        const q = String(req.query.q || '').trim();
        const statusFilter = String(req.query.status || '').trim().toLowerCase();
        const limit = Math.min(Math.max(parseInt(req.query.limit || '100'), 1), 200);

        const sql = `
            SELECT
                b.borrow_id AS id, g.game_name AS game,
                CASE
                    WHEN b.status='approved'    THEN 'Approve'
                    WHEN b.status='disapproved' THEN 'Disapprove'
                    WHEN b.status='returned'    THEN 'Returned'
                    WHEN b.status='cancelled'   THEN 'Cancelled'
                    WHEN b.status='returning'   THEN 'Returning'
                    ELSE 'Pending'
                END AS status,
                uL.username AS borrowedBy, uS.username AS returnedTo,
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
                    CAST(b.borrow_id AS CHAR) LIKE CONCAT('%', ?, '%')
                )
            ORDER BY b.from_date DESC LIMIT ?
        `;
        const params = [lenderId];
        if (statusFilter) params.push(statusFilter);
        params.push(q, q, q, limit);

        const [rows] = await con.query(sql, params);
        res.json({ success: true, count: rows.length, items: rows });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ----------
// STAFF ROUTES
// ----------

app.get('/api/staff/returning-list', authenticateToken, authorizeRole(['staff']), async (req, res) => {
  try {
    const sql = `
      SELECT b.borrow_id, g.game_name, g.game_pic_path, u.username AS borrower_name, b.from_date, b.return_date
      FROM borrow b
      JOIN game g ON b.game_id = g.game_id
      JOIN users u ON b.borrower_id = u.user_id
      WHERE b.status = 'returning'
      ORDER BY b.from_date DESC;
    `;
    const [rows] = await con.query(sql);
    res.status(200).json({ message: 'Returning list loaded', data: rows });
  } catch (err) {
    res.status(500).json({ message: 'Error', error: err.message });
  }
});

app.put('/api/staff/confirm-return/:borrowId', authenticateToken, authorizeRole(['staff']), async (req, res) => {
  const { borrowId } = req.params;
  try {
    await con.query(
      `UPDATE borrow SET status = 'returned', staff_id = ? WHERE borrow_id = ? AND status = 'returning'`,
      [req.user.user_id, borrowId]
    );
    await con.query(
      `UPDATE game_inventory gi JOIN borrow b ON gi.game_id = b.game_id SET gi.status = 'Available' WHERE b.borrow_id = ?`,
      [borrowId]
    );
    res.status(200).json({ message: 'Return confirmed' });
  } catch (err) {
    res.status(500).json({ message: 'Error', error: err.message });
  }
});

app.get('/staff/games', async (req, res) => {
  try {
    const sql = `
      SELECT g.game_id, g.game_name, g.style_id, g.game_time, g.game_min_player, g.game_max_player, g.game_link_howto, g.game_pic_path,
      COUNT(*) as total_copies,
      SUM(CASE WHEN gi.status = 'Available' THEN 1 ELSE 0 END) as enabled_count,
      SUM(CASE WHEN gi.status = 'Disabled' THEN 1 ELSE 0 END) as disabled_count,
      GROUP_CONCAT(gi.inventory_id) as item_ids,
      GROUP_CONCAT(gi.status) as item_statuses
      FROM game g JOIN game_inventory gi ON g.game_id = gi.game_id
      GROUP BY g.game_id, g.game_name, g.style_id, g.game_time, g.game_min_player, g.game_max_player, g.game_link_howto, g.game_pic_path
      ORDER BY g.game_name
    `;
    const [rows] = await con.query(sql);
    const games = rows.map(row => ({
      gameName: row.game_name, styleId: row.style_id, gameTime: row.game_time,
      minPlayers: row.game_min_player, maxPlayers: row.game_max_player,
      howToLink: row.game_link_howto, picPath: row.game_pic_path,
      totalCopies: parseInt(row.total_copies),
      enabledCount: parseInt(row.enabled_count || 0),
      disabledCount: parseInt(row.disabled_count || 0),
      itemIds: row.item_ids ? row.item_ids.split(',').map(id => id.trim()) : [],
      itemStatuses: row.item_statuses ? row.item_statuses.split(',').map(s => s.trim()) : []
    }));
    res.json({ success: true, games });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.put('/staff/game/status/:inventoryId', authenticateToken, authorizeRole(['staff']), async (req, res) => {
  const { inventoryId } = req.params;
  const { status } = req.body;
  if (!['Available', 'Disabled', 'Borrowing'].includes(status)) return res.status(400).json({ success: false });

  try {
    const [result] = await con.query('UPDATE game_inventory SET status = ? WHERE inventory_id = ?', [status, inventoryId]);
    if (result.affectedRows === 0) return res.status(404).json({ success: false });
    res.json({ success: true, new_status: status });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.put('/api/staff/game/:gameId', authenticateToken, authorizeRole(['staff']), async (req, res) => {
  const { gameId } = req.params;
  const { game_name, style_id, game_time, game_min_player, game_max_player, game_link_howto, game_pic_path } = req.body;

  try {
    await con.query(
      `UPDATE game SET game_name=?, style_id=?, game_time=?, game_min_player=?, game_max_player=?, game_link_howto=?, game_pic_path=COALESCE(?, game_pic_path) WHERE game_id=?`,
      [game_name, style_id, game_time, game_min_player, game_max_player, game_link_howto, game_pic_path, gameId]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get('/StaffHistory', authenticateToken, authorizeRole(['staff']), async (req, res) => {
    try {
        const q = String(req.query.q || '').trim();
        const statusFilter = String(req.query.status || '').trim().toLowerCase();
        const limit = 200;

        const sql = `
            SELECT b.borrow_id AS id, g.game_name AS game,
            CASE
                WHEN b.status='approved'    THEN 'Approve'
                WHEN b.status='disapproved' THEN 'Disapprove'
                WHEN b.status='returned'    THEN 'Returned'
                WHEN b.status='cancelled'   THEN 'Cancelled'
                WHEN b.status='returning'   THEN 'Returning'
                ELSE 'Pending'
            END AS status,
            uBorrow.username AS borrowedBy, uLender.username AS lenderName, uStaff.username AS staffName,
            DATE_FORMAT(b.from_date, '%d %b %Y') AS borrowedDate,
            DATE_FORMAT(b.return_date, '%d %b %Y') AS returnedDate,
            b.reason AS reason
            FROM borrow b
            JOIN game g ON g.game_id = b.game_id
            LEFT JOIN users uBorrow ON uBorrow.user_id = b.borrower_id
            LEFT JOIN users uLender ON uLender.user_id = b.lender_id
            LEFT JOIN users uStaff ON uStaff.user_id = b.staff_id
            WHERE b.status IN ('approved', 'disapproved', 'returned', 'cancelled', 'returning', 'pending')
            ${statusFilter ? 'AND LOWER(b.status) = ?' : ''}
            AND (
                ? = '' OR LOWER(g.game_name) LIKE CONCAT('%', LOWER(?), '%') OR CAST(b.borrow_id AS CHAR) LIKE CONCAT('%', ?, '%')
            )
            ORDER BY b.from_date DESC LIMIT ?
        `;
        const params = [];
        if (statusFilter) params.push(statusFilter);
        params.push(q, q, q, limit);

        const [rows] = await con.query(sql, params);
        res.json({ success: true, count: rows.length, items: rows });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post("/api/add_game", authenticateToken, authorizeRole(["staff"]), upload.single("game_image"), async (req, res) => {
    let connection;
    try {
      if (!req.file) return res.status(400).json({ success: false, message: "กรุณาอัปโหลดรูปภาพ" });
      const picPath = "image/" + req.file.filename;
      const { game_name, game_style, game_time, min_P, max_P, game_how2 } = req.body;

      if (!game_name || !game_style || !game_time) return res.status(400).json({ success: false, message: "กรอกข้อมูลไม่ครบ" });

      connection = await con.getConnection();
      await connection.beginTransaction();

      let style_id = null;
      const [styleRows] = await connection.query("SELECT style_id FROM game_style WHERE style_name = ?", [game_style]);
      if (styleRows.length > 0) {
        style_id = styleRows[0].style_id;
      } else {
        const [insertStyle] = await connection.query("INSERT INTO game_style (style_name) VALUES (?)", [game_style]);
        style_id = insertStyle.insertId;
      }

      const [insertResult] = await connection.query(
        `INSERT INTO game (game_name, style_id, game_time, game_min_player, game_max_player, game_link_howto, game_pic_path) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [game_name, style_id, game_time, min_P, max_P, game_how2, picPath]
      );

      await connection.commit();
      res.status(201).json({ success: true, message: "เพิ่มเกมสำเร็จ!" });

    } catch (error) {
      if (connection) await connection.rollback();
      if (req.file) fs.unlinkSync(req.file.path);
      res.status(500).json({ success: false, message: "Error", error: error.message });
    } finally {
      if (connection) connection.release();
    }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log('Server is running at ' + PORT);
});