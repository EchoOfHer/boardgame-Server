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

// ---------- MIDDLEWARE ----------
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token not provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('❌ JWT Verification Failed:', err.name, err.message);
            let errorMessage = 'Token is invalid';
            if (err.name === 'TokenExpiredError') errorMessage = 'Token expired. Please log in again.';
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

// ---------- AUTH ROUTES ----------
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  const role = 'borrower';
  if (!username || !password) return res.status(400).json({ message: 'Incomplete data' });

  try {
    const [existing] = await con.query('SELECT user_id FROM users WHERE username = ?', [username]);
    if (existing.length > 0) return res.status(409).json({ message: 'Username exists' });

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const [result] = await con.query('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', [username, hash, role]);
    res.status(201).json({ message: 'Registered', user_id: result.insertId });
  } catch (error) {
    res.status(500).json({ message: 'Error', error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Incomplete data' });

  try {
    const [users] = await con.query('SELECT * FROM users WHERE username = ?', [username]);
    if (users.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ user_id: user.user_id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    let landingPage = 'student.main';
    if (user.role === 'lender') landingPage = 'lender.main';
    else if (user.role === 'staff') landingPage = 'staff.main';

    res.json({ message: 'Login success', token, user_id: user.user_id, username: user.username, role: user.role, landingPage });
  } catch (error) {
    res.status(500).json({ message: 'Error', error: error.message });
  }
});

app.post('/api/logout', (req, res) => res.status(200).json({ message: 'Logout success' }));

app.get('/api/username', function (req, res) {
    let token = req.headers['authorization'];
    if (!token) return res.status(400).send('No token');
    if (token.startsWith('Bearer ')) token = token.slice(7);
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(400).send('Incorrect token');
        res.send(decoded);
    });
});

// ---------- GENERAL ROUTES ----------
app.get('/api/dashboard', authenticateToken, (req, res) => {
  res.json({ message: `Dashboard for ${req.user.role}`, user_info: req.user });
});

app.get('/api/game_styles', async (req, res) => {
  try {
    const [rows] = await con.query('SELECT style_id, style_name FROM game_style ORDER BY style_name');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching styles', error: err.message });
  }
});

// ★ FIXED: เพิ่ม gameId ใน response
app.get('/api/games', async (req, res) => {
  try {
    const sql = `
        SELECT gi.inventory_id, g.game_id, g.game_name, COALESCE(gs.style_name, 'Unknown') as gameStyle,
        g.game_pic_path, g.game_min_player, g.game_max_player, g.game_time, g.game_link_howto, gi.status 
        FROM game_inventory gi 
        JOIN game g ON gi.game_id = g.game_id 
        LEFT JOIN game_style gs ON g.style_id = gs.style_id
        ORDER BY g.game_name, gi.inventory_id`;
    const [results] = await con.query(sql);
    const list = results.map(row => ({
      inventory_id: row.inventory_id, 
      game_id: row.game_id, 
      gameName: row.game_name,
      gameStyle: row.gameStyle, 
      picPath: row.game_pic_path, 
      status: row.status,
      minP: row.game_min_player, 
      maxP: row.game_max_player, 
      gTime: row.game_time,
      g_link: row.game_link_howto, 
      gameGroup: row.game_name
    }));
    res.json(list);
  } catch (err) {
    res.status(500).json({ message: 'Error', error: err.message });
  }
});

app.get('/api/status-summary', authenticateToken, async (req, res) => {
  try {
    const sql = `SELECT 
      SUM(CASE WHEN status='Borrowing' THEN 1 ELSE 0 END) as borrowed,
      SUM(CASE WHEN status='Available' THEN 1 ELSE 0 END) as available,
      SUM(CASE WHEN status='Disabled' THEN 1 ELSE 0 END) as disabled
      FROM game_inventory`;
    const [rows] = await con.query(sql);
    res.json({ success: true, data: rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ---------- STUDENT ROUTES ----------
app.get('/borrow-history', authenticateToken, async (req, res) => {
    try {
        const borrowerId = req.user.user_id;
        const q = String(req.query.q || '').trim();
        const statusFilter = String(req.query.status || '').trim().toLowerCase();
        const limit = Math.min(Math.max(parseInt(req.query.limit || '100'), 1), 200);
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
                AND (? = '' OR LOWER(g.game_name) LIKE CONCAT('%', LOWER(?), '%') OR CAST(b.borrow_id AS CHAR) LIKE CONCAT('%', ?, '%'))
            ORDER BY b.from_date DESC LIMIT ?`;
        const params = [borrowerId];
        if (statusFilter) params.push(statusFilter);
        params.push(q, q, q, limit);
        const [rows] = await con.query(sql, params);
        res.status(200).json({ success: true, count: rows.length, items: rows });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get('/api/check-request/:user_id', authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  
  // Security Check: ห้ามดูข้อมูลคนอื่น (ยกเว้น Staff)
  if (req.user.user_id != user_id && req.user.role !== 'staff') {
      return res.status(403).json({ message: 'Unauthorized access to other user data' });
  }

  try {
    const sql = `
      SELECT b.borrow_id, b.status AS borrow_status, b.from_date, b.return_date,
      g.game_name, g.game_pic_path, g.game_link_howto, gi.status AS game_inventory_status
      FROM borrow b JOIN game g ON b.game_id = g.game_id JOIN game_inventory gi ON g.game_id = gi.game_id
      WHERE b.borrower_id = ? AND b.status IN ('pending', 'approved', 'returning') ORDER BY b.borrow_id DESC`;
    const [results] = await con.query(sql, [user_id]);
    if (results.length === 0) return res.status(200).json({ message: 'ไม่พบคำขอยืม', data: [] });
    
    // ... (ส่วน mapping data เหมือนเดิม) ...
    const formatted = results.map(item => ({
      borrow_id: item.borrow_id, game_name: item.game_name, pic_path: item.game_pic_path,
      from_date: item.from_date, return_date: item.return_date, borrow_status: item.borrow_status,
      game_inventory_status: item.game_inventory_status, howto_link: item.game_link_howto
    }));

    res.status(200).json({ message: 'Success', data: formatted });
  } catch (err) {
    res.status(500).json({ message: 'Error', error: err.message });
  }
});

app.put('/api/borrow/status/:borrowId', authenticateToken, async (req, res) => {
  const { borrowId } = req.params;
  const { status } = req.body;
  const userId = req.user.user_id; // เอา ID คนกดมาจาก Token

  if (!status || !['cancelled', 'returning'].includes(status.toLowerCase())) return res.status(400).json({ message: 'Invalid status' });

  try {
    // Security Check: ตรวจสอบว่า Borrow ID นี้เป็นของ User คนนี้จริงๆ หรือไม่
    const [checkOwner] = await con.query('SELECT * FROM borrow WHERE borrow_id = ? AND borrower_id = ?', [borrowId, userId]);
    if (checkOwner.length === 0 && req.user.role !== 'staff') {
        return res.status(403).json({ message: 'You do not have permission to modify this request' });
    }

    const [result] = await con.query('UPDATE borrow SET status = ? WHERE borrow_id = ?', [status.toLowerCase(), borrowId]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Borrow ID not found' });
    res.status(200).json({ message: 'Updated successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error', error: err.message });
  }
});

app.post('/request-borrowing', authenticateToken, async (req, res) => {
  // ไม่รับ student_id จาก body แล้ว ให้ใช้ req.user.user_id แทน
  const { game_id, start_date, end_date } = req.body;
  const student_id = req.user.user_id; // ปลอดภัยกว่า

  if (!game_id || !start_date || !end_date) return res.status(400).json({ message: 'Missing fields' });
  
  try {
    const [active] = await con.query("SELECT borrow_id FROM borrow WHERE borrower_id = ? AND status IN ('pending', 'approved', 'returning')", [student_id]);
    if (active.length > 0) return res.status(409).json({ message: 'Active request exists' });
    
    const [result] = await con.query(
      'INSERT INTO borrow (borrower_id, game_id, from_date, return_date, status) VALUES (?, ?, ?, ?, ?)',
      [student_id, game_id, start_date, end_date, 'pending']
    );
    res.status(200).json({ message: 'Request created', borrow_id: result.insertId });
  } catch (err) {
    res.status(500).json({ message: 'Error', error: err.message });
  }
});
// ---------- LENDER ROUTES ----------
app.post('/api/borrow/approval/:borrowId', authenticateToken, async (req, res) => {
  const { borrowId } = req.params;
  const { status, reason } = req.body;
  const approverId = req.user.user_id;
  const userRole = req.user.role;
  if (!['lender', 'staff'].includes(userRole)) return res.status(403).json({ message: 'No permission' });
  if (!status || !['approved', 'disapproved'].includes(status.toLowerCase())) return res.status(400).json({ message: 'Invalid status' });
  const updateStatus = status.toLowerCase();
  const updateField = userRole === 'lender' ? 'lender_id' : 'staff_id';
  if (updateStatus === 'disapproved' && !reason) return res.status(400).json({ message: 'Reason required' });

  try {
    const [info] = await con.query('SELECT status FROM borrow WHERE borrow_id = ?', [borrowId]);
    if (info.length === 0 || info[0].status !== 'pending') return res.status(404).json({ message: 'Invalid request' });
    let sql = `UPDATE borrow SET status = ?, ${updateField} = ?`;
    let params = [updateStatus, approverId];
    if (updateStatus === 'disapproved') { sql += `, reason = ?`; params.push(reason); }
    sql += ` WHERE borrow_id = ?`;
    params.push(borrowId);
    await con.query(sql, params);
    res.status(200).json({ message: `Updated to ${updateStatus}`, action_by: approverId });
  } catch (err) {
    res.status(500).json({ message: 'Error', error: err.message });
  }
});

app.get('/lender/pending', authenticateToken, authorizeRole(['lender']), async (req, res) => {
  const sql = `SELECT b.borrow_id AS id, g.game_name, g.game_pic_path, u.username AS borrower_name, b.from_date, b.return_date 
               FROM borrow b LEFT JOIN game g ON b.game_id = g.game_id LEFT JOIN users u ON b.borrower_id = u.user_id 
               WHERE b.status = 'pending' ORDER BY b.from_date ASC`;
  try { const [rows] = await con.query(sql); res.json(rows); } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/HistoryLenderPage', authenticateToken, authorizeRole(['lender']), async (req, res) => {
    try {
        const lenderId = req.user.user_id;
        const q = String(req.query.q || '').trim();
        const statusFilter = String(req.query.status || '').trim().toLowerCase();
        const limit = 200;
        const sql = `SELECT b.borrow_id AS id, g.game_name AS game,
            CASE WHEN b.status='approved' THEN 'Approve' WHEN b.status='disapproved' THEN 'Disapprove' WHEN b.status='returned' THEN 'Returned' WHEN b.status='cancelled' THEN 'Cancelled' WHEN b.status='returning' THEN 'Returning' ELSE 'Pending' END AS status,
            uL.username AS borrowedBy, uS.username AS returnedTo, DATE_FORMAT(b.from_date, '%d %b %Y') AS borrowedDate, DATE_FORMAT(b.return_date, '%d %b %Y') AS returnedDate, b.reason AS reason
            FROM borrow b JOIN game g ON g.game_id = b.game_id LEFT JOIN users uL ON uL.user_id = b.borrower_id LEFT JOIN users uS ON uS.user_id = b.staff_id
            WHERE b.lender_id = ? AND b.status IN ('approved', 'disapproved', 'returned', 'cancelled', 'returning')
            ${statusFilter ? 'AND LOWER(b.status) = ?' : ''} AND (? = '' OR LOWER(g.game_name) LIKE CONCAT('%', LOWER(?), '%') OR CAST(b.borrow_id AS CHAR) LIKE CONCAT('%', ?, '%'))
            ORDER BY b.from_date DESC LIMIT ?`;
        const params = [lenderId];
        if (statusFilter) params.push(statusFilter);
        params.push(q, q, q, limit);
        const [rows] = await con.query(sql, params);
        res.json({ success: true, count: rows.length, items: rows });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ---------- STAFF ROUTES ----------
app.get('/api/staff/returning-list', authenticateToken, authorizeRole(['staff']), async (req, res) => {
  try {
    const sql = `SELECT b.borrow_id, g.game_name, g.game_pic_path, u.username AS borrower_name, b.from_date, b.return_date
      FROM borrow b JOIN game g ON b.game_id = g.game_id JOIN users u ON b.borrower_id = u.user_id WHERE b.status = 'returning' ORDER BY b.from_date DESC`;
    const [rows] = await con.query(sql);
    res.status(200).json({ message: 'Returning list loaded', data: rows });
  } catch (err) { res.status(500).json({ message: 'Error', error: err.message }); }
});

app.put('/api/staff/confirm-return/:borrowId', authenticateToken, authorizeRole(['staff']), async (req, res) => {
  const { borrowId } = req.params;
  try {
    await con.query(`UPDATE borrow SET status = 'returned', staff_id = ? WHERE borrow_id = ? AND status = 'returning'`, [req.user.user_id, borrowId]);
    await con.query(`UPDATE game_inventory gi JOIN borrow b ON gi.game_id = b.game_id SET gi.status = 'Available' WHERE b.borrow_id = ?`, [borrowId]);
    res.status(200).json({ message: 'Return confirmed' });
  } catch (err) { res.status(500).json({ message: 'Error', error: err.message }); }
});

// ★ FIXED: Staff Get Games (เพิ่ม gameId ใน response เพื่อใช้ในการ Edit)
app.get('/staff/games', authenticateToken, authorizeRole(['staff']), async (req, res) => {
  try {
    const sql = `
      SELECT g.game_id, g.game_name, g.style_id, COALESCE(gs.style_name, 'Unknown') as style_name, 
      g.game_time, g.game_min_player, g.game_max_player, g.game_link_howto, g.game_pic_path,
      COUNT(*) as total_copies,
      SUM(CASE WHEN gi.status = 'Available' THEN 1 ELSE 0 END) as enabled_count,
      SUM(CASE WHEN gi.status = 'Disabled' THEN 1 ELSE 0 END) as disabled_count,
      GROUP_CONCAT(gi.inventory_id) as item_ids, GROUP_CONCAT(gi.status) as item_statuses
      FROM game g JOIN game_inventory gi ON g.game_id = gi.game_id
      LEFT JOIN game_style gs ON g.style_id = gs.style_id
      GROUP BY g.game_id ORDER BY g.game_name
    `;
    const [rows] = await con.query(sql);
    const games = rows.map(row => ({
      gameId: row.game_id, // ★ สำคัญ: ส่ง Game ID จริงๆ กลับไปด้วย (ไม่ใช่ Inventory ID)
      gameName: row.game_name, styleId: row.style_id, gameStyle: row.style_name,
      gameTime: row.game_time, minPlayers: row.game_min_player, maxPlayers: row.game_max_player,
      howToLink: row.game_link_howto, picPath: row.game_pic_path,
      totalCopies: parseInt(row.total_copies), enabledCount: parseInt(row.enabled_count || 0), disabledCount: parseInt(row.disabled_count || 0),
      itemIds: (row.item_ids||'').split(','), itemStatuses: (row.item_statuses||'').split(',')
    }));
    res.json({ success: true, games });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

app.put('/staff/game/status/:inventoryId', authenticateToken, authorizeRole(['staff']), async (req, res) => {
  const { inventoryId } = req.params;
  const { status } = req.body;
  if (!['Available', 'Disabled', 'Borrowing'].includes(status)) return res.status(400).json({ success: false });
  try {
    const [result] = await con.query('UPDATE game_inventory SET status = ? WHERE inventory_id = ?', [status, inventoryId]);
    if (result.affectedRows === 0) return res.status(404).json({ success: false });
    res.json({ success: true, new_status: status });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
});

// ✅ FIXED & SMART: Edit Game (Handles both Game ID and Inventory ID)
app.put('/api/staff/game/:gameId', authenticateToken, authorizeRole(['staff']), upload.single('game_image'), async (req, res) => {
    const { gameId } = req.params;
    const { game_name, style_id, game_time, game_min_player, game_max_player, game_link_howto } = req.body;

    console.log(`[Edit Game] Received Request for ID: ${gameId}`);

    let connection;
    try {
        connection = await con.getConnection();
        await connection.beginTransaction();

        let targetGameId = gameId;

        // 1. Try to find the game directly using the ID provided
        let [existingGame] = await connection.query("SELECT game_id, game_pic_path FROM game WHERE game_id = ?", [targetGameId]);

        // 2. If not found, assume the ID provided might be an INVENTORY ID and try to find the linked Game ID
        if (existingGame.length === 0) {
            console.log(`⚠️ ID ${gameId} not found in 'game' table. Checking 'game_inventory'...`);
            const [inventoryRow] = await connection.query("SELECT game_id FROM game_inventory WHERE inventory_id = ?", [gameId]);
            
            if (inventoryRow.length > 0) {
                targetGameId = inventoryRow[0].game_id;
                console.log(`✅ Found via Inventory! Swapping ID ${gameId} -> Real Game ID ${targetGameId}`);
                
                // Re-fetch the game data using the correct Game ID
                [existingGame] = await connection.query("SELECT game_id, game_pic_path FROM game WHERE game_id = ?", [targetGameId]);
            }
        }

        // 3. If STILL not found, then the ID is truly invalid
        if (existingGame.length === 0) {
            await connection.rollback();
            if (req.file) fs.unlinkSync(req.file.path);
            return res.status(404).json({ success: false, message: `Game ID not found in database (ID: ${gameId})` });
        }

        let currentPicPath = existingGame[0].game_pic_path;
        let finalPicPath = currentPicPath;

        // 4. Handle Image Replacement
        if (req.file) {
            console.log("📸 New image uploaded:", req.file.filename);
            finalPicPath = "image/" + req.file.filename;

            // Remove old image if it exists
            if (currentPicPath && !currentPicPath.includes('default') && fs.existsSync(currentPicPath)) {
                try {
                    fs.unlinkSync(currentPicPath);
                } catch (delErr) {
                    console.error("⚠️ Could not delete old image:", delErr.message);
                }
            }
        }

        // 5. Update the database using the CORRECT targetGameId
        const sql = `
            UPDATE game 
            SET game_name = ?, 
                style_id = ?, 
                game_time = ?, 
                game_min_player = ?, 
                game_max_player = ?, 
                game_link_howto = ?,
                game_pic_path = ?
            WHERE game_id = ?`;

        await connection.query(sql, [
            game_name, 
            style_id, 
            game_time, 
            game_min_player, 
            game_max_player, 
            game_link_howto, 
            finalPicPath, 
            targetGameId // Use the verified Game ID
        ]);

        await connection.commit();

        res.json({ 
            success: true, 
            message: 'Game updated successfully',
            new_pic_path: finalPicPath 
        });

    } catch (err) {
        if (connection) await connection.rollback();
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        console.error("Update Error:", err);
        res.status(500).json({ success: false, message: err.message });
    } finally {
        if (connection) connection.release();
    }
});

app.get('/StaffHistory', authenticateToken, authorizeRole(['staff']), async (req, res) => {
    try {
        const q = String(req.query.q || '').trim();
        const statusFilter = String(req.query.status || '').trim().toLowerCase();
        const limit = 200;
        const sql = `SELECT b.borrow_id AS id, g.game_name AS game,
            CASE WHEN b.status='approved' THEN 'Approve' WHEN b.status='disapproved' THEN 'Disapprove' WHEN b.status='returned' THEN 'Returned' WHEN b.status='cancelled' THEN 'Cancelled' WHEN b.status='returning' THEN 'Returning' ELSE 'Pending' END AS status,
            uBorrow.username AS borrowedBy, uLender.username AS lenderName, uStaff.username AS staffName,
            DATE_FORMAT(b.from_date, '%d %b %Y') AS borrowedDate, DATE_FORMAT(b.return_date, '%d %b %Y') AS returnedDate, b.reason AS reason
            FROM borrow b JOIN game g ON g.game_id = b.game_id LEFT JOIN users uBorrow ON uBorrow.user_id = b.borrower_id LEFT JOIN users uLender ON uLender.user_id = b.lender_id LEFT JOIN users uStaff ON uStaff.user_id = b.staff_id
            WHERE b.status IN ('approved', 'disapproved', 'returned', 'cancelled', 'returning', 'pending')
            ${statusFilter ? 'AND LOWER(b.status) = ?' : ''} AND (? = '' OR LOWER(g.game_name) LIKE CONCAT('%', LOWER(?), '%') OR CAST(b.borrow_id AS CHAR) LIKE CONCAT('%', ?, '%'))
            ORDER BY b.from_date DESC LIMIT ?`;
        const params = [];
        if (statusFilter) params.push(statusFilter);
        params.push(q, q, q, limit);
        const [rows] = await con.query(sql, params);
        res.json({ success: true, count: rows.length, items: rows });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
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
      if (styleRows.length > 0) { style_id = styleRows[0].style_id; } 
      else { const [insertStyle] = await connection.query("INSERT INTO game_style (style_name) VALUES (?)", [game_style]); style_id = insertStyle.insertId; }
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
    } finally { if (connection) connection.release(); }
});

const PORT = 3000;
app.listen(PORT, () => console.log('Server is running at ' + PORT));