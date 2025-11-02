const express = require('express');
const app = express();


app.use(express.json());
app.use(express.urlencoded({ extended: true }));


const con = require('./db');
// ---------- image in server local storage ---------
app.use('/image', express.static('images'));

// ---------- authentication ---------


// ---------- dashboard ---------
app.get('/api/games', async (req, res) => {
  console.log('Received GET request for /api/games');
  try {
    const sql = `
      SELECT
          g.game_id,
          g.game_name AS gameName,
          COALESCE(gs.style_name, 'Unknown Style') AS gameStyle,
          g.game_pic_path AS picPath,
          g.game_min_player AS minP,
          g.game_max_player AS maxP,
          g.game_time AS gTime,
          g.game_link_howto AS g_link,
          g.game_name AS gameGroup,
          gi.status AS status  -- ✅ Real status from game_inventory
      FROM
          game g
      LEFT JOIN game_style gs 
          ON g.style_id = gs.style_id
      LEFT JOIN game_inventory gi 
          ON g.game_id = gi.game_id
      ORDER BY g.game_name;
    `;

    // Execute the query
    const [results] = await con.query(sql);

    // Map to clean structure
    const gameList = results.map(row => ({
      game_id: row.game_id,
      gameName: row.gameName,
      gameStyle: row.gameStyle,
      picPath: row.picPath,
      status: row.status, // ✅ real-time game status
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


// ---------- borrow-history ---------


// ---------- Check request ---------


// ---------- Request borrowing ---------




// ---------- Server starts here ---------
const PORT = 3000;
app.listen(PORT, () => {
    console.log('Server is running at ' + PORT);
});
