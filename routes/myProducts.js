const express = require("express");
const router = express.Router();
const pool = require("../db");
const { authenticateUser } = require("../middleware/auth");

router.get("/", authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await pool.query(
      "SELECT * FROM products WHERE user_id = $1",
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching user's products:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
