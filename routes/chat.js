const express = require("express");
const router = express.Router();
const pool = require("../db");

router.get("/messages/:conversationId", async (req, res) => {
  const { conversationId } = req.params;

  try {
    const result = await pool.query(
      "SELECT * FROM messages WHERE conversation_id = $1 ORDER BY created_at ASC",
      [conversationId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching messages:", err);
    res.status(500).json({ error: "Something went wrong" });
  }
});

router.get("/users", async (req, res) => {
  const { userId } = req.query;

  try {
    const result = await pool.query(`
      SELECT DISTINCT 
        CASE 
          WHEN c.buyer_id = $1 THEN c.seller_id 
          ELSE c.buyer_id 
        END AS other_user_id,
        u.name AS other_user_name
      FROM conversations c
      JOIN users u ON u.id = 
        CASE 
          WHEN c.buyer_id = $1 THEN c.seller_id 
          ELSE c.buyer_id 
        END
      WHERE c.buyer_id = $1 OR c.seller_id = $1
    `, [userId]);

    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching chat users:", err);
    res.status(500).json({ error: "Failed to get chat users" });
  }
});

router.get("/conversations/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    const result = await pool.query(`
      SELECT 
        c.*,
        p.title AS product_title,
        u.name AS other_user_name,
        (
          SELECT COUNT(*)
          FROM messages m
          WHERE m.conversation_id = c.id
            AND m.sender_id != $1
            AND m.is_read = false
        ) AS unread_count
      FROM conversations c
      JOIN products p ON c.product_id = p.id
      JOIN users u ON u.id = (
        CASE 
          WHEN c.buyer_id = $1 THEN c.seller_id
          ELSE c.buyer_id
        END
      )
      WHERE c.buyer_id = $1 OR c.seller_id = $1
    `, [userId]);

    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching chat list:", err);
    res.status(500).json({ error: "Failed to fetch conversations" });
  }
});


router.post("/start", async (req, res) => {
  const { product_id, buyer_id, seller_id } = req.body;

  try {
    let convo = await pool.query(`
      SELECT * FROM conversations 
      WHERE product_id = $1 AND buyer_id = $2 AND seller_id = $3
    `, [product_id, buyer_id, seller_id]);

    if (convo.rows.length === 0) {
      const newConvo = await pool.query(`
        INSERT INTO conversations (product_id, buyer_id, seller_id) 
        VALUES ($1, $2, $3) RETURNING *
      `, [product_id, buyer_id, seller_id]);
      convo = newConvo;
    }

    const otherUserId = buyer_id === seller_id ? buyer_id : seller_id;
    const otherUserRes = await pool.query(`
      SELECT name FROM users WHERE id = $1
    `, [otherUserId]);

    res.json({
      ...convo.rows[0],
      other_user_name: otherUserRes.rows[0]?.name || "Хэрэглэгч",
    });
  } catch (error) {
    console.error("Start chat error:", error);
    res.status(500).json({ error: "Chat эхлүүлэхэд алдаа гарлаа." });
  }
});

router.post("/send", async (req, res) => {
  const { conversation_id, sender_id, message } = req.body;

  try {
    const result = await pool.query(`
      INSERT INTO messages (conversation_id, sender_id, message, created_at)
      VALUES ($1, $2, $3, NOW())
      RETURNING *
    `, [conversation_id, sender_id, message]);

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error sending message:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

router.patch("/read", async (req, res) => {
  const { conversation_id, user_id } = req.body;

  try {
    await pool.query(`
      UPDATE messages
      SET is_read = true
      WHERE conversation_id = $1
        AND sender_id != $2
        AND is_read = false
    `, [conversation_id, user_id]);

    res.json({ message: "Messages marked as read." });
  } catch (err) {
    console.error("Error marking messages as read:", err);
    res.status(500).json({ error: "Failed to mark messages as read" });
  }
});


module.exports = router;
