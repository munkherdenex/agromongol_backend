const express = require("express");
const router = express.Router();
const pool = require("../db");

router.get("/:user_id", async (req, res) => {
  const { user_id } = req.params;

  try {
    const savedProducts = await pool.query(
      `
      SELECT 
        products.*, 
        users.name AS poster_name 
      FROM saved_products 
      JOIN products ON saved_products.product_id = products.id 
      JOIN users ON products.user_id = users.id 
      WHERE saved_products.user_id = $1
      `,
      [user_id]
    );
    res.json(savedProducts.rows);
  } catch (error) {
    console.error("Error fetching saved products:", error);
    res.status(500).send("Server error");
  }
});


router.post("/", async (req, res) => {
  try {
    const { user_id, product_id } = req.body;
    const result = await pool.query(
      "INSERT INTO saved_products (user_id, product_id) VALUES ($1, $2) RETURNING *",
      [user_id, product_id]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error saving product:", error);
    res.status(500).send("Server error");
  }
});

router.delete("/:user_id/:product_id", async (req, res) => {
  try {
    const { user_id, product_id } = req.params;
    const result = await pool.query(
      "DELETE FROM saved_products WHERE user_id = $1 AND product_id = $2 RETURNING *",
      [user_id, product_id]
    );

    if (result.rowCount === 0) {
      return res.status(404).send("Saved product not found");
    }

    res.send("Saved product removed");
  } catch (error) {
    console.error("Error removing saved product:", error);
    res.status(500).send("Server error");
  }
});




module.exports = router;
