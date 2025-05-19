const express = require("express");
const router = express.Router();
const pool = require("../db");
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("../cloudinary");
const { authenticateUser } = require('../middleware/auth');

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: "products",
    allowed_formats: ["jpg", "png", "jpeg"],
  },
});
const upload = multer({ storage });

router.get("/", async (req, res) => {
  try {
    console.log("🔥 GET /api/products called");
    const { search, category, minPrice, maxPrice, location } = req.query;
    console.log("Query params:", { search, category, minPrice, maxPrice, location });

    let query = `
      SELECT products.*, users.name AS poster_name
      FROM products
      JOIN users ON products.user_id = users.id
      WHERE 1=1
    `;
    let values = [];

    if (search) {
      query += ` AND LOWER(title) LIKE LOWER($${values.length + 1})`;
      values.push(`%${search}%`);
    }
    if (category) {
      query += ` AND category = $${values.length + 1}`;
      values.push(category);
    }
    if (minPrice) {
      query += ` AND price >= $${values.length + 1}`;
      values.push(minPrice);
    }
    if (maxPrice) {
      query += ` AND price <= $${values.length + 1}`;
      values.push(maxPrice);
    }
    if (location) {
      query += ` AND location = $${values.length + 1}`;
      values.push(location);
    }

    query += " ORDER BY created_at DESC";

    const { rows } = await pool.query(query, values);
    res.json(rows);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ message: "Server error" });
  }
});

router.get("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const product = await pool.query(
      `SELECT products.*, users.name AS poster_name, users.id AS seller_id
       FROM products 
       JOIN users ON products.user_id = users.id 
       WHERE products.id = $1`,
      [id]
    );
    if (product.rows.length === 0) return res.status(404).json({ message: "Product not found" });
    res.json(product.rows[0]);
  } catch (error) {
    console.error("Error fetching product details:", error);
    res.status(500).send("Server error");
  }
});

router.post("/", upload.single("image"), async (req, res) => {
  try {
    console.log("Received data:", req.body);
    console.log("Received file:", req.file);

    const { title, description, price, location, contact, user_id, quantity, unit  } = req.body;
    const imageUrl = req.file ? req.file.path : null;

    const result = await pool.query(
      "INSERT INTO products (title, description, price, location, image_url, contact, user_id, quantity, unit ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *",
      [title, description, price, location, imageUrl, contact, user_id, quantity, unit]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error adding product:", err.message);
    res.status(500).send("Server Error");
  }
});


router.delete("/:id", authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    const product = await pool.query("SELECT * FROM products WHERE id = $1", [id]);

    if (product.rows.length === 0) {
      return res.status(404).json({ message: "Product not found" });
    }

    if (product.rows[0].user_id !== userId) {
      return res.status(403).json({ message: "You are not authorized to delete this product" });
    }

    await pool.query("DELETE FROM products WHERE id = $1", [id]);

    res.json({ message: "Product deleted successfully" });
  } catch (err) {
    console.error("Error deleting product:", err.message);
    res.status(500).send("Server Error");
  }
});


module.exports = router;
