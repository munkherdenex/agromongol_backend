const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cloudinary = require("../cloudinary");
const pool = require("../db");
require("dotenv").config();

const storage = multer.memoryStorage();
const upload = multer({ storage });

router.get("/", (req, res) => {
  res.send("Auth route working!");
});

router.post("/register", async (req, res) => {
  console.log("Received request:", req.body);  

  const { name, email, password } = req.body;
  try {
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const userExists = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ message: "User already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
      [name, email, hashedPassword]
    );

    console.log("User registered:", newUser.rows[0]); 
    res.json({ message: "User registered successfully", user: newUser.rows[0] });

  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).send("Server error");
  }
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (user.rows.length === 0) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.rows[0].password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.rows[0].id, name: user.rows[0].name, email: user.rows[0].email },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    console.log("🔐 Token signed with secret:", process.env.JWT_SECRET);

    res.json({ 
      token, 
      user: { id: user.rows[0].id, name: user.rows[0].name, email: user.rows[0].email } 
    });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).send("Server error");
  }
});

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token missing" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

router.get("/me", verifyToken, async (req, res) => {
  try {
    const { id } = req.user;
    const result = await pool.query(
      "SELECT id, name, email, created_at, profile_image_url FROM users WHERE id = $1",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error fetching user info:", err);
    res.status(500).json({ message: "Server error" });
  }
});

router.put("/update-profile", verifyToken, upload.single("profileImage"), async (req, res) => {
  const { name, email } = req.body;
  const userId = req.user.id;

  if (!name || !email) {
    return res.status(400).json({ message: "Нэр болон и-мэйл шаардлагатай" });
  }

  try {
    let profileImageUrl = null;

    // If file uploaded, upload it to Cloudinary
    if (req.file) {
      const streamUpload = () =>
        new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder: "agromongol_profiles" },
            (error, result) => {
              if (result) resolve(result);
              else reject(error);
            }
          );
          stream.end(req.file.buffer);
        });

      const result = await streamUpload();
      profileImageUrl = result.secure_url;
    }

    // Update DB with or without image
    const updateResult = await pool.query(
      `
      UPDATE users 
      SET name = $1, email = $2, profile_image_url = COALESCE($3, profile_image_url)
      WHERE id = $4 
      RETURNING id, name, email, created_at, profile_image_url
      `,
      [name, email, profileImageUrl, userId]
    );

    res.json({ message: "Амжилттай шинэчлэгдлээ", user: updateResult.rows[0] });
  } catch (err) {
    console.error("❌ Error updating profile:", err);
    res.status(500).json({ message: "Серверийн алдаа" });
  }
});


module.exports = router;
