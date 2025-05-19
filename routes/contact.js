const express = require("express");
const nodemailer = require("nodemailer");
require("dotenv").config();

const router = express.Router();

router.post("/", async (req, res) => {
  const { name, email, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ message: "Бүх талбарыг бөглөнө үү." });
  }

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: email,
    to: process.env.EMAIL_USER,
    subject: `Шинэ санал хүсэлт - ${name}`,
    text: `Илгээгч: ${name} (${email})\n\n${message}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ message: "Санал хүсэлт амжилттай илгээгдлээ!" });
  } catch (error) {
    console.error("Error sending email:", error);
    res.status(500).json({ message: "Имэйл илгээхэд алдаа гарлаа." });
  }
});

module.exports = router;
