const express = require("express");
const cors = require("cors");
const pool = require("./db");
require("dotenv").config();
const http = require("http");
const { Server } = require("socket.io");
const orderRoutes = require("./routes/orders");

const allowedOrigins = [
  "http://localhost:3000",
  "https://mongolian-agriculture-trade.vercel.app",
  "https://www.agromongol.store",
  "https://agromongol.store"
];

const app = express();
const server = http.createServer(app);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("CORS Not Allowed"));
  },
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());

app.get("/api/ping", (req, res) => {
  res.status(200).json({ message: "pong" });
});

app.use("/api/auth", require("./routes/auth"));
app.use("/api/products", require("./routes/products"));
app.use("/api/saved-products", require("./routes/savedProducts"));
app.use("/api/contact", require("./routes/contact"));
app.use("/api/my-products", require("./routes/myProducts"));
app.use("/api/chat", require("./routes/chat"));
app.use("/api/orders", orderRoutes);

app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"]
  }
});

const connectedUsers = new Map();

io.on("connection", (socket) => {
  console.log(`[${new Date().toISOString()}] ✅ New user connected: ${socket.id}`);

  socket.on("registerUser", (userId) => {
    connectedUsers.set(userId, socket.id);
    console.log(`[${new Date().toISOString()}] 📍 Registered user ${userId} to socket ${socket.id}`);
  });

  socket.on("joinRoom", ({ roomId }) => {
    socket.join(roomId);
    console.log(`[${new Date().toISOString()}] 🔗 User ${socket.id} joined room: ${roomId}`);
  });

  socket.on("send_message", async (data) => {
    const { userId, username, message, roomId, recipientId } = data;

    const newMessage = {
      userId,
      username,
      message,
      roomId,
      recipientId,
      createdAt: new Date()
    };

    try {
      await pool.query(
        "INSERT INTO messages (user_id, username, message, room_id, recipient_id, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
        [userId, username, message, roomId, recipientId, new Date()]
      );

      io.to(roomId).emit("receive_message", newMessage);

      const recipientSocketId = connectedUsers.get(recipientId);
      if (recipientSocketId && !Array.from(socket.rooms).includes(roomId)) {
        io.to(recipientSocketId).emit("newMessageNotification", {
          fromUserId: userId,
          fromUsername: username,
          message,
          roomId
        });
        console.log(`[${new Date().toISOString()}] 🔔 Notified user ${recipientId} (socket: ${recipientSocketId}) about new message`);
      }
    } catch (err) {
      console.error(`[${new Date().toISOString()}] ❌ Error saving message:`, err);
    }
  });

  socket.on("disconnect", () => {
    for (let [userId, sockId] of connectedUsers.entries()) {
      if (sockId === socket.id) {
        connectedUsers.delete(userId);
        console.log(`[${new Date().toISOString()}] ❌ User ${userId} disconnected and removed from map`);
        break;
      }
    }
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server with Socket.IO running on http://localhost:${PORT}`);
});
