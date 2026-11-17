import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import mongoose from "mongoose";
import dotenv from "dotenv";
import dns from "dns";
import crypto from "crypto";
import { Chat } from "./models/Chat";
import { Call } from "./models/Call";

// Load Environment Variables
dotenv.config();

// Override local DNS to prevent MongoDB Atlas connection issues on Windows
dns.setServers(["8.8.8.8", "8.8.4.4"]);

const app = express();
const httpServer = createServer(app);

const allowedOrigins = process.env.CORS_ORIGINS 
  ? process.env.CORS_ORIGINS.split(",")
  : ["http://localhost:3000", "https://zline.vercel.app"];

const io = new Server(httpServer, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true,
  },
  transports: ["websocket", "polling"], // support websocket and fallback polling
});

// ─── Authentication Middleware ──────────────────────────────────────
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error("Authentication error: No token provided"));
  }
  
  try {
    const [userId, timestampStr, signature] = token.split(".");
    if (!userId || !timestampStr || !signature) {
      return next(new Error("Authentication error: Invalid token format"));
    }
    
    // Check expiry (5 minutes)
    const timestamp = parseInt(timestampStr, 10);
    if (Date.now() - timestamp > 5 * 60 * 1000) {
      return next(new Error("Authentication error: Token expired"));
    }
    
    const data = `${userId}:${timestampStr}`;
    const secret = process.env.NEXTAUTH_SECRET;
    if (!secret) {
      return next(new Error("Authentication error: Server secret missing"));
    }
    
    const expectedSignature = crypto.createHmac("sha256", secret).update(data).digest("hex");
    
    // Use timingSafeEqual to prevent timing attacks
    const sigBuf = Buffer.from(signature);
    const expectedSigBuf = Buffer.from(expectedSignature);
    
    if (sigBuf.length !== expectedSigBuf.length || !crypto.timingSafeEqual(sigBuf, expectedSigBuf)) {
      return next(new Error("Authentication error: Invalid signature"));
    }
    
    // Auth successful
    (socket as any).userId = userId;
    next();
  } catch (error) {
    next(new Error("Authentication error"));
  }
});

// App default route
app.get("/", (_, res) => {
  res.send("Zline Socket Server is running");
});

let dbPromise: Promise<typeof mongoose> | null = null;

// DB connection wrapper with promise caching to prevent startup race conditions
const connectDB = async () => {
  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  if (!dbPromise) {
    if (!process.env.MONGO_URI) {
      throw new Error("MONGO_URI environment variable is missing.");
    }
    dbPromise = mongoose.connect(process.env.MONGO_URI, {
      bufferCommands: false,
      family: 4,
    });
  }

  try {
    await dbPromise;
  } catch (err) {
    dbPromise = null;
    throw err;
  }
  return mongoose.connection;
};

// Connect to MongoDB once on startup
connectDB()
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch((err) => console.error("❌ MongoDB connection failed:", err));

// Keep track of ongoing calls in memory
const activeCalls = new Map<string, {
  callId: string;
  callerId: string;
  calleeId: string;
  initiatedAt: Date;
  connectedAt?: Date;
}>();

const activeGroupCalls = new Map<string, {
  callId: string;
  chatId: string;
  startedAt: Date;
  activeUsers: Set<string>;
}>();

io.on("connection", (socket) => {
  console.log("Connected:", socket.id);

  // ─── Presence ───────────────────────────────────────────────────────
  socket.on("join", async () => {
    const userId = (socket as any).userId;
    socket.join(userId);
    console.log(`User ${userId} joined their personal room`);
    socket.broadcast.emit("user_online", userId);
    
    // Auto-join all group rooms this user is in
    try {
      await connectDB();
      const groups = await Chat.find({ users: userId, isGroup: true }).select("_id");
      groups.forEach((g) => {
        socket.join(g._id.toString());
        console.log(`User ${userId} auto-joined group room ${g._id}`);
      });
    } catch (err) {
      console.error("Auto-join group rooms error:", err);
    }
  });

  // ─── Multi-Device Identity & Revocation ─────────────────────────────
  socket.on("join_device", (data: { deviceId: string; userId?: string }) => {
    if (data?.deviceId) {
      socket.join(data.deviceId);
      (socket as any).deviceId = data.deviceId;
      console.log(`Socket ${socket.id} joined device room ${data.deviceId}`);
    }
  });

  socket.on("join_pairing_room", (pairingId: string) => {
    if (pairingId) {
      socket.join(pairingId);
      console.log(`Socket ${socket.id} joined pairing room ${pairingId}`);
    }
  });

  socket.on("device_paired", (data: { pairingId: string; deviceId: string; userId: string }) => {
    if (data?.pairingId) {
      io.to(data.pairingId).emit("pairing_approved", data);
    }
    if (data?.userId) {
      io.to(data.userId).emit("device_list_updated");
    }
  });

  socket.on("device_revoked", (data: { deviceId: string; userId: string }) => {
    if (data?.deviceId) {
      io.to(data.deviceId).emit("device_revoked", { deviceId: data.deviceId });
    }
    if (data?.userId) {
      io.to(data.userId).emit("device_list_updated");
    }
  });

  socket.on("join_group_room", (data) => {
    // data: { chatId }
    socket.join(data.chatId);
    console.log(`Socket ${socket.id} joined group room ${data.chatId}`);
  });

  socket.on("create_group", (data) => {
    // data: { chatId, userIds }
    const connectedSockets = io.sockets.sockets;
    connectedSockets.forEach((s) => {
      data.userIds.forEach((uId: string) => {
        if (s.rooms.has(uId)) {
          s.join(data.chatId);
          s.emit("group_added", { chatId: data.chatId });
          console.log(`Socket for user ${uId} joined group room ${data.chatId}`);
        }
      });
    });
  });

  // ─── Messaging ──────────────────────────────────────────────────────
  socket.on("send_message", (data) => {
    // data: { receiverId, chatId, message }
    if (data.chatId) {
      socket.to(data.chatId).emit("receive_message", data.message);
    } else if (data.receiverId) {
      io.to(data.receiverId).emit("receive_message", data.message);
    }
  });

  socket.on("typing", (data) => {
    // data: { receiverId, chatId }
    const senderId = (socket as any).userId;
    if (data.chatId) {
      socket.to(data.chatId).emit("typing", { chatId: data.chatId, senderId });
    } else if (data.receiverId) {
      io.to(data.receiverId).emit("typing", { senderId });
    }
  });
  
  socket.on("stop_typing", (data) => {
    // data: { receiverId, chatId }
    const senderId = (socket as any).userId;
    if (data.chatId) {
      socket.to(data.chatId).emit("stop_typing", { chatId: data.chatId, senderId });
    } else if (data.receiverId) {
      io.to(data.receiverId).emit("stop_typing", { senderId });
    }
  });

  socket.on("mark_seen", (data) => {
    // data: { senderId, chatId }
    const receiverId = (socket as any).userId;
    if (data.chatId) {
      socket.to(data.chatId).emit("messages_seen", { chatId: data.chatId, receiverId, readAt: new Date().toISOString() });
    } else if (data.senderId) {
      io.to(data.senderId).emit("messages_seen", { receiverId, readAt: new Date().toISOString() });
    }
  });

  // Per-message read receipt (for tooltip)
  socket.on("read_receipt", (data) => {
    const userId = (socket as any).userId;
    if (data.chatId) {
      socket.to(data.chatId).emit("read_receipt", {
        chatId: data.chatId,
        messageId: data.messageId,
        userId,
        readAt: data.readAt,
      });
    } else if (data.targetId) {
      io.to(data.targetId).emit("read_receipt", {
        messageId: data.messageId,
        userId,
        readAt: data.readAt,
      });
    }
  });
  
  socket.on("message_delivered", (data) => {
    io.to(data.senderId).emit("message_status_update", {
      messageId: data.messageId,
      status: "delivered",
    });
  });

  // ─── Polls ──────────────────────────────────────────────────────────
  socket.on("poll_update", (data) => {
    if (data.chatId) {
      socket.to(data.chatId).emit("poll_updated", data.updatedMessage);
    } else if (data.receiverId) {
      io.to(data.receiverId).emit("poll_updated", data.updatedMessage);
    }
  });

  // ─── Reactions ────────────────────────────────────────────────────────
  socket.on("reaction_update", (data) => {
    if (data.chatId) {
      socket.to(data.chatId).emit("reaction_updated", {
        chatId: data.chatId,
        messageId: data.messageId,
        reactions: data.reactions,
      });
    } else if (data.targetUserId) {
      io.to(data.targetUserId).emit("reaction_updated", {
        messageId: data.messageId,
        reactions: data.reactions,
      });
    }
  });

  // ─── Message Edit ───────────────────────────────────────────────────
  socket.on("message_edited", (data) => {
    // data: { chatId?, targetUserId?, message }
    if (data.chatId) {
      socket.to(data.chatId).emit("message_edited", {
        chatId: data.chatId,
        message: data.message,
      });
    } else if (data.targetUserId) {
      io.to(data.targetUserId).emit("message_edited", {
        message: data.message,
      });
    }
  });

  // ─── Message Delete for Everyone ────────────────────────────────────
  socket.on("message_deleted", (data) => {
    // data: { chatId?, targetUserId?, messageId }
    if (data.chatId) {
      socket.to(data.chatId).emit("message_deleted", {
        chatId: data.chatId,
        messageId: data.messageId,
      });
    } else if (data.targetUserId) {
      io.to(data.targetUserId).emit("message_deleted", {
        messageId: data.messageId,
      });
    }
  });

  // ─── Pinned Messages ───────────────────────────────────────────────
  socket.on("message_pinned", (data) => {
    // data: { chatId?, targetUserId?, message, pinnedCount }
    if (data.chatId) {
      socket.to(data.chatId).emit("message_pinned", {
        chatId: data.chatId,
        message: data.message,
        pinnedCount: data.pinnedCount,
      });
    } else if (data.targetUserId) {
      io.to(data.targetUserId).emit("message_pinned", {
        message: data.message,
        pinnedCount: data.pinnedCount,
      });
    }
  });

  socket.on("message_unpinned", (data) => {
    // data: { chatId?, targetUserId?, messageId, pinnedCount }
    if (data.chatId) {
      socket.to(data.chatId).emit("message_unpinned", {
        chatId: data.chatId,
        messageId: data.messageId,
        pinnedCount: data.pinnedCount,
      });
    } else if (data.targetUserId) {
      io.to(data.targetUserId).emit("message_unpinned", {
        messageId: data.messageId,
        pinnedCount: data.pinnedCount,
      });
    }
  });

  // ─── WebRTC Signaling (Audio / Video Calls) ─────────────────────────
  // Caller → Callee: initiate a call
  socket.on("call_user", async (data) => {
    // data: { calleeId, offer, callType: "audio"|"video", callerName }
    const callerId = (socket as any).userId;
    try {
      await connectDB();
      const newCall = await Call.create({
        caller: callerId,
        participants: [data.calleeId],
        type: data.callType === "video" ? "video" : "voice",
        status: "missed", // default status
        startedAt: new Date(),
      });

      const callInfo = {
        callId: newCall._id.toString(),
        callerId: callerId,
        calleeId: data.calleeId,
        initiatedAt: new Date(),
      };

      activeCalls.set(callerId, callInfo);
      activeCalls.set(data.calleeId, callInfo);

      io.to(data.calleeId).emit("incoming_call", {
        offer: data.offer,
        callType: data.callType,
        callerId: callerId,
        callerName: data.callerName,
        callId: newCall._id.toString(),
      });
    } catch (err) {
      console.error("Error creating call log:", err);
    }
  });

  // Callee → Caller: accept with SDP answer
  socket.on("call_answer", async (data) => {
    // data: { callerId, answer }
    const calleeId = (socket as any).userId;
    const callInfo = activeCalls.get(data.callerId);
    if (callInfo && callInfo.calleeId === calleeId) {
      callInfo.connectedAt = new Date();
      try {
        await connectDB();
        await Call.findByIdAndUpdate(callInfo.callId, {
          status: "completed",
          startedAt: callInfo.connectedAt,
        });
      } catch (err) {
        console.error("Error answering call:", err);
      }
    }
    io.to(data.callerId).emit("call_answered", { answer: data.answer });
  });

  // Relay ICE candidates between peers
  socket.on("ice_candidate", (data) => {
    io.to(data.targetId).emit("ice_candidate", { candidate: data.candidate });
  });

  // Callee → Caller: reject incoming call
  socket.on("call_reject", async (data) => {
    // data: { callerId }
    const callInfo = activeCalls.get(data.callerId);
    if (callInfo) {
      try {
        await connectDB();
        await Call.findByIdAndUpdate(callInfo.callId, {
          status: "rejected",
        });
      } catch (err) {
        console.error("Error rejecting call:", err);
      }
      activeCalls.delete(callInfo.callerId);
      activeCalls.delete(callInfo.calleeId);
    }
    io.to(data.callerId).emit("call_rejected");
  });

  // Either side ends an active call
  socket.on("call_end", async (data) => {
    // data: { targetId }
    const myUserId = (socket as any).userId;
    const lookupId = myUserId || data.targetId;
    const callInfo = activeCalls.get(lookupId);

    if (callInfo) {
      try {
        await connectDB();
        if (callInfo.connectedAt) {
          const endedAt = new Date();
          const duration = Math.max(0, Math.round((endedAt.getTime() - callInfo.connectedAt.getTime()) / 1000));
          await Call.findByIdAndUpdate(callInfo.callId, {
            endedAt,
            duration,
            status: "completed",
          });
        } else {
          const isCaller = myUserId === callInfo.callerId;
          await Call.findByIdAndUpdate(callInfo.callId, {
            status: isCaller ? "cancelled" : "missed",
          });
        }
      } catch (err) {
        console.error("Error ending call:", err);
      }
      activeCalls.delete(callInfo.callerId);
      activeCalls.delete(callInfo.calleeId);
    }
    io.to(data.targetId).emit("call_ended");
  });

  // ─── Group WebRTC Calling ────────────────────────────────────────────
  socket.on("group_call_start", async (data) => {
    // data: { chatId, callerName, callType }
    const callerId = (socket as any).userId;
    try {
      await connectDB();
      const chat = await Chat.findById(data.chatId);
      const participants = chat ? chat.users.filter((u: any) => u.toString() !== callerId) : [];

      const newCall = await Call.create({
        chatId: data.chatId,
        caller: callerId,
        participants,
        type: data.callType === "video" ? "video" : "voice",
        status: "completed",
        startedAt: new Date(),
      });

      const groupCallInfo = {
        callId: newCall._id.toString(),
        chatId: data.chatId,
        startedAt: new Date(),
        activeUsers: new Set<string>([callerId]),
      };

      activeGroupCalls.set(data.chatId, groupCallInfo);
      const payload = { ...data, callerId };
      socket.to(data.chatId).emit("incoming_group_call", payload);
    } catch (err) {
      console.error("Error starting group call:", err);
    }
  });

  socket.on("group_call_join", (data) => {
    const userId = (socket as any).userId;
    const groupCallInfo = activeGroupCalls.get(data.chatId);
    if (groupCallInfo) {
      groupCallInfo.activeUsers.add(userId);
    }
    const payload = { ...data, userId };
    socket.to(data.chatId).emit("group_call_joined", payload);
  });

  socket.on("group_call_leave", async (data) => {
    const userId = (socket as any).userId;
    const groupCallInfo = activeGroupCalls.get(data.chatId);
    if (groupCallInfo) {
      groupCallInfo.activeUsers.delete(userId);
      if (groupCallInfo.activeUsers.size === 0) {
        try {
          await connectDB();
          const endedAt = new Date();
          const duration = Math.max(0, Math.round((endedAt.getTime() - groupCallInfo.startedAt.getTime()) / 1000));
          await Call.findByIdAndUpdate(groupCallInfo.callId, {
            endedAt,
            duration,
            status: "completed",
          });
        } catch (err) {
          console.error("Error ending group call:", err);
        }
        activeGroupCalls.delete(data.chatId);
      }
    }
    const payload = { ...data, userId };
    socket.to(data.chatId).emit("group_call_left", payload);
  });

  socket.on("group_call_signal", (data) => {
    const senderId = (socket as any).userId;
    io.to(data.targetId).emit("group_call_signaling", {
      senderId,
      signal: data.signal,
    });
  });

  // ─── Account Deletion ────────────────────────────────────────────────
  // When a user deletes their account, the server handles all cleanup.
  // The client emits this event after the delete API succeeds.
  // The server then: force-logouts all devices, ends active calls,
  // notifies contacts, and disconnects all sockets for this user.
  socket.on("account_deleted", async () => {
    const myUserId = (socket as any).userId;
    if (!myUserId) return;

    console.log(`Account deleted for user ${myUserId}. Cleaning up...`);

    // 1. Broadcast force_logout to ALL sockets in this user's room
    //    (handles multi-device logout — other tabs/devices get logged out)
    io.to(myUserId).emit("force_logout");

    // 2. Notify all connected users that this user's account was deleted
    //    so they can update their UI (e.g., show "Deleted User" in chat list)
    socket.broadcast.emit("user_deleted", myUserId);

    // 3. Clean up active 1-on-1 calls
    const callInfo = activeCalls.get(myUserId);
    if (callInfo) {
      try {
        await connectDB();
        const targetId = myUserId === callInfo.callerId ? callInfo.calleeId : callInfo.callerId;

        if (callInfo.connectedAt) {
          const endedAt = new Date();
          const duration = Math.max(0, Math.round((endedAt.getTime() - callInfo.connectedAt.getTime()) / 1000));
          await Call.findByIdAndUpdate(callInfo.callId, {
            endedAt,
            duration,
            status: "completed",
          });
        } else {
          await Call.findByIdAndUpdate(callInfo.callId, {
            status: "cancelled",
          });
        }
        io.to(targetId).emit("call_ended");
      } catch (err) {
        console.error("Error ending call on account deletion:", err);
      }
      activeCalls.delete(callInfo.callerId);
      activeCalls.delete(callInfo.calleeId);
    }

    // 4. Clean up group calls
    for (const [chatId, groupCallInfo] of activeGroupCalls.entries()) {
      if (groupCallInfo.activeUsers.has(myUserId)) {
        groupCallInfo.activeUsers.delete(myUserId);
        socket.to(chatId).emit("group_call_left", { chatId, userId: myUserId });
        if (groupCallInfo.activeUsers.size === 0) {
          try {
            await connectDB();
            const endedAt = new Date();
            const duration = Math.max(0, Math.round((endedAt.getTime() - groupCallInfo.startedAt.getTime()) / 1000));
            await Call.findByIdAndUpdate(groupCallInfo.callId, {
              endedAt,
              duration,
              status: "completed",
            });
          } catch (err) {
            console.error("Error ending group call on account deletion:", err);
          }
          activeGroupCalls.delete(chatId);
        }
      }
    }

    // 5. Broadcast user_offline since the account no longer exists
    socket.broadcast.emit("user_offline", myUserId);

    // 6. Disconnect all sockets for this user
    const allSockets = await io.in(myUserId).fetchSockets();
    for (const s of allSockets) {
      s.disconnect(true);
    }
  });

  // ─── Disconnect ──────────────────────────────────────────────────────
  socket.on("disconnect", async (reason) => {
    console.log("Client disconnected:", socket.id, "Reason:", reason);
    const myUserId = (socket as any).userId;
    if (myUserId) {
      // End 1-to-1 active calls if user disconnects suddenly
      const callInfo = activeCalls.get(myUserId);
      if (callInfo) {
        try {
          await connectDB();
          const targetId = myUserId === callInfo.callerId ? callInfo.calleeId : callInfo.callerId;
          
          if (callInfo.connectedAt) {
            const endedAt = new Date();
            const duration = Math.max(0, Math.round((endedAt.getTime() - callInfo.connectedAt.getTime()) / 1000));
            await Call.findByIdAndUpdate(callInfo.callId, {
              endedAt,
              duration,
              status: "completed",
            });
          } else {
            const isCaller = myUserId === callInfo.callerId;
            await Call.findByIdAndUpdate(callInfo.callId, {
              status: isCaller ? "cancelled" : "missed",
            });
          }
          io.to(targetId).emit("call_ended");
        } catch (err) {
          console.error("Error ending call on disconnect:", err);
        }
        activeCalls.delete(callInfo.callerId);
        activeCalls.delete(callInfo.calleeId);
      }

      // Leave group calls if user disconnects
      for (const [chatId, groupCallInfo] of activeGroupCalls.entries()) {
        if (groupCallInfo.activeUsers.has(myUserId)) {
          groupCallInfo.activeUsers.delete(myUserId);
          if (groupCallInfo.activeUsers.size === 0) {
            try {
              await connectDB();
              const endedAt = new Date();
              const duration = Math.max(0, Math.round((endedAt.getTime() - groupCallInfo.startedAt.getTime()) / 1000));
              await Call.findByIdAndUpdate(groupCallInfo.callId, {
                endedAt,
                duration,
                status: "completed",
              });
            } catch (err) {
              console.error("Error ending group call on disconnect:", err);
            }
            activeGroupCalls.delete(chatId);
          }
        }
      }
    }
  });
});

const PORT = process.env.PORT || 3001;

httpServer.listen(PORT, () => {
  console.log(`🚀 Socket server running on port ${PORT}`);
});
