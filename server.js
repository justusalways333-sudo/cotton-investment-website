// ===============================
// IMPORTS
// ===============================
const http = require("http");
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const nodemailer = require("nodemailer");
const multer = require("multer");
const fs = require("fs");
const PDFDocument = require("pdfkit");
const { Server } = require("socket.io");
require("dotenv").config();


// ===============================
// APP & SOCKET SETUP
// ===============================
const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 1000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});



// ===============================
// certificate
// ===============================
function generateCertificate(user, investment) {
  if (!fs.existsSync("certificates")) {
    fs.mkdirSync("certificates");
  }

  const filePath = `certificates/investment_${investment.id}.pdf`;
  const doc = new PDFDocument();

  doc.pipe(fs.createWriteStream(filePath));

  doc.fontSize(22).text("Investment Certificate", { align: "center" });
  doc.moveDown();

  doc.fontSize(12).text(`Investor: ${user.email}`);
  doc.text(`Investment ID: ${investment.id}`);
  doc.text(`Amount: $${investment.amount}`);
  doc.text(`ROI: ${investment.percent}%`);
  doc.text(`Profit: $${investment.profit}`);
  doc.text(`Date: ${new Date().toDateString()}`);

  doc.end();

  return filePath;
}



// ===============================
// EMAIL SETUP
// ===============================
let transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: "agriculturalfoundationiv@gmail.com",
    pass: "pkbc qkdu yjmo dpox"
  }
});

transporter.verify((err, success) => {
  if (err) console.log("Email connection failed:", err);
  else console.log("Email server ready to send messages");
});

function sendEmail(to, subject, html) {
  transporter.sendMail({ to, subject, html }, (err, info) => {
    if (err) console.log("Email error:", err);
  });
}

function send2FACode(email, code) {
  sendEmail(email, "Your Login Security Code", `Your login verification code is: ${code}\nThis code expires in 5 minutes.`);
}


// ===============================
// MIDDLEWARE
// ===============================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));

app.use(session({
  secret: "cotton-secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

// ===============================
// DATABASE
// ===============================
const db = new sqlite3.Database("database.db", err => {
  if (err) console.error(err.message);
  else console.log("✅ Database connected");
});


const transporters = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ===============================
// HELPER FUNCTIONS
// ===============================
function addColumnIfNotExists(table, column, definition) {
  db.all(`PRAGMA table_info(${table})`, (err, cols) => {
    if (err) return console.error(err);
    if (!cols.some(c => c.name === column)) {
      db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
      console.log(`✅ ${column} added to ${table}`);
    }
  });
}

function requireKYC(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Login required" });
  if (req.session.user.kyc_status !== "approved") return res.status(403).json({ error: "KYC verification required" });
  next();
}

const isLoggedIn = (req, res, next) => {
  if (!req.session.user) return res.redirect("/login.html");
  next();
};

const isAdmin = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== "admin") return res.status(403).send("Access denied");
  next();
};


// ===============================
// FILE UPLOAD
// ===============================
if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");
if (!fs.existsSync("certificates")) fs.mkdirSync("certificates");

const upload = multer({
  storage: multer.diskStorage({
    destination: "uploads/",
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
  })
});

// ===============================
// TABLES SETUP
// ===============================
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    balance REAL DEFAULT 0,
    kyc_status TEXT DEFAULT 'pending',
    referral_code TEXT,
    referred_by TEXT,
    referral_bonus_paid INTEGER DEFAULT 0,
    twofa_code TEXT,
    twofa_expires INTEGER,
    withdraw_otp TEXT,
    withdraw_otp_expires INTEGER,
    withdraw_otp_attempts INTEGER DEFAULT 0,
    withdraw_blocked_until INTEGER,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS kyc (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    document TEXT,
    id_type TEXT,
    id_number TEXT,
    video_link TEXT,
    status TEXT DEFAULT 'pending',
    reason TEXT,
    submitted_at INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    type TEXT,
    amount REAL,
    status TEXT DEFAULT 'Pending',
    reason TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS investments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    plan_id INTEGER DEFAULT 1,
    amount REAL,
    percent REAL,
    profit REAL,
    status TEXT DEFAULT 'Pending',
    paid INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS invest_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    percent REAL
  )`);

  db.run(`INSERT INTO invest_plans (name, percent)
          SELECT 'Default Plan', 15
          WHERE NOT EXISTS (SELECT 1 FROM invest_plans)`);

  db.run(`CREATE TABLE IF NOT EXISTS withdrawals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    amount REAL,
    status TEXT DEFAULT 'Pending',
    reason TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS loans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    amount REAL,
    method TEXT,
    status TEXT DEFAULT 'Pending',
    reason TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS bank_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    bank_name TEXT,
    account_number TEXT,
    account_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS crypto_withdrawals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    wallet TEXT,
    network TEXT,
    amount REAL,
    status TEXT DEFAULT 'Pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// ===============================
// SESSION REFRESH
// ===============================
app.use((req, res, next) => {
  if (!req.session.user) return next();
  db.get(`SELECT balance, kyc_status FROM users WHERE id=?`, [req.session.user.id], (err, row) => {
    if (row) {
      req.session.user.balance = row.balance;
      req.session.user.kyc_status = row.kyc_status;
    }
    next();
  });
});

// ===============================
// INVESTMENT CERTIFICATE
// ===============================
function generateCertificate(user, investment) {
  const doc = new PDFDocument();
  const filePath = `certificates/investment_${investment.id}.pdf`;
  doc.pipe(fs.createWriteStream(filePath));
  doc.fontSize(20).text("Investment Certificate", { align: "center" });
  doc.moveDown();
  doc.fontSize(12).text(`Investor: ${user.name}`);
  doc.text(`Investment ID: ${investment.id}`);
  doc.text(`Amount: $${investment.amount}`);
  doc.text(`ROI: ${investment.percent}%`);
  doc.text(`Profit: $${investment.profit}`);
  doc.text(`Date: ${new Date().toDateString()}`);
  doc.end();
  return filePath;
}

// ===============================
// AUTO ROI PAYOUT
// ===============================
setInterval(() => {
  db.all(`SELECT * FROM investments WHERE status='Approved' AND paid=0`, [], (err, rows) => {
    if (err || !rows.length) return;
    rows.forEach(inv => {
      db.run(`UPDATE users SET balance = balance + ? WHERE id=?`, [inv.profit, inv.user_id]);
      db.run(`UPDATE investments SET paid=1 WHERE id=?`, [inv.id]);
      db.get(`SELECT email FROM users WHERE id=?`, [inv.user_id], (_, user) => {
        if (user) sendEmail(user.email, "ROI Credited", `<p>Your ROI of <b>${inv.profit}</b> has been credited to your balance.</p>`);
      });
    });
  });
}, 1000 * 60 * 60 * 24);

// ===============================
// AUTH ROUTES
// ===============================
app.post("/register", async (req, res) => {
  const { name, email, password, referralCode } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const myCode = Math.random().toString(36).substring(2, 8);
  db.run(`INSERT INTO users (name,email,password,referral_code,referred_by) VALUES (?,?,?,?,?)`,
    [name, email.toLowerCase(), hash, myCode, referralCode || null],
    err => { if (err) return res.send("Email already exists"); res.send("Registration successful"); });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email=?`, [email], async (err, user) => {
    if (!user) return res.send("User not found");
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.send("Wrong password");

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 5 * 60 * 1000;
    db.run(`UPDATE users SET twofa_code=?, twofa_expires=? WHERE id=?`, [code, expires, user.id]);
    send2FACode(user.email, code);
    req.session.tempUser = user.id;
    res.send("2FA_REQUIRED");
  });
});

app.post("/verify-2fa", (req, res) => {
  const { code } = req.body;
  const userId = req.session.tempUser;
  if (!userId) return res.send("Session expired");
  db.get(`SELECT * FROM users WHERE id=?`, [userId], (err, user) => {
    if (!user) return res.send("User not found");
    if (user.twofa_code !== code || Date.now() > user.twofa_expires) return res.send("Invalid or expired code");

    req.session.user = { id: user.id, email: user.email, role: user.role, balance: user.balance, kyc_status: user.kyc_status };
    db.run(`UPDATE users SET twofa_code=NULL, twofa_expires=NULL WHERE id=?`, [user.id]);
    delete req.session.tempUser;
    res.send("LOGIN_SUCCESS");
  });
});

// ===============================
// DEPOSIT ROUTE
// ===============================
app.post("/deposit", isLoggedIn, (req, res) => {
  const { amount } = req.body;
  db.run(`INSERT INTO transactions (user_id,type,amount) VALUES (?,?,?)`, [req.session.user.id, "Deposit", amount], () => {
    sendEmail(req.session.user.email, "Deposit Request Received", "<p>Your deposit request is pending admin approval.</p>");
    res.json({ success: true });
  });
});

// ===============================
// INVESTMENT ROUTE
// ===============================
app.post("/invest", isLoggedIn, (req, res) => {
  const { amount } = req.body;
  if (req.session.user.balance < amount) return res.send("Insufficient balance to invest");
  const percent = 15;
  const profit = (amount * percent) / 100;
  db.run(`INSERT INTO investments (user_id,amount,percent,profit) VALUES (?,?,?,?)`, [req.session.user.id, amount, percent, profit], () => {
    res.send("Investment pending admin approval");
  });
});
app.post("/admin/approve-investment", isAdmin, (req, res) => {
  const { id } = req.body;

  db.get(
    `SELECT users.email, investments.* 
     FROM investments 
     JOIN users ON users.id = investments.user_id 
     WHERE investments.id=?`,
    [id],
    (err, data) => {
      if (!data) return res.send("Investment not found");

      db.run("UPDATE investments SET status='Approved' WHERE id=?", [id]);

      const certPath = generateCertificate(data, data);

      transporter.sendMail({
        to: data.email,
        subject: "Investment Approved",
        text: "Your investment has been approved. Certificate attached.",
        attachments: [{ path: certPath }]
      });

      res.send("Investment approved and certificate sent");
    }
  );
});

// ===============================
// WITHDRAWAL ROUTES
// ===============================
function checkWithdrawBlock(req, res, next) {
  db.get(`SELECT withdraw_blocked_until FROM users WHERE id=?`, [req.session.user.id], (err, user) => {
    if (user?.withdraw_blocked_until && Date.now() < user.withdraw_blocked_until) return res.status(403).json({ error: "Withdrawals blocked due to multiple failed OTP attempts. Try again later." });
    next();
  });
}

app.post("/withdraw/request", isLoggedIn, checkWithdrawBlock, (req, res) => {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 5 * 60 * 1000;
  db.run(`UPDATE users SET withdraw_otp=?, withdraw_otp_expires=? WHERE id=?`, [otp, expires, req.session.user.id], () => {
    sendEmail(req.session.user.email, "Withdrawal OTP", `Your withdrawal OTP is ${otp}. Valid for 5 minutes.`);
    res.json({ message: "OTP sent to email" });
  });
});

app.post("/withdraw/confirm", isLoggedIn, checkWithdrawBlock, (req, res) => {
  const { otp, amount } = req.body;
  db.get(`SELECT withdraw_otp, withdraw_otp_expires, withdraw_otp_attempts, balance FROM users WHERE id=?`, [req.session.user.id], (err, user) => {
    if (!user) return res.status(400).json({ error: "User not found" });
    if (Date.now() > user.withdraw_otp_expires) return res.status(400).json({ error: "OTP expired" });

    if (user.withdraw_otp !== otp) {
      const attempts = (user.withdraw_otp_attempts || 0) + 1;
      if (attempts >= 3) {
        const blockUntil = Date.now() + 24 * 60 * 60 * 1000;
        db.run(`UPDATE users SET withdraw_otp_attempts=?, withdraw_blocked_until=? WHERE id=?`, [attempts, blockUntil, req.session.user.id]);
        return res.status(403).json({ error: "Too many failed attempts. Withdrawals blocked for 24 hours." });
      }
      db.run(`UPDATE users SET withdraw_otp_attempts=? WHERE id=?`, [attempts, req.session.user.id]);
      return res.status(400).json({ error: `Invalid OTP. ${3 - attempts} attempts left` });
    }

    // Correct OTP
    db.run(`UPDATE users SET withdraw_otp_attempts=0, withdraw_otp=NULL, withdraw_otp_expires=NULL, withdraw_blocked_until=NULL, balance=balance-? WHERE id=?`, [amount, req.session.user.id]);
    db.run(`INSERT INTO withdrawals (user_id, amount, status) VALUES (?, ?, 'Pending')`, [req.session.user.id, amount]);
    sendEmail(req.session.user.email, "Withdrawal Request Submitted", "<p>Your withdrawal request is pending admin approval.</p>");
    res.json({ success: true });
  });
});

// ===============================
// KYC ROUTES
// ===============================
app.post("/kyc/upload", isLoggedIn, upload.single("document"), (req, res) => {
  const { id_type, id_number, video_link } = req.body;
  db.run(`INSERT INTO kyc (user_id, document, id_type, id_number, video_link, status, submitted_at) VALUES (?,?,?,?,?, 'pending', ?)`, [req.session.user.id, req.file.filename, id_type, id_number, video_link, Date.now()], () => {
    res.redirect("/kyc-status.html");
  });
});

app.get("/api/kyc/status", isLoggedIn, (req, res) => {
  db.get(`SELECT status, submitted_at FROM kyc WHERE user_id=? ORDER BY id DESC LIMIT 1`, [req.session.user.id], (err, row) => {
    if (!row) return res.json({ status: "pending", submitted_at: Date.now() });
    res.json(row);
  });
});

// ===============================
// LOAN ROUTE
// ===============================
app.post("/loan", isLoggedIn, requireKYC, (req, res) => {
  db.get(`SELECT COUNT(*) AS total FROM transactions WHERE user_id=? AND type='Deposit' AND status='Approved'`, [req.session.user.id], (err, row) => {
    if (row.total === 0) return res.send("Deposit required before loan");
    db.run(`INSERT INTO loans (user_id, amount, method) VALUES (?,?,?)`, [req.session.user.id, req.body.amount, req.body.method], () => res.send("Loan request pending admin approval"));
  });
});

// ===============================
// 2FA LOGIN FLOW
// ===============================

// Step 1: User submits email & password
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email=?`, [email], async (err, user) => {
    if (!user) return res.status(400).send("User not found");

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).send("Wrong password");

    // Generate 6-digit 2FA code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 5 * 60 * 1000; // 5 minutes

    // Save 2FA code in DB
    db.run(`UPDATE users SET twofa_code=?, twofa_expires=? WHERE id=?`, [code, expires, user.id]);

    // Send code via email
    send2FACode(user.email, code);

    // Temporarily store user ID in session
    req.session.tempUser = user.id;

    res.send("2FA_REQUIRED");
  });
});

// Step 2: User submits 2FA code
app.post("/verify-2fa", (req, res) => {
  const { code } = req.body;
  const userId = req.session.tempUser;

  if (!userId) return res.status(400).send("Session expired");

  db.get(`SELECT * FROM users WHERE id=?`, [userId], (err, user) => {
    if (!user) return res.status(400).send("User not found");

    // Validate code and expiry
    if (user.twofa_code !== code || Date.now() > user.twofa_expires) {
      return res.status(400).send("Invalid or expired 2FA code");
    }

    // ✅ Final login
    req.session.user = {
      id: user.id,
      email: user.email,
      role: user.role || "user",
      kyc_status: user.kyc_status
    };

    // Clear code in DB and session
    db.run(`UPDATE users SET twofa_code=NULL, twofa_expires=NULL WHERE id=?`, [user.id]);
    delete req.session.tempUser;

    res.send("LOGIN_SUCCESS");
  });
});

// Helper function to send 2FA code
function send2FACode(email, code) {
  transporter.sendMail({
    to: email,
    subject: "Your 2FA Security Code",
    text: `Your login verification code is: ${code}\nThis code expires in 5 minutes.`
  }, (err, info) => {
    if (err) console.log("2FA email error:", err);
    else console.log("2FA code sent to", email);
  });
}

// ===============================
// ADMIN ROUTES (CONTINUED)
// ===============================

// Approve Transaction (Deposit / Withdraw)
app.post("/admin/approve-transaction", isAdmin, (req, res) => {
  const { id, user_id, type, amount } = req.body;
  if (!id || !user_id || !type || !amount) return res.status(400).send("Missing data");

  // Update user balance
  if (type === "Deposit") {
    db.run(`UPDATE users SET balance = balance + ? WHERE id=?`, [amount, user_id], () => {
      // Handle referral bonus
      db.get(`SELECT referred_by, referral_bonus_paid FROM users WHERE id=?`, [user_id], (err, u) => {
        if (u?.referred_by && u.referral_bonus_paid === 0) {
          db.run(`UPDATE users SET balance = balance + 5 WHERE referral_code=?`, [u.referred_by]);
          db.run(`UPDATE users SET referral_bonus_paid=1 WHERE id=?`, [user_id]);
        }
      });
    });
  }

  if (type === "Withdraw") {
    db.run(`UPDATE users SET balance = balance - ? WHERE id=?`, [amount, user_id]);
  }

  // Update transaction status
  db.run(`UPDATE transactions SET status='Approved' WHERE id=?`, [id]);

  // Send email notification
  db.get(`SELECT email FROM users WHERE id=?`, [user_id], (_, user) => {
    if (user) sendEmail(user.email, `${type} Approved`, `Your ${type.toLowerCase()} of $${amount} has been approved.`);
  });

  res.send("Transaction approved");
});

// Approve Investment
app.post("/admin/approve-investment", isAdmin, (req, res) => {
  const { id, user_id, amount } = req.body;

  db.run(`UPDATE investments SET status='Approved' WHERE id=?`, [id], () => {
    db.get(`SELECT * FROM users WHERE id=?`, [user_id], (err, user) => {
      if (!user) return res.status(404).send("User not found");

      const investment = { id, amount, percent: 15, profit: (amount * 15) / 100 };
      const cert = generateCertificate(user, investment);

      sendEmail(user.email, "Investment Approved", "Your investment has been approved. Certificate attached.");
    });
    res.send("Investment approved");
  });
});

// Approve Loan
app.post("/admin/approve-loan", isAdmin, (req, res) => {
  const { id } = req.body;
  db.run(`UPDATE loans SET status='Approved' WHERE id=?`, [id]);
  res.send("Loan approved");
});

// Approve KYC
app.post("/admin/approve-kyc", isAdmin, (req, res) => {
  const { user_id } = req.body;
  db.run(`UPDATE users SET kyc_status='approved' WHERE id=?`, [user_id]);
  db.get(`SELECT email FROM users WHERE id=?`, [user_id], (_, user) => {
    if (user) sendEmail(user.email, "KYC Approved", "<p>Your KYC has been approved. You can now withdraw and request loans.</p>");
  });
  res.send("KYC approved");
});

// Reject Transaction
app.post("/admin/reject-transaction", isAdmin, (req, res) => {
  const { id, user_id, reason } = req.body;
  db.run(`UPDATE transactions SET status='Rejected', reason=? WHERE id=?`, [reason, id]);
  db.get(`SELECT email FROM users WHERE id=?`, [user_id], (_, user) => {
    if (user) sendEmail(user.email, "Transaction Rejected", `Your transaction was rejected.\nReason: ${reason}`);
  });
  res.send("Transaction rejected");
});

// Reject KYC
app.post("/admin/reject-kyc", isAdmin, (req, res) => {
  const { user_id, reason } = req.body;
  db.run(`UPDATE kyc SET status='Rejected', reason=? WHERE user_id=?`, [reason, user_id]);
  db.get(`SELECT email FROM users WHERE id=?`, [user_id], (_, user) => {
    if (user) sendEmail(user.email, "KYC Rejected", `Your KYC was rejected.\nReason: ${reason}`);
  });
  res.send("KYC rejected");
});

// Admin – view pending KYC
app.get("/admin/kyc", isAdmin, (req, res) => {
  db.all(`SELECT kyc.id, users.name, users.email, kyc.document, kyc.status FROM kyc JOIN users ON users.id = kyc.user_id WHERE kyc.status='pending'`, [], (err, rows) => res.json(rows));
});

// Admin – view pending Transactions
app.get("/admin/transactions", isAdmin, (req, res) => {
  db.all(`SELECT * FROM transactions WHERE status='Pending'`, [], (_, rows) => res.json(rows));
});

app.use(express.static("public"));

app.get("/", (req,res)=>{
  res.sendFile(__dirname + "/public/index.html");
});

// ===============================
// LIVE CHAT + AUTO BOT
// ===============================
let adminOnline = false;

io.on("connection", (socket) => {
  console.log("💬 A user connected to chat");

  // Admin signals online/offline
  socket.on("admin online", () => {
    adminOnline = true;
  });

  socket.on("admin offline", () => {
    adminOnline = false;
  });

  // User sends a chat message
  socket.on("chat message", (msg) => {
    io.emit("chat message", msg); // broadcast to everyone

    // Auto bot reply if admin offline
    if (!adminOnline && msg.startsWith("User:")) {
      setTimeout(() => {
        let reply = "🤖 Support Bot: Please wait, an agent will assist you.";

        const text = msg.toLowerCase();
        if (text.includes("deposit"))
          reply =
            "🤖 Bot: For deposits, please check the Deposit page or contact your account officer via Telegram.";
        if (text.includes("withdraw"))
          reply =
            "🤖 Bot: Withdrawals are processed within 24 hours. Please be patient.";
        if (text.includes("loan"))
          reply =
            "🤖 Bot: We offer two types of loans. Contact the manager for assistance.";
        if (text.includes("invest"))
          reply =
            "🤖 Bot: Visit the Invest section to proceed or chat with customer service.";

        io.emit("chat message", reply);
      }, 1200); // delay for realism
    }
  });

  socket.on("disconnect", () => {
    console.log("💬 A user disconnected from chat");
  });
});

// ===============================
// SERVER START
// ===============================
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});




