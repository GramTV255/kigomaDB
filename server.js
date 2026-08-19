const express = require("express");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = "kigoma_api_twhhiqo828773779";
const JWT_SECRET = "kigoma_secret_key_2026";
const DB_FILE = path.join(__dirname, "database.json");

app.use(express.json());
app.use(cors());

// Kusoma Database
function readDB() {
    if (!fs.existsSync(DB_FILE)) {
        const initialData = { users: {}, data: {} };
        fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
    }
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}

// Kuhifadhi Database
function saveDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Middleware ya API Key
function requireApiKey(req, res, next) {
    const apiKey = req.headers["x-api-key"];
    if (!apiKey || apiKey !== API_KEY) {
        return res.status(403).json({ success: false, error: "API key si sahihi" });
    }
    next();
}

// Middleware ya JWT Token
function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) {
        return res.status(401).json({ success: false, error: "Token inahitajika" });
    }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, error: "Token si sahihi au imeisha muda wake" });
        req.user = user;
        next();
    });
}

// Health Check Endpoint
app.get("/", (req, res) => {
    res.json({ status: "KigomaDB v3.0 inafanya kazi vizuri" });
});

// 1. Signup Endpoint
app.post("/v1/auth/signup", requireApiKey, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, error: "Email na password vinahitajika" });
        }
        const db = readDB();
        if (db.users[email]) {
            return res.status(400).json({ success: false, error: "Mtumiaji yupo tayari" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        db.users[email] = { password: hashedPassword, createdAt: new Date() };
        saveDB(db);
        res.json({ success: true, message: "Usajili umefanikiwa" });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 2. Signin Endpoint
app.post("/v1/auth/signin", requireApiKey, async (req, res) => {
    try {
        const { email, password } = req.body;
        const db = readDB();
        const user = db.users[email];
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ success: false, error: "Email au password si sahihi" });
        }
        const accessToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" });
        res.json({ success: true, accessToken });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 3. Data Endpoint (Splat)
app.all("/v1/data/*splat", requireApiKey, verifyToken, (req, res) => {
    const pathString = req.params.splat || "";
    const db = readDB();
    
    if (req.method === "GET") {
        const keys = pathString.split("/").filter(Boolean);
        let ref = db.data;
        for (const key of keys) {
            if (ref[key] === undefined) {
                return res.status(404).json({ success: false, error: "Data haipatikani" });
            }
            ref = ref[key];
        }
        return res.json({ success: true, data: ref });
    }

    if (["POST", "PUT", "PATCH"].includes(req.method)) {
        const keys = pathString.split("/").filter(Boolean);
        let ref = db.data;
        for (let i = 0; i < keys.length - 1; i++) {
            if (!ref[keys[i]]) ref[keys[i]] = {};
            ref = ref[keys[i]];
        }
        if (keys.length > 0) {
            ref[keys[keys.length - 1]] = req.body;
        } else {
            db.data = req.body;
        }
        saveDB(db);
        return res.json({ success: true, message: "Data imehifadhiwa" });
    }

    res.json({ success: true, message: "Method supported" });
});

app.listen(PORT, () => {
    console.log(`KigomaDB v3.0 imewaka kwenye port ${PORT}`);
    console.log(`API Key: ${API_KEY}`);
});
