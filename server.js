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
const UPLOAD_DIR = path.join(__dirname, "uploads");

// Hakikisha folda ya uploads ipo
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Konfigurations za Multer kwa ajili ya Image na Video
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 } // Kikomo cha 50MB kwa ajili ya video
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use("/uploads", express.static(UPLOAD_DIR));

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
    const apiKey = req.headers["x-api-key"] || req.query.api_key;
    if (!apiKey || apiKey !== API_KEY) {
        return res.status(403).json({ success: false, error: "API key si sahihi au haipo" });
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

// 1. Browser HTML Root Route (Site Status)
app.get("/", (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>KigomaDB Server</title>
            <style>
                body { font-family: Arial, sans-serif; background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                .card { background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); text-align: center; max-width: 400px; width: 100%; }
                h1 { color: #38bdf8; margin-bottom: 10px; }
                p { color: #94a3b8; }
                .status { display: inline-block; padding: 6px 12px; background: #065f46; color: #34d399; border-radius: 20px; font-size: 14px; margin-top: 15px; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>KigomaDB Cloud</h1>
                <p>Backend Server inafanya kazi kikamilifu kwa ajili ya App yako.</p>
                <div class="status">System Online & Active</div>
            </div>
        </body>
        </html>
    `);
});

// 2. Signup Endpoint (Inatoa UID na Token)
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
        
        // Kutengeneza UID ya kipekee
        const uid = "user_" + Date.now() + Math.random().toString(36).substring(2, 7);
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.users[email] = { uid, password: hashedPassword, createdAt: new Date() };
        saveDB(db);

        const accessToken = jwt.sign({ email, uid }, JWT_SECRET, { expiresIn: "30d" });
        res.json({ success: true, uid, accessToken, message: "Usajili umefanikiwa" });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 3. Signin Endpoint (Inatoa UID iliyopo na Token mpya)
app.post("/v1/auth/signin", requireApiKey, async (req, res) => {
    try {
        const { email, password } = req.body;
        const db = readDB();
        const user = db.users[email];
        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ success: false, error: "Email au password si sahihi" });
        }
        
        const accessToken = jwt.sign({ email, uid: user.uid }, JWT_SECRET, { expiresIn: "30d" });
        res.json({ success: true, uid: user.uid, accessToken, message: "Umeingia kwa mafanikio" });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 4. File Upload Endpoint (Image & Video)
app.post("/v1/upload", requireApiKey, verifyToken, upload.single("file"), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, error: "Hakuna faili lililopakiwa" });
        }
        const fileUrl = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
        res.json({ success: true, fileUrl, fileName: req.file.filename });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// 5. Flexible Data Endpoint (GET, POST, PUT, PATCH, DELETE bila kikomo)
app.all("/v1/data/:collection", requireApiKey, verifyToken, (req, res) => {
    const collection = req.params.collection;
    const db = readDB();
    if (!db.data[collection]) db.data[collection] = {};

    if (req.method === "GET") {
        return res.json({ success: true, data: db.data[collection] });
    }

    if (["POST", "PUT", "PATCH"].includes(req.method)) {
        const recordId = req.body.id || ("rec_" + Date.now());
        db.data[collection][recordId] = { ...req.body, updatedAt: new Date() };
        saveDB(db);
        return res.json({ success: true, id: recordId, message: "Data imehifadhiwa" });
    }

    if (req.method === "DELETE") {
        const recordId = req.body.id || req.query.id;
        if (recordId && db.data[collection][recordId]) {
            delete db.data[collection][recordId];
            saveDB(db);
            return res.json({ success: true, message: "Data imefutwa" });
        }
        return res.status(404).json({ success: false, error: "ID haipatikani" });
    }

    res.status(405).json({ success: false, error: "Method haikubaliwi" });
});

app.listen(PORT, () => {
    console.log(`KigomaDB v4.0 imewaka kwenye port ${PORT}`);
});
