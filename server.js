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

if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Mipangilio ya Multer kupokea picha, video na documents zote
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 100 * 1024 * 1024 } // Kikomo cha 100MB kwa ajili ya video na files kubwa
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use("/uploads", express.static(UPLOAD_DIR));

function readDB() {
    if (!fs.existsSync(DB_FILE)) {
        const initialData = { users: {}, data: {} };
        fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2));
    }
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}

function saveDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Middleware ya API Key - Inazuia browser au mtu asiye na key
function requireApiKey(req, res, next) {
    const apiKey = req.headers["x-api-key"] || req.query.api_key;
    if (!apiKey || apiKey !== API_KEY) {
        // Kama amefungua kwenye browser au hana key, mpe HTML ya site haipatikani
        if (req.headers["accept"] && req.headers["accept"].includes("text/html")) {
            return res.status(403).send(`
                <!DOCTYPE html>
                <html lang="sw">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Site Haipatikani</title>
                    <style>
                        body { font-family: Arial, sans-serif; background: #111827; color: #f3f4f6; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                        .container { background: #1f2937; padding: 40px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); text-align: center; max-width: 450px; }
                        h1 { color: #ef4444; margin-bottom: 15px; font-size: 24px; }
                        p { color: #9ca3af; line-height: 1.6; font-size: 16px; }
                        .badge { display: inline-block; margin-top: 20px; padding: 8px 16px; background: #374151; color: #d1d5db; border-radius: 20px; font-size: 14px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>Huduma Haipatikani</h1>
                        <p>Samahani, site hii haipatikani kwa sasa au kagua mtandao wako kabla ya kujaribu tena.</p>
                        <div class="badge">Connection Offline / Restricted</div>
                    </div>
                </body>
                </html>
            `);
        }
        return res.status(403).json({ success: false, error: "API key si sahihi au haipo" });
    }
    next();
}

function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) {
        return res.status(401).json({ success: false, error: "Token inahitajika ili kufanya kitendo hiki" });
    }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, error: "Token si sahihi au imeisha muda wake" });
        req.user = user;
        next();
    });
}

// Root Endpoint - Mtu akiweka link kwenye browser moja kwa moja anaona HTML ya site haipatikani
app.get("/", (req, res) => {
    res.status(403).send(`
        <!DOCTYPE html>
        <html lang="sw">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Site Haipatikani</title>
            <style>
                body { font-family: Arial, sans-serif; background: #111827; color: #f3f4f6; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                .container { background: #1f2937; padding: 40px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); text-align: center; max-width: 450px; }
                h1 { color: #ef4444; margin-bottom: 15px; font-size: 24px; }
                p { color: #9ca3af; line-height: 1.6; font-size: 16px; }
                .badge { display: inline-block; margin-top: 20px; padding: 8px 16px; background: #374151; color: #d1d5db; border-radius: 20px; font-size: 14px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Huduma Haipatikani</h1>
                <p>Samahani, site hii haipatikani kwa sasa au kagua mtandao wako.</p>
                <div class="badge">Server Locked</div>
            </div>
        </body>
        </html>
    `);
});

// 1. Signup Endpoint - Ujumbe sahihi kabisa wa error na kutoa UID mpya na Token
app.post("/v1/auth/signup", requireApiKey, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, error: "Tafadhali jaza email na password zote" });
        }
        
        const db = readDB();
        if (db.users[email]) {
            return res.status(400).json({ success: false, error: "Email hii imeshasajiliwa tayari" });
        }
        
        const uid = "user_" + Date.now() + Math.random().toString(36).substring(2, 7);
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.users[email] = { uid, password: hashedPassword, createdAt: new Date() };
        saveDB(db);

        const accessToken = jwt.sign({ email, uid }, JWT_SECRET, { expiresIn: "30d" });
        
        res.json({ 
            success: true, 
            uid: uid, 
            accessToken: accessToken, 
            message: "Usajili umefanikiwa" 
        });
    } catch (err) {
        res.status(500).json({ success: false, error: "Imeshindikana kusajili kwa sasa: " + err.message });
    }
});

// 2. Signin Endpoint - Ujumbe sahihi wa email haipo au password imekosewa, inatoa UID iliyopo na Token mpya
app.post("/v1/auth/signin", requireApiKey, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, error: "Tafadhali jaza email na password" });
        }

        const db = readDB();
        const user = db.users[email];
        
        if (!user) {
            return res.status(401).json({ success: false, error: "Email hii haipo kwenye mfumo wetu" });
        }
        
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, error: "Password imekosewa, tafadhali jaribu tena" });
        }
        
        const accessToken = jwt.sign({ email, uid: user.uid }, JWT_SECRET, { expiresIn: "30d" });
        
        res.json({ 
            success: true, 
            uid: user.uid, 
            accessToken: accessToken, 
            message: "Umeingia kwa mafanikio" 
        });
    } catch (err) {
        res.status(500).json({ success: false, error: "Kosa limetokea wakati wa kuingia: " + err.message });
    }
});

// 3. File & Media Upload Endpoint (Picha, Video, na Documents zote)
app.post("/v1/upload", requireApiKey, verifyToken, upload.single("file"), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, error: "Mafaili hayajaingia, tafadhali chagua faili sahihi" });
        }
        const fileUrl = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
        res.json({ 
            success: true, 
            fileUrl: fileUrl, 
            fileName: req.file.filename, 
            message: "Faili limepokelewa na kuhifadhiwa kikamilifu" 
        });
    } catch (err) {
        res.status(500).json({ success: false, error: "Mafaili hayajaingia kutokana na hitilafu ya server: " + err.message });
    }
});

// 4. Real-time Database Endpoint (GET, POST, PUT, PATCH, DELETE bila kikomo)
app.all("/v1/data/:collection", requireApiKey, verifyToken, (req, res) => {
    try {
        const collection = req.params.collection;
        const db = readDB();
        if (!db.data[collection]) db.data[collection] = {};

        if (req.method === "GET") {
            return res.json({ success: true, data: db.data[collection] });
        }

        if (["POST", "PUT", "PATCH"].includes(req.method)) {
            if (!req.body || Object.keys(req.body).length === 0) {
                return res.status(400).json({ success: false, error: "Data hazijaingia, tafadhali ambatanisha taarifa kwenye ombi" });
            }
            const recordId = req.body.id || ("rec_" + Date.now());
            db.data[collection][recordId] = { ...req.body, updatedAt: new Date() };
            saveDB(db);
            return res.json({ success: true, id: recordId, message: "Data imehifadhiwa kikamilifu" });
        }

        if (req.method === "DELETE") {
            const recordId = req.body.id || req.query.id;
            if (recordId && db.data[collection][recordId]) {
                delete db.data[collection][recordId];
                saveDB(db);
                return res.json({ success: true, message: "Data imefutwa kikamilifu" });
            }
            return res.status(404).json({ success: false, error: "Data hazijaingia au ID haipatikani kwenye mfumo" });
        }

        res.status(405).json({ success: false, error: "Method hii haikubaliwi kwenye server" });
    } catch (err) {
        res.status(500).json({ success: false, error: "Hitilafu imetokea kwenye data: " + err.message });
    }
});

app.listen(PORT, () => {
    console.log(`KigomaDB v5.0 imewaka kikamilifu kwenye port ${PORT}`);
});
