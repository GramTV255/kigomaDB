const express = require("express");
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const { Server } = require("socket.io");

/* =========================================================
   APP
========================================================= */

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: process.env.CORS_ORIGIN || "*",
        methods: [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE"
        ]
    }
});

/* =========================================================
   CONFIG
========================================================= */

const PORT =
    process.env.PORT || 3000;

const API_KEY =
    process.env.API_KEY ||
    "kigoma_api_twhhiqo828773779";

const JWT_SECRET =
    process.env.JWT_SECRET ||
    "kigoma_secret_key_2026";

const REFRESH_SECRET =
    process.env.REFRESH_SECRET ||
    "kigoma_refresh_secret_2026";

const DB_FILE =
    path.join(__dirname, "database.json");

const STORAGE_DIR =
    path.join(__dirname, "storage");

const MAX_FILE_SIZE =
    500 * 1024 * 1024;

/*
 * Production:
 *
 * Weka secrets kwenye environment variables:
 *
 * API_KEY
 * JWT_SECRET
 * REFRESH_SECRET
 *
 * Usitumie secrets za mfano hapo juu production.
 */

/* =========================================================
   DIRECTORIES
========================================================= */

if (!fs.existsSync(STORAGE_DIR)) {
    fs.mkdirSync(STORAGE_DIR, {
        recursive: true
    });
}

/* =========================================================
   EXPRESS
========================================================= */

app.disable("x-powered-by");

app.use(
    cors({
        origin:
            process.env.CORS_ORIGIN || "*",
        methods: [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS"
        ],
        allowedHeaders: [
            "Content-Type",
            "Authorization",
            "X-API-Key"
        ]
    })
);

app.use(
    express.json({
        limit: "10mb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "10mb"
    })
);

/* =========================================================
   BASIC SECURITY HEADERS
========================================================= */

app.use((req, res, next) => {

    res.setHeader(
        "X-Content-Type-Options",
        "nosniff"
    );

    res.setHeader(
        "X-Frame-Options",
        "DENY"
    );

    res.setHeader(
        "Referrer-Policy",
        "no-referrer"
    );

    res.setHeader(
        "X-XSS-Protection",
        "0"
    );

    next();
});

/* =========================================================
   DATABASE
========================================================= */

function createDatabase() {

    return {
        users: {},
        data: {},
        files: {},
        refreshTokens: {}
    };
}

function readDB() {

    try {

        if (!fs.existsSync(DB_FILE)) {

            const db =
                createDatabase();

            fs.writeFileSync(
                DB_FILE,
                JSON.stringify(
                    db,
                    null,
                    2
                ),
                "utf8"
            );

            return db;
        }

        const content =
            fs.readFileSync(
                DB_FILE,
                "utf8"
            );

        if (!content.trim()) {
            return createDatabase();
        }

        const db =
            JSON.parse(content);

        db.users =
            db.users || {};

        db.data =
            db.data || {};

        db.files =
            db.files || {};

        db.refreshTokens =
            db.refreshTokens || {};

        return db;

    } catch (error) {

        console.error(
            "DATABASE READ ERROR:",
            error
        );

        throw new Error(
            "Database haisomeki vizuri"
        );
    }
}

/*
 * Atomic write.
 */
function saveDB(db) {

    const tempFile =
        DB_FILE +
        "." +
        process.pid +
        ".tmp";

    fs.writeFileSync(
        tempFile,
        JSON.stringify(
            db,
            null,
            2
        ),
        "utf8"
    );

    fs.renameSync(
        tempFile,
        DB_FILE
    );
}

/* =========================================================
   UTILS
========================================================= */

function generateId(
    prefix = "id"
) {

    return (
        prefix +
        "_" +
        crypto.randomUUID()
    );
}

function now() {
    return new Date().toISOString();
}

function normalizeEmail(email) {

    return String(email)
        .trim()
        .toLowerCase();
}

function sanitizeUser(user) {

    if (!user) {
        return null;
    }

    return {
        uid: user.uid,
        email: user.email,
        displayName:
            user.displayName || null,
        photoURL:
            user.photoURL || null,
        role:
            user.role || "user",
        createdAt:
            user.createdAt,
        updatedAt:
            user.updatedAt
    };
}

function findUserByUid(
    db,
    uid
) {

    return Object.values(
        db.users
    ).find(
        user =>
            user.uid === uid
    );
}

function isObject(value) {

    return (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value)
    );
}

/* =========================================================
   PATH SECURITY
========================================================= */

function splitPath(input) {

    const value =
        String(input || "")
            .replace(/^\/+|\/+$/g, "");

    if (!value) {
        return [];
    }

    const parts =
        value.split("/");

    /*
     * Zuia path traversal.
     */
    for (const part of parts) {

        if (
            part === "." ||
            part === ".." ||
            part.includes("\\") ||
            part.includes("\0")
        ) {

            throw new Error(
                "Invalid database path"
            );
        }
    }

    return parts;
}

function pathToString(parts) {

    return "/" +
        parts.join("/");
}

/* =========================================================
   API KEY
========================================================= */

function requireApiKey(
    req,
    res,
    next
) {

    const key =
        req.headers["x-api-key"] ||
        req.query.api_key;

    if (
        !key ||
        key !== API_KEY
    ) {

        return res.status(403).json({
            success: false,
            error:
                "API key si sahihi au haipo"
        });
    }

    next();
}

/* =========================================================
   RATE LIMITER
========================================================= */

const rateLimitStore =
    new Map();

function rateLimit(
    options = {}
) {

    const windowMs =
        options.windowMs ||
        60 * 1000;

    const max =
        options.max ||
        20;

    return (req, res, next) => {

        const ip =
            req.ip ||
            req.connection.remoteAddress ||
            "unknown";

        const key =
            options.keyPrefix
                ? options.keyPrefix +
                  ":" +
                  ip
                : ip;

        const current =
            Date.now();

        let record =
            rateLimitStore.get(key);

        if (
            !record ||
            current - record.start >
                windowMs
        ) {

            record = {
                start: current,
                count: 0
            };
        }

        record.count++;

        rateLimitStore.set(
            key,
            record
        );

        if (
            record.count > max
        ) {

            return res.status(429).json({
                success: false,
                error:
                    "Requests nyingi sana. Tafadhali jaribu tena baadaye."
            });
        }

        next();
    };
}

/*
 * Safisha rate limiter mara kwa mara.
 */
setInterval(() => {

    const current =
        Date.now();

    for (
        const [key, record]
        of rateLimitStore
    ) {

        if (
            current - record.start >
            10 * 60 * 1000
        ) {

            rateLimitStore.delete(
                key
            );
        }
    }

}, 10 * 60 * 1000);

/* =========================================================
   JWT
========================================================= */

function createAccessToken(
    user
) {

    return jwt.sign(
        {
            uid: user.uid,
            email: user.email,
            role:
                user.role || "user"
        },
        JWT_SECRET,
        {
            expiresIn: "30m"
        }
    );
}

function createRefreshToken(
    user
) {

    return jwt.sign(
        {
            uid: user.uid
        },
        REFRESH_SECRET,
        {
            expiresIn: "30d"
        }
    );
}

function hashRefreshToken(
    token
) {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function verifyToken(
    req,
    res,
    next
) {

    const authorization =
        req.headers.authorization;

    if (!authorization) {

        return res.status(401).json({
            success: false,
            error:
                "Authorization token inahitajika"
        });
    }

    const parts =
        authorization.trim()
            .split(/\s+/);

    if (
        parts.length !== 2 ||
        parts[0] !== "Bearer"
    ) {

        return res.status(401).json({
            success: false,
            error:
                "Tumia Authorization: Bearer TOKEN"
        });
    }

    jwt.verify(
        parts[1],
        JWT_SECRET,
        (error, decoded) => {

            if (error) {

                return res.status(401).json({
                    success: false,
                    error:
                        "Token imeisha au si sahihi"
                });
            }

            const db =
                readDB();

            const user =
                findUserByUid(
                    db,
                    decoded.uid
                );

            if (!user) {

                return res.status(401).json({
                    success: false,
                    error:
                        "Mtumiaji wa token hii hayupo"
                });
            }

            req.user = {
                uid: user.uid,
                email: user.email,
                role:
                    user.role || "user"
            };

            next();
        }
    );
}

/* =========================================================
   ADMIN MIDDLEWARE
========================================================= */

function requireAdmin(
    req,
    res,
    next
) {

    if (
        !req.user ||
        req.user.role !== "admin"
    ) {

        return res.status(403).json({
            success: false,
            error:
                "Admin permission inahitajika"
        });
    }

    next();
}

/* =========================================================
   DATABASE SECURITY RULES
========================================================= */

/*
 * Firebase-style rules.
 *
 * public:
 *     Mtu yeyote hata bila login.
 *
 * authenticated:
 *     User aliye-login.
 *
 * owner:
 *     User anayemiliki UID iliyo kwenye
 *     sehemu ya pili ya path.
 *
 * admin:
 *     User mwenye role = admin.
 */

const DATABASE_RULES = {

    users: {
        read: "owner",
        write: "owner"
    },

    profiles: {
        read: "authenticated",
        write: "owner"
    },

    messages: {
        read: "authenticated",
        write: "authenticated"
    },

    posts: {
        read: "public",
        write: "authenticated"
    },

    public: {
        read: "public",
        write: "authenticated"
    },

    settings: {
        read: "authenticated",
        write: "admin"
    },

    admin: {
        read: "admin",
        write: "admin"
    }
};

function checkDatabaseRule(
    req,
    parts,
    action
) {

    if (!parts.length) {
        return false;
    }

    const collection =
        parts[0];

    const rule =
        DATABASE_RULES[
            collection
        ];

    /*
     * Collection ambayo haina rule
     * imefungwa kabisa.
     */
    if (!rule) {
        return false;
    }

    const permission =
        rule[action];

    if (!permission) {
        return false;
    }

    if (
        permission === "public"
    ) {
        return true;
    }

    if (
        permission === "authenticated"
    ) {

        return !!req.user;
    }

    if (
        permission === "admin"
    ) {

        return (
            !!req.user &&
            req.user.role === "admin"
        );
    }

    if (
        permission === "owner"
    ) {

        if (!req.user) {
            return false;
        }

        /*
         * /users/{uid}
         *
         * /profiles/{uid}
         */
        const targetUid =
            parts[1];

        return (
            targetUid ===
            req.user.uid
        );
    }

    return false;
}

/* =========================================================
   DATABASE OBJECT FUNCTIONS
========================================================= */

function getPathObject(
    root,
    parts
) {

    let current = root;

    for (
        const part of parts
    ) {

        if (
            current === null ||
            typeof current !==
                "object"
        ) {

            return undefined;
        }

        current =
            current[part];
    }

    return current;
}

function setPathObject(
    root,
    parts,
    value
) {

    if (!parts.length) {
        throw new Error(
            "Empty database path"
        );
    }

    let current = root;

    for (
        let i = 0;
        i < parts.length - 1;
        i++
    ) {

        const part =
            parts[i];

        if (
            !current[part] ||
            typeof current[part] !==
                "object" ||
            Array.isArray(
                current[part]
            )
        ) {

            current[part] = {};
        }

        current =
            current[part];
    }

    current[
        parts[parts.length - 1]
    ] = value;
}

function deletePathObject(
    root,
    parts
) {

    if (!parts.length) {
        return false;
    }

    let current = root;

    for (
        let i = 0;
        i < parts.length - 1;
        i++
    ) {

        if (
            !current[parts[i]]
        ) {

            return false;
        }

        current =
            current[parts[i]];
    }

    const last =
        parts[
            parts.length - 1
        ];

    if (
        Object.prototype
            .hasOwnProperty.call(
                current,
                last
            )
    ) {

        delete current[last];

        return true;
    }

    return false;
}

/* =========================================================
   ROOT
========================================================= */

app.get(
    "/",
    (req, res) => {

        res.status(403).json({

            success: false,

            service:
                "KigomaDB",

            message:
                "API access required"
        });
    }
);

/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/health",
    (req, res) => {

        res.json({

            success: true,

            service:
                "KigomaDB",

            status:
                "online",

            authentication:
                true,

            database:
                true,

            realtime:
                true,

            storage:
                true,

            securityRules:
                true,

            time:
                now()
        });
    }
);

/* =========================================================
   AUTHENTICATION
========================================================= */

/* =========================
   SIGNUP
========================= */

app.post(
    "/v1/auth/signup",
    requireApiKey,
    rateLimit({
        windowMs:
            15 * 60 * 1000,
        max: 10,
        keyPrefix:
            "signup"
    }),
    async (req, res) => {

        try {

            const {
                email,
                password,
                displayName,
                photoURL
            } = req.body;

            if (
                !email ||
                !password
            ) {

                return res.status(400)
                    .json({
                        success: false,
                        error:
                            "Email na password vinahitajika"
                    });
            }

            if (
                String(password)
                    .length < 6
            ) {

                return res.status(400)
                    .json({
                        success: false,
                        error:
                            "Password lazima iwe na angalau characters 6"
                    });
            }

            const normalizedEmail =
                normalizeEmail(
                    email
                );

            const db =
                readDB();

            if (
                db.users[
                    normalizedEmail
                ]
            ) {

                return res.status(409)
                    .json({
                        success: false,
                        error:
                            "Email hii imeshasajiliwa tayari"
                    });
            }

            const uid =
                generateId("user");

            const passwordHash =
                await bcrypt.hash(
                    String(password),
                    12
                );

            const user = {

                uid,

                email:
                    normalizedEmail,

                password:
                    passwordHash,

                displayName:
                    displayName
                        ? String(
                            displayName
                        ).trim()
                        : null,

                photoURL:
                    photoURL
                        ? String(
                            photoURL
                        ).trim()
                        : null,

                role:
                    "user",

                createdAt:
                    now(),

                updatedAt:
                    now()
            };

            /*
             * Email ndiyo key ya lookup.
             * UID ni permanent identity.
             */
            db.users[
                normalizedEmail
            ] = user;

            const accessToken =
                createAccessToken(
                    user
                );

            const refreshToken =
                createRefreshToken(
                    user
                );

            const refreshHash =
                hashRefreshToken(
                    refreshToken
                );

            db.refreshTokens[
                refreshHash
            ] = {

                uid:
                    user.uid,

                createdAt:
                    now()
            };

            saveDB(db);

            res.status(201)
                .json({

                    success: true,

                    uid:
                        user.uid,

                    user:
                        sanitizeUser(
                            user
                        ),

                    accessToken,

                    refreshToken,

                    message:
                        "Usajili umefanikiwa"
                });

        } catch (error) {

            console.error(
                "SIGNUP ERROR:",
                error
            );

            res.status(500)
                .json({

                    success: false,

                    error:
                        "Signup failed"
                });
        }
    }
);

/* =========================
   SIGNIN
========================= */

app.post(
    "/v1/auth/signin",
    requireApiKey,
    rateLimit({
        windowMs:
            15 * 60 * 1000,
        max: 15,
        keyPrefix:
            "signin"
    }),
    async (req, res) => {

        try {

            const {
                email,
                password
            } = req.body;

            if (
                !email ||
                !password
            ) {

                return res.status(400)
                    .json({
                        success: false,
                        error:
                            "Email na password vinahitajika"
                    });
            }

            const normalizedEmail =
                normalizeEmail(
                    email
                );

            const db =
                readDB();

            /*
             * HAPA NDIPO UID YA ZAMANI
             * INAPATIKANA KWA EMAIL.
             */
            const user =
                db.users[
                    normalizedEmail
                ];

            if (!user) {

                return res.status(401)
                    .json({
                        success: false,
                        error:
                            "Email hii haipo kwenye mfumo"
                    });
            }

            const valid =
                await bcrypt.compare(
                    String(password),
                    user.password
                );

            if (!valid) {

                return res.status(401)
                    .json({
                        success: false,
                        error:
                            "Password imekosewa"
                    });
            }

            /*
             * MUHIMU:
             *
             * Hatuundi UID mpya.
             *
             * Tunatumia:
             *
             * user.uid
             *
             * iliyohifadhiwa wakati wa signup.
             */
            const uid =
                user.uid;

            const accessToken =
                createAccessToken(
                    user
                );

            const refreshToken =
                createRefreshToken(
                    user
                );

            const refreshHash =
                hashRefreshToken(
                    refreshToken
                );

            db.refreshTokens[
                refreshHash
            ] = {

                uid,

                createdAt:
                    now()
            };

            saveDB(db);

            res.json({

                success: true,

                uid,

                user:
                    sanitizeUser(
                        user
                    ),

                accessToken,

                refreshToken,

                message:
                    "Umeingia kwa mafanikio"
            });

        } catch (error) {

            console.error(
                "SIGNIN ERROR:",
                error
            );

            res.status(500)
                .json({

                    success: false,

                    error:
                        "Signin failed"
                });
        }
    }
);

/* =========================================================
   REFRESH TOKEN
========================================================= */

app.post(
    "/v1/auth/refresh",
    requireApiKey,
    rateLimit({
        windowMs:
            15 * 60 * 1000,
        max: 30,
        keyPrefix:
            "refresh"
    }),
    (req, res) => {

        try {

            const {
                refreshToken
            } = req.body;

            if (
                !refreshToken
            ) {

                return res.status(400)
                    .json({

                        success: false,

                        error:
                            "Refresh token inahitajika"
                    });
            }

            const refreshHash =
                hashRefreshToken(
                    refreshToken
                );

            const db =
                readDB();

            const stored =
                db.refreshTokens[
                    refreshHash
                ];

            if (!stored) {

                return res.status(401)
                    .json({

                        success: false,

                        error:
                            "Refresh token si sahihi au ime-revoke"
                    });
            }

            jwt.verify(
                refreshToken,
                REFRESH_SECRET,
                (error, decoded) => {

                    if (error) {

                        delete db
                            .refreshTokens[
                                refreshHash
                            ];

                        saveDB(db);

                        return res
                            .status(401)
                            .json({

                                success: false,

                                error:
                                    "Refresh token imeisha"
                            });
                    }

                    if (
                        decoded.uid !==
                        stored.uid
                    ) {

                        return res
                            .status(401)
                            .json({

                                success: false,

                                error:
                                    "Refresh token identity si sahihi"
                            });
                    }

                    const user =
                        findUserByUid(
                            db,
                            decoded.uid
                        );

                    if (!user) {

                        return res
                            .status(404)
                            .json({

                                success: false,

                                error:
                                    "User haipatikani"
                            });
                    }

                    const accessToken =
                        createAccessToken(
                            user
                        );

                    res.json({

                        success: true,

                        uid:
                            user.uid,

                        accessToken,

                        message:
                            "Access token mpya imetengenezwa"
                    });
                }
            );

        } catch (error) {

            console.error(
                "REFRESH ERROR:",
                error
            );

            res.status(500)
                .json({

                    success: false,

                    error:
                        "Refresh failed"
                });
        }
    }
);

/* =========================================================
   AUTH ME
========================================================= */

app.get(
    "/v1/auth/me",
    requireApiKey,
    verifyToken,
    (req, res) => {

        const db =
            readDB();

        const user =
            findUserByUid(
                db,
                req.user.uid
            );

        if (!user) {

            return res.status(404)
                .json({

                    success: false,

                    error:
                        "User haipatikani"
                });
        }

        res.json({

            success: true,

            uid:
                user.uid,

            user:
                sanitizeUser(
                    user
                )
        });
    }
);

/* =========================================================
   UPDATE PROFILE
========================================================= */

app.patch(
    "/v1/auth/profile",
    requireApiKey,
    verifyToken,
    (req, res) => {

        const db =
            readDB();

        const user =
            findUserByUid(
                db,
                req.user.uid
            );

        if (!user) {

            return res.status(404)
                .json({

                    success: false,

                    error:
                        "User haipatikani"
                });
        }

        if (
            req.body.displayName !==
            undefined
        ) {

            user.displayName =
                String(
                    req.body.displayName
                ).trim();
        }

        if (
            req.body.photoURL !==
            undefined
        ) {

            user.photoURL =
                String(
                    req.body.photoURL
                ).trim();
        }

        /*
         * User hawezi kubadilisha:
         *
         * uid
         * email
         * password hash
         * role
         */
        user.updatedAt =
            now();

        saveDB(db);

        const cleanUser =
            sanitizeUser(
                user
            );

        io.emit(
            "user.updated",
            {
                uid:
                    user.uid,
                user:
                    cleanUser
            }
        );

        res.json({

            success: true,

            uid:
                user.uid,

            user:
                cleanUser,

            message:
                "Profile imebadilishwa"
        });
    }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
    "/v1/auth/logout",
    requireApiKey,
    verifyToken,
    (req, res) => {

        try {

            const {
                refreshToken
            } = req.body;

            const db =
                readDB();

            if (
                refreshToken
            ) {

                const hash =
                    hashRefreshToken(
                        refreshToken
                    );

                delete db
                    .refreshTokens[
                        hash
                    ];
            }

            saveDB(db);

            res.json({

                success: true,

                message:
                    "Umetoka kwenye mfumo"
            });

        } catch (error) {

            res.status(500)
                .json({

                    success: false,

                    error:
                        "Logout failed"
                });
        }
    }
);

/* =========================================================
   DATABASE GET
========================================================= */

app.get(
    /^\/v1\/db\/(.+)$/,
    requireApiKey,
    verifyToken,
    (req, res) => {

        try {

            const pathString =
                req.params[0];

            const parts =
                splitPath(
                    pathString
                );

            if (!parts.length) {

                return res.status(400)
                    .json({

                        success: false,

                        error:
                            "Database path haipo"
                    });
            }

            /*
             * SECURITY RULE
             */
            if (
                !checkDatabaseRule(
                    req,
                    parts,
                    "read"
                )
            ) {

                return res.status(403)
                    .json({

                        success: false,

                        error:
                            "Huna ruhusa ya kusoma data hii"
                    });
            }

            const db =
                readDB();

            const value =
                getPathObject(
                    db.data,
                    parts
                );

            res.json({

                success: true,

                path:
                    pathToString(
                        parts
                    ),

                data:
                    value === undefined
                        ? null
                        : value
            });

        } catch (error) {

            res.status(400)
                .json({

                    success: false,

                    error:
                        error.message
                });
        }
    }
);

/* =========================================================
   DATABASE PUT
========================================================= */

app.put(
    /^\/v1\/db\/(.+)$/,
    requireApiKey,
    verifyToken,
    (req, res) => {

        try {

            const parts =
                splitPath(
                    req.params[0]
                );

            if (!parts.length) {

                return res.status(400)
                    .json({

                        success: false,

                        error:
                            "Database path haipo"
                    });
            }

            /*
             * SECURITY RULE
             */
            if (
                !checkDatabaseRule(
                    req,
                    parts,
                    "write"
                )
            ) {

                return res.status(403)
                    .json({

                        success: false,

                        error:
                            "Huna ruhusa ya kuandika data hii"
                    });
            }

            if (
                !isObject(
                    req.body
                )
            ) {

                return res.status(400)
                    .json({

                        success: false,

                        error:
                            "Data lazima iwe JSON object"
                    });
            }

            /*
             * Zuia client kubadili
             * security fields.
             */
            const data = {
                ...req.body
            };

            delete data.uid;
            delete data.role;
            delete data.password;
            delete data.email;

            data.updatedAt =
                now();

            const db =
                readDB();

            setPathObject(
                db.data,
                parts,
                data
            );

            saveDB(db);

            const fullPath =
                pathToString(
                    parts
                );

            const payload = {

                path:
                    fullPath,

                data,

                uid:
                    req.user.uid,

                timestamp:
                    now()
            };

            io.emit(
                "database.updated",
                payload
            );

            io.to(
                "path:" +
                fullPath
            ).emit(
                "value.changed",
                payload
            );

            res.json({

                success: true,

                path:
                    fullPath,

                data,

                message:
                    "Data imehifadhiwa"
            });

        } catch (error) {

            res.status(400)
                .json({

                    success: false,

                    error:
                        error.message
                });
        }
    }
);

/* =========================================================
   DATABASE PATCH
========================================================= */

app.patch(
    /^\/v1\/db\/(.+)$/,
    requireApiKey,
    verifyToken,
    (req, res) => {

        try {

            const parts =
                splitPath(
                    req.params[0]
                );

            if (!parts.length) {

                return res.status(400)
                    .json({

                        success: false,

                        error:
                            "Database path haipo"
                    });
            }

            if (
                !checkDatabaseRule(
                    req,
                    parts,
                    "write"
                )
            ) {

                return res.status(403)
                    .json({

                        success: false,

                        error:
                            "Huna ruhusa ya ku-update data hii"
                    });
            }

            if (
                !isObject(
                    req.body
                )
            ) {

                return res.status(400)
                    .json({

                        success: false,

                        error:
                            "Data lazima iwe JSON object"
                    });
            }

            const db =
                readDB();

            let current =
                getPathObject(
                    db.data,
                    parts
                );

            const patch = {
                ...req.body
            };

            delete patch.uid;
            delete patch.role;
            delete patch.password;
            delete patch.email;

            if (
                !isObject(
                    current
                )
            ) {

                current = {};
            }

            Object.assign(
                current,
                patch
            );

            current.updatedAt =
                now();

            setPathObject(
                db.data,
                parts,
                current
            );

            saveDB(db);

            const fullPath =
                pathToString(
                    parts
                );

            const payload = {

                path:
                    fullPath,

                data:
                    current,

                uid:
                    req.user.uid,

                timestamp:
                    now()
            };

            io.emit(
                "database.updated",
                payload
            );

            io.to(
                "path:" +
                fullPath
            ).emit(
                "value.changed",
                payload
            );

            res.json({

                success: true,

                path:
                    fullPath,

                data:
                    current,

                message:
                    "Data ime-update"
            });

        } catch (error) {

            res.status(400)
                .json({

                    success: false,

                    error:
                        error.message
                });
        }
    }
);

/* =========================================================
   DATABASE POST
========================================================= */

app.post(
    /^\/v1\/db\/(.+)$/,
    requireApiKey,
    verifyToken,
    (req, res) => {

        try {

            const parts =
                splitPath(
                    req.params[0]
                );

            if (!parts.length) {

                return res.status(400)
                    .json({

                        success: false,

                        error:
                            "Database path haipo"
                    });
            }

            if (
                !checkDatabaseRule(
                    req,
                    parts,
                    "write"
                )
            ) {

                return res.status(403)
                    .json({

                        success: false,

                        error:
                            "Huna ruhusa ya kuandika data hii"
                    });
            }

            if (
                !isObject(
                    req.body
                )
            ) {

                return res.status(400)
                    .json({

                        success: false,

                        error:
                            "Data lazima iwe JSON object"
                    });
            }

            const db =
                readDB();

            const id =
                req.body.id ||
                generateId(
                    "record"
                );

            const record = {
                ...req.body,
                id,
                createdAt:
                    now(),
                updatedAt:
                    now()
            };

            /*
             * Zuia security fields
             */
            delete record.uid;
            delete record.role;
            delete record.password;

            let collection =
                getPathObject(
                    db.data,
                    parts
                );

            if (
                !isObject(
                    collection
                )
            ) {

                collection = {};

                setPathObject(
                    db.data,
                    parts,
                    collection
                );
            }

            collection[id] =
                record;

            saveDB(db);

            const fullPath =
                pathToString(
                    parts
                ) +
                "/" +
                id;

            const payload = {

                path:
                    fullPath,

                data:
                    record,

                uid:
                    req.user.uid,

                timestamp:
                    now()
            };

            io.emit(
                "database.created",
                payload
            );

            io.to(
                "path:" +
                fullPath
            ).emit(
                "value.created",
                payload
            );

            res.status(201)
                .json({

                    success: true,

                    id,

                    path:
                        fullPath,

                    data:
                        record
                });

        } catch (error) {

            res.status(400)
                .json({

                    success: false,

                    error:
                        error.message
                });
        }
    }
);

/* =========================================================
   DATABASE DELETE
========================================================= */

app.delete(
    /^\/v1\/db\/(.+)$/,
    requireApiKey,
    verifyToken,
    (req, res) => {

        try {

            const parts =
                splitPath(
                    req.params[0]
                );

            if (!parts.length) {

                return res.status(400)
                    .json({

                        success: false,

                        error:
                            "Database path haipo"
                    });
            }

            if (
                !checkDatabaseRule(
                    req,
                    parts,
                    "write"
                )
            ) {

                return res.status(403)
                    .json({

                        success: false,

                        error:
                            "Huna ruhusa ya kufuta data hii"
                    });
            }

            const db =
                readDB();

            const deleted =
                deletePathObject(
                    db.data,
                    parts
                );

            if (!deleted) {

                return res.status(404)
                    .json({

                        success: false,

                        error:
                            "Data haikupatikana"
                    });
            }

            saveDB(db);

            const fullPath =
                pathToString(
                    parts
                );

            const payload = {

                path:
                    fullPath,

                uid:
                    req.user.uid,

                timestamp:
                    now()
            };

            io.emit(
                "database.deleted",
                payload
            );

            io.to(
                "path:" +
                fullPath
            ).emit(
                "value.deleted",
                payload
            );

            res.json({

                success: true,

                path:
                    fullPath,

                message:
                    "Data imefutwa"
            });

        } catch (error) {

            res.status(400)
                .json({

                    success: false,

                    error:
                        error.message
                });
        }
    }
);

/* =========================================================
   REALTIME SOCKET.IO AUTH
========================================================= */

io.use(
    (socket, next) => {

        try {

            const apiKey =
                socket.handshake
                    .auth
                    ?.apiKey;

            if (
                apiKey !==
                API_KEY
            ) {

                return next(
                    new Error(
                        "Invalid API key"
                    )
                );
            }

            const token =
                socket.handshake
                    .auth
                    ?.token;

            if (!token) {

                return next(
                    new Error(
                        "Token required"
                    )
                );
            }

            const decoded =
                jwt.verify(
                    token,
                    JWT_SECRET
                );

            const db =
                readDB();

            const user =
                findUserByUid(
                    db,
                    decoded.uid
                );

            if (!user) {

                return next(
                    new Error(
                        "User not found"
                    )
                );
            }

            socket.user = {

                uid:
                    user.uid,

                email:
                    user.email,

                role:
                    user.role ||
                    "user"
            };

            next();

        } catch (error) {

            next(
                new Error(
                    "Authentication failed"
                )
            );
        }
    }
);

/* =========================================================
   REALTIME
========================================================= */

io.on(
    "connection",
    (socket) => {

        console.log(
            "Realtime connected:",
            socket.user.uid
        );

        socket.emit(
            "connected",
            {

                success: true,

                uid:
                    socket.user.uid,

                timestamp:
                    now()
            }
        );

        /* =========================
           SUBSCRIBE
        ========================= */

        socket.on(
            "subscribe",
            (pathString) => {

                try {

                    if (
                        !pathString
                    ) {
                        return;
                    }

                    const parts =
                        splitPath(
                            pathString
                        );

                    /*
                     * Realtime read rule
                     */
                    const fakeReq = {
                        user:
                            socket.user
                    };

                    if (
                        !checkDatabaseRule(
                            fakeReq,
                            parts,
                            "read"
                        )
                    ) {

                        socket.emit(
                            "permission.denied",
                            {
                                path:
                                    pathString,
                                error:
                                    "Huna ruhusa ya kusubscribe kwenye data hii"
                            }
                        );

                        return;
                    }

                    const room =
                        "path:" +
                        pathToString(
                            parts
                        );

                    socket.join(
                        room
                    );

                    const db =
                        readDB();

                    const data =
                        getPathObject(
                            db.data,
                            parts
                        );

                    socket.emit(
                        "initial.value",
                        {

                            path:
                                pathToString(
                                    parts
                                ),

                            data:
                                data ===
                                undefined
                                    ? null
                                    : data
                        }
                    );

                } catch (error) {

                    socket.emit(
                        "error",
                        {
                            message:
                                error.message
                        }
                    );
                }
            }
        );

        /* =========================
           UNSUBSCRIBE
        ========================= */

        socket.on(
            "unsubscribe",
            (pathString) => {

                try {

                    if (
                        !pathString
                    ) {
                        return;
                    }

                    const parts =
                        splitPath(
                            pathString
                        );

                    socket.leave(
                        "path:" +
                        pathToString(
                            parts
                        )
                    );

                } catch (error) {

                    console.error(
                        error
                    );
                }
            }
        );

        /* =========================
           DISCONNECT
        ========================= */

        socket.on(
            "disconnect",
            () => {

                console.log(
                    "Realtime disconnected:",
                    socket.user.uid
                );
            }
        );
    }
);

/* =========================================================
   STORAGE
========================================================= */

const storage =
    multer.diskStorage({

        destination:
            (req, file, cb) => {

                cb(
                    null,
                    STORAGE_DIR
                );
            },

        filename:
            (req, file, cb) => {

                const extension =
                    path.extname(
                        file.originalname
                    )
                    .toLowerCase();

                const filename =
                    crypto.randomUUID() +
                    extension;

                cb(
                    null,
                    filename
                );
            }
    });

/*
 * File types zinazoruhusiwa.
 *
 * Unaweza kuongeza zaidi.
 */
const ALLOWED_MIME_TYPES = [

    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",

    "video/mp4",
    "video/webm",
    "video/quicktime",

    "audio/mpeg",
    "audio/mp4",
    "audio/wav",
    "audio/ogg",

    "application/pdf",

    "text/plain",

    "application/zip"
];

const upload =
    multer({

        storage,

        limits: {

            fileSize:
                MAX_FILE_SIZE
        },

        fileFilter:
            (req, file, cb) => {

                if (
                    ALLOWED_MIME_TYPES
                        .includes(
                            file.mimetype
                        )
                ) {

                    cb(
                        null,
                        true
                    );

                } else {

                    cb(
                        new Error(
                            "Aina ya file hairuhusiwi"
                        )
                    );
                }
            }
    });

/* =========================================================
   STORAGE UPLOAD
========================================================= */

app.post(
    "/v1/storage/upload",
    requireApiKey,
    verifyToken,
    upload.single("file"),
    (req, res) => {

        try {

            if (
                !req.file
            ) {

                return res.status(400)
                    .json({

                        success: false,

                        error:
                            "Faili halijatumwa"
                    });
            }

            const db =
                readDB();

            const fileId =
                generateId(
                    "file"
                );

            const fileData = {

                id:
                    fileId,

                uid:
                    req.user.uid,

                originalName:
                    req.file
                        .originalname,

                fileName:
                    req.file.filename,

                mimeType:
                    req.file.mimetype,

                size:
                    req.file.size,

                createdAt:
                    now()
            };

            /*
             * URL ya file inalindwa
             * na JWT/API key.
             */
            fileData.url =
                `${req.protocol}://${req.get("host")}/v1/storage/file/${fileId}`;

            db.files[
                fileId
            ] = fileData;

            saveDB(db);

            io.emit(
                "storage.created",
                {
                    file:
                        fileData
                }
            );

            res.status(201)
                .json({

                    success: true,

                    file:
                        fileData,

                    message:
                        "Faili limehifadhiwa"
                });

        } catch (error) {

            console.error(
                "UPLOAD ERROR:",
                error
            );

            /*
             * Kama metadata imeshindwa,
             * jaribu kuondoa file.
             */
            if (
                req.file
            ) {

                const filePath =
                    path.join(
                        STORAGE_DIR,
                        req.file.filename
                    );

                if (
                    fs.existsSync(
                        filePath
                    )
                ) {

                    try {
                        fs.unlinkSync(
                            filePath
                        );
                    } catch (_) {}
                }
            }

            res.status(500)
                .json({

                    success: false,

                    error:
                        error.message
                });
        }
    }
);

/* =========================================================
   STORAGE FILE
========================================================= */

app.get(
    "/v1/storage/file/:id",
    requireApiKey,
    verifyToken,
    (req, res) => {

        try {

            const db =
                readDB();

            const file =
                db.files[
                    req.params.id
                ];

            if (!file) {

                return res.status(404)
                    .json({

                        success: false,

                        error:
                            "File haipatikani"
                    });
            }

            /*
             * OWNER AU ADMIN
             */
            if (
                file.uid !==
                    req.user.uid &&
                req.user.role !==
                    "admin"
            ) {

                return res.status(403)
                    .json({

                        success: false,

                        error:
                            "Huna ruhusa ya kuona file hii"
                    });
            }

            const filePath =
                path.resolve(
                    STORAGE_DIR,
                    file.fileName
                );

            /*
             * Zuia path traversal.
             */
            const storageRoot =
                path.resolve(
                    STORAGE_DIR
                );

            if (
                !filePath.startsWith(
                    storageRoot +
                    path.sep
                )
            ) {

                return res.status(403)
                    .json({

                        success: false,

                        error:
                            "Invalid storage path"
                    });
            }

            if (
                !fs.existsSync(
                    filePath
                )
            ) {

                return res.status(404)
                    .json({

                        success: false,

                        error:
                            "File haipo kwenye storage"
                    });
            }

            res.sendFile(
                filePath
            );

        } catch (error) {

            res.status(500)
                .json({

                    success: false,

                    error:
                        "Storage error"
                });
        }
    }
);

/* =========================================================
   STORAGE METADATA
========================================================= */

app.get(
    "/v1/storage/:id",
    requireApiKey,
    verifyToken,
    (req, res) => {

        const db =
            readDB();

        const file =
            db.files[
                req.params.id
            ];

        if (!file) {

            return res.status(404)
                .json({

                    success: false,

                    error:
                        "File haipatikani"
                });
        }

        if (
            file.uid !==
                req.user.uid &&
            req.user.role !==
                "admin"
        ) {

            return res.status(403)
                .json({

                    success: false,

                    error:
                        "Huna ruhusa ya kuona metadata hii"
                });
        }

        res.json({

            success: true,

            file
        });
    }
);

/* =========================================================
   STORAGE DELETE
========================================================= */

app.delete(
    "/v1/storage/:id",
    requireApiKey,
    verifyToken,
    (req, res) => {

        try {

            const db =
                readDB();

            const file =
                db.files[
                    req.params.id
                ];

            if (!file) {

                return res.status(404)
                    .json({

                        success: false,

                        error:
                            "File haipatikani"
                    });
            }

            /*
             * OWNER AU ADMIN
             */
            if (
                file.uid !==
                    req.user.uid &&
                req.user.role !==
                    "admin"
            ) {

                return res.status(403)
                    .json({

                        success: false,

                        error:
                            "Huna ruhusa kufuta file hii"
                    });
            }

            const filePath =
                path.resolve(
                    STORAGE_DIR,
                    file.fileName
                );

            const storageRoot =
                path.resolve(
                    STORAGE_DIR
                );

            if (
                !filePath.startsWith(
                    storageRoot +
                    path.sep
                )
            ) {

                return res.status(403)
                    .json({

                        success: false,

                        error:
                            "Invalid storage path"
                    });
            }

            if (
                fs.existsSync(
                    filePath
                )
            ) {

                fs.unlinkSync(
                    filePath
                );
            }

            delete db.files[
                req.params.id
            ];

            saveDB(db);

            io.emit(
                "storage.deleted",
                {

                    id:
                        req.params.id,

                    uid:
                        req.user.uid
                }
            );

            res.json({

                success: true,

                message:
                    "File imefutwa"
            });

        } catch (error) {

            res.status(500)
                .json({

                    success: false,

                    error:
                        "Storage delete failed"
                });
        }
    }
);

/* =========================================================
   ADMIN - CHANGE USER ROLE
========================================================= */

app.patch(
    "/v1/admin/users/:uid/role",
    requireApiKey,
    verifyToken,
    requireAdmin,
    (req, res) => {

        const {
            role
        } = req.body;

        if (
            role !== "user" &&
            role !== "admin"
        ) {

            return res.status(400)
                .json({

                    success: false,

                    error:
                        "Role lazima iwe user au admin"
                });
        }

        const db =
            readDB();

        const user =
            findUserByUid(
                db,
                req.params.uid
            );

        if (!user) {

            return res.status(404)
                .json({

                    success: false,

                    error:
                        "User haipatikani"
                });
        }

        user.role =
            role;

        user.updatedAt =
            now();

        saveDB(db);

        res.json({

            success: true,

            uid:
                user.uid,

            role:
                user.role,

            message:
                "User role imebadilishwa"
        });
    }
);

/* =========================================================
   ADMIN - LIST USERS
========================================================= */

app.get(
    "/v1/admin/users",
    requireApiKey,
    verifyToken,
    requireAdmin,
    (req, res) => {

        const db =
            readDB();

        const users =
            Object.values(
                db.users
            ).map(
                sanitizeUser
            );

        res.json({

            success: true,

            count:
                users.length,

            users
        });
    }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "SERVER ERROR:",
            error
        );

        if (
            error instanceof
            multer.MulterError
        ) {

            if (
                error.code ===
                "LIMIT_FILE_SIZE"
            ) {

                return res.status(400)
                    .json({

                        success: false,

                        error:
                            "File ni kubwa kuliko 500MB"
                    });
            }

            return res.status(400)
                .json({

                    success: false,

                    error:
                        "Upload error: " +
                        error.message
                });
        }

        if (
            error &&
            error.message ===
                "Aina ya file hairuhusiwi"
        ) {

            return res.status(400)
                .json({

                    success: false,

                    error:
                        "Aina ya file hairuhusiwi"
                });
        }

        res.status(500)
            .json({

                success: false,

                error:
                    "Internal server error"
            });
    }
);

/* =========================================================
   404
========================================================= */

app.use(
    (req, res) => {

        res.status(404)
            .json({

                success: false,

                error:
                    "Endpoint haipatikani"
            });
    }
);

/* =========================================================
   SOCKET.IO ERROR
========================================================= */

io.engine.on(
    "connection_error",
    (err) => {

        console.error(
            "Socket connection error:",
            err.message
        );
    }
);

/* =========================================================
   SERVER
========================================================= */

server.listen(
    PORT,
    () => {

        console.log(
            "========================================"
        );

        console.log(
            "          KIGOMADB SERVER"
        );

        console.log(
            "========================================"
        );

        console.log(
            `HTTP: http://localhost:${PORT}`
        );

        console.log(
            "Authentication : ENABLED"
        );

        console.log(
            "UID System     : ENABLED"
        );

        console.log(
            "JWT            : ENABLED"
        );

        console.log(
            "Refresh Token  : ENABLED"
        );

        console.log(
            "Database       : ENABLED"
        );

        console.log(
            "Security Rules : ENABLED"
        );

        console.log(
            "Realtime       : ENABLED"
        );

        console.log(
            "Socket.IO      : ENABLED"
        );

        console.log(
            "Storage        : ENABLED"
        );

        console.log(
            "Admin System   : ENABLED"
        );

        console.log(
            "Rate Limiting  : ENABLED"
        );

        console.log(
            "========================================"
        );
    }
);
