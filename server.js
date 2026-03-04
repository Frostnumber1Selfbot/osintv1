/**
 * ============================================================================
 * TITAN OSINT KERNEL - ENTERPRISE EDITION v6.4.1
 * ============================================================================
 * Internal build for restricted access.
 * ----------------------------------------------------------------------------
 */

const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const axios = require('axios');
const http = require('http');

// --- SERVER CONSTANTS ---
const app = express();
const PORT = 3000;

// --- PERSISTENCE LAYER PATHS ---
const DB_PATH = path.join(__dirname, 'user.json');
const LOG_FILE = path.join(__dirname, 'relay.log');
const ERROR_LOG = path.join(__dirname, 'error.log');
const BACKUP_DIR = path.join(__dirname, 'backups');
const DATA_TXT_PATH = path.join(__dirname, 'views', 'data.txt');
const SYSTEM_STATE = path.join(__dirname, 'state.lock');

// --- API INTEGRATION REGISTRY ---
const CLUSTER_NODE = "http://94.249.230.111:8000";
const SHODAN_KEY = "ZInUV2niG7iKGxJBz9buYLc78qKxG5Mq"; 
const GHOSINT_KEY = "659239a4a836bf1d67a51102460867d8";
const NUMLOOKUP_KEY = "num_live_fngAi2HkDW2He2XXXU4FFAusGchy0gQ8BxnDSe1r";

/**
 * KERNEL INITIALIZATION SEQUENCE
 * Ensures all critical IO structures are present before boot.
 */
const initializeKernel = () => {
    console.log("[SYSTEM] Initializing Filesystem...");
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    
    const manifest = [
        { path: DATA_TXT_PATH, data: "TITAN_DATABASE_v1\n" },
        { path: LOG_FILE, data: "" },
        { path: ERROR_LOG, data: "" },
        { path: SYSTEM_STATE, data: Date.now().toString() }
    ];

    manifest.forEach(item => {
        if (!fs.existsSync(item.path)) {
            fs.mkdirSync(path.dirname(item.path), { recursive: true });
            fs.writeFileSync(item.path, item.data, 'utf8');
        }
    });
};
initializeKernel();

/**
 * WEB SERVER CONFIGURATION
 */
app.set('view engine', 'ejs');
app.set('views', [path.join(__dirname, '.'), path.join(__dirname, 'views')]);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));

app.use(session({
    name: 'TITAN_SID',
    secret: 'titan_omega_shards_9921_ultra_secure_entropy_raw_build_v6',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: { 
        maxAge: 3600000 * 24, 
        httpOnly: true, 
        secure: false,
        sameSite: 'lax'
    }
}));

/**
 * DATABASE KERNEL MODULE
 */
function loadDB() {
    try {
        if (!fs.existsSync(DB_PATH)) {
            const initial = { 
                users: [{ 
                    username: 'admin', 
                    password: '123', 
                    role: 'admin', 
                    locked: false, 
                    expiry: 4102444800000 
                }], 
                pending_keys: [], 
                audit: [] 
            };
            fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 4));
            return initial;
        }
        const data = fs.readFileSync(DB_PATH, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        console.error("CRITICAL_IO_READ_FAILURE:", err);
        return { users: [], pending_keys: [], audit: [] };
    }
}

function saveDB(data) {
    try {
        fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 4), 'utf8');
        return true;
    } catch (err) {
        console.error("CRITICAL_IO_WRITE_FAILURE:", err);
        return false;
    }
}

/**
 * AUDIT & TELEMETRY SYSTEMS
 */
function pushAudit(db, admin, action, target, extra = {}) {
    const entry = {
        id: crypto.randomBytes(4).toString('hex').toUpperCase(),
        timestamp: new Date().toLocaleString(),
        admin,
        action,
        target,
        pass: extra.pass || 'N/A',
        ip: extra.ip || '0.0.0.0',
        status: "SUCCESS"
    };
    if (!db.audit) db.audit = [];
    db.audit.unshift(entry);
    if (db.audit.length > 500) db.audit.pop();
}

function getMetrics() {
    const mem = process.memoryUsage();
    return {
        uptime: Math.floor(process.uptime() / 60),
        os_kernel: os.release(),
        mem_rss: `${(mem.rss / 1024 / 1024).toFixed(2)} MB`,
        mem_heap: `${(mem.heapUsed / 1024 / 1024).toFixed(2)} MB`,
        cpu_load: (os.loadavg()[0] * 100).toFixed(1),
        active_threads: os.cpus().length,
        platform: os.platform(),
        hostname: os.hostname(),
        arch: os.arch()
    };
}

/**
 * GATEKEEPER MIDDLEWARE
 */
const authenticate = (req, res, next) => {
    if (req.session.user) return next();
    if (req.xhr || req.path.startsWith('/api/')) return res.status(401).json({ error: "UNAUTHORIZED_ACCESS" });
    res.redirect('/login');
};

const authorizeAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.role === 'admin') return next();
    res.status(403).send("ACCESS_DENIED: INSUFFICIENT_PRIVILEGE");
};

/**
 * PAGE ROUTING
 */
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/dashboard');
    res.render('login', { msg: null });
});

app.get('/plans', (req, res) => res.render('plans'));

app.get('/dashboard', authenticate, (req, res) => {
    const db = loadDB();
    const u = db.users.find(x => x.username === req.session.user.username);
    if (!u) return res.redirect('/logout');

    let safeExpiry = "PERMANENT";
    if (u.role !== 'admin' && u.expiry) {
        const expiryDate = new Date(u.expiry);
        safeExpiry = isNaN(expiryDate.getTime()) ? "ERROR" : expiryDate.toISOString();
    }

    res.render('index', { 
        user: req.session.user, 
        expiry: safeExpiry 
    });
});

app.get('/admin', authenticate, authorizeAdmin, (req, res) => {
    const db = loadDB();
    res.render('admin', { 
        users: db.users, 
        keys: db.pending_keys || [], 
        audit: db.audit || [],
        metrics: getMetrics()
    });
});

/**
 * ADMIN API COMMAND CENTER
 * RESTORED: All admin functions from original build.
 */
app.post('/api/admin/action', authenticate, authorizeAdmin, (req, res) => {
    const { action, target, planType, customDays, customPass } = req.body;
    let db = loadDB();
    const realIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const adminUser = req.session.user.username;

    try {
        if (action === 'DELETE_KEY') {
            db.pending_keys = db.pending_keys.filter(k => k.key !== target);
            pushAudit(db, adminUser, "KEY_PURGE", target, { ip: realIp });
        }
        else if (action === 'GEN_KEY') {
            const keyStr = `TITAN-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
            db.pending_keys.push({ 
                key: keyStr, plan: planType || 'month', used: false, 
                genBy: adminUser, ts: Date.now() 
            });
            pushAudit(db, adminUser, "KEY_GEN", keyStr, { ip: realIp });
        }
        else if (action === 'CREATE_CUSTOM_USER') {
            if (db.users.find(u => u.username === target)) throw new Error("USER_EXISTS");
            const expiry = Date.now() + (parseInt(customDays || 30) * 86400000);
            db.users.push({ 
                username: target, password: customPass || '123', 
                role: 'user', locked: false, expiry 
            });
            pushAudit(db, adminUser, "MANUAL_INJECT", target, { ip: realIp, pass: customPass });
        }
        else if (action === 'RESET_PASS') {
            const user = db.users.find(u => u.username === target);
            if (!user) throw new Error("USER_NOT_FOUND");
            user.password = customPass;
            pushAudit(db, adminUser, "PASS_RESET", target, { ip: realIp, pass: customPass });
        }
        else if (action === 'TOGGLE_LOCK') {
            const user = db.users.find(u => u.username === target);
            if (user && target !== 'admin') {
                user.locked = !user.locked;
                pushAudit(db, adminUser, "LOCK_TOGGLE", target, { ip: realIp });
            }
        }
        else if (action === 'DELETE_USER') {
            if (target === 'admin') throw new Error("ROOT_IMMUTABLE");
            db.users = db.users.filter(u => u.username !== target);
            pushAudit(db, adminUser, "USER_WIPE", target, { ip: realIp });
        }
        else if (action === 'EXTEND_ALL') {
            const addedMs = parseInt(customDays) * 86400000;
            db.users.forEach(u => { if(u.role !== 'admin') u.expiry += addedMs; });
            pushAudit(db, adminUser, "BULK_EXTEND", `${customDays} Days`, { ip: realIp });
        }
        else if (action === 'PURGE_EXPIRED') {
            const initialCount = db.users.length;
            db.users = db.users.filter(u => u.role === 'admin' || u.expiry > Date.now());
            const purged = initialCount - db.users.length;
            pushAudit(db, adminUser, "BULK_PURGE", `${purged} Users`, { ip: realIp });
        }

        saveDB(db);
        res.json({ success: true });
    } catch (e) {
        console.error("ADMIN_ACTION_ERROR:", e.message);
        res.status(500).json({ success: false, error: e.message });
    }
});

/**
 * CORE RELAY INTERFACE
 * RESTORED: All output functions and custom Discord2Roblox script logic.
 */
app.post('/api/relay', authenticate, async (req, res) => {
    const { endpoint, query, type, isPhone, isGhosint, split, param } = req.body;
    const startTime = Date.now();
    const adminUser = req.session.user.username;
    
    if (!endpoint || !query) return res.status(400).json({ error: "ERR_INVALID_PARAMS" });
    
    const searchTerm = query.toLowerCase().trim();
    fs.appendFileSync(LOG_FILE, `[${new Date().toISOString()}] RELAY: ${adminUser} -> ${endpoint} [${query}]\n`);

    try {
        const axiosConfig = { timeout: 15000, headers: { 'User-Agent': 'Titan_Omega_Internal' } };
        let resultData;

        // --- SPECIAL HANDLER: DISCORD TO ROBLOX (EXACT SCRIPT LOGIC) ---
        if (endpoint === '/api/discord2roblox' || endpoint.includes('discord2roblox')) {
            try {
                // Request A: Eryn/Linkage API
                const erynResp = await axios.get(`https://verify.eryn.io/api/user/${query}`, axiosConfig);
                const jsn = erynResp.data;

                if (jsn && jsn.status === "ok") {
                    try {
                        // Request B: Roblox Users V1 API
                        const robloxResp = await axios.get(`https://users.roblox.com/v1/users/${jsn.robloxId}`, axiosConfig);
                        const jsn2 = robloxResp.data;

                        // Formatting exactly like your script output
                        resultData = {
                            "Status": `Successfully got data for id ${query}`,
                            "Roblox Id": jsn.robloxId,
                            "Roblox Username": jsn2.name ? `${jsn2.name} [${jsn.robloxUsername}]` : jsn.robloxUsername,
                            "Banned": jsn2.isBanned,
                            "Created at": jsn2.created ? (new Date(jsn2.created)).toLocaleDateString() : 'NA',
                            "Description": jsn2.description ? jsn2.description.split('\n').join('\n\t - ') : "None"
                        };
                    } catch (innerError) {
                        // Partial data fallback
                        resultData = {
                            "Status": "Was only able to get some data.",
                            "Roblox Id": jsn.robloxId,
                            "Roblox Username": jsn.robloxUsername
                        };
                    }
                } else {
                    throw new Error("NOT_LINKED");
                }
            } catch (outerError) {
                return res.json({ success: false, error: `Unable to find any results for ${query}` });
            }
        }

        // --- HANDLER: LOCAL BREACH DATABASE ---
        else if (endpoint === 'LOCAL_DISCORD_BREACH' || type === 'BREACH' || endpoint.includes('LOCAL')) {
            if (!fs.existsSync(DATA_TXT_PATH)) return res.json({ success: false, error: "SOURCE_OFFLINE" });

            const rawBuffer = fs.readFileSync(DATA_TXT_PATH);
            const rawContent = rawBuffer.toString('utf8').replace(/^\uFEFF/, '');
            const lines = rawContent.split(/\r?\n/).filter(line => line.trim().length > 0);
            
            resultData = lines
                .filter(line => line.toLowerCase().includes(searchTerm))
                .slice(0, 100)
                .map(line => {
                    const [email, ip, browser, username] = line.split(',');
                    return { email: email || "N/A", ip: ip || "N/A", browser: browser || "N/A", username: username || "N/A" };
                });
        }
        
        // --- HANDLER: PHONE LOOKUP ---
        else if (isPhone || endpoint === 'DIRECT_PHONE') {
            const cleanPhone = query.replace(/\D/g, '');
            const resp = await axios.get(`https://api.numlookupapi.com/v1/validate/${cleanPhone}?apikey=${NUMLOOKUP_KEY}`, axiosConfig);
            resultData = resp.data;
        }

        // --- HANDLER: GHOSINT AGGREGATOR ---
        else if (isGhosint) {
            const resp = await axios.post("https://api.ghosint.io/search", { 
                key: GHOSINT_KEY, query: query.trim(), services: ['leakcheck', 'snusbase'] 
            }, axiosConfig);
            resultData = resp.data;
        }

        // --- HANDLER: SHODAN NODES ---
        else if (endpoint.startsWith('/shodan')) {
            const pathTail = endpoint.replace('/shodan', '');
            const resp = await axios.get(`https://api.shodan.io${pathTail}?key=${SHODAN_KEY}`, axiosConfig);
            resultData = resp.data;
        }

        // --- HANDLER: EXTERNAL CLUSTER RELAY ---
        else {
            let finalUrl = `${CLUSTER_NODE}${endpoint}`;
            const sep = endpoint.includes('?') ? '&' : '?';
            
            if (split) {
                const parts = query.trim().split(/\s+/);
                const fname = parts[0] || "";
                const lname = parts.slice(1).join(" ") || "";
                finalUrl += `${sep}firstname=${encodeURIComponent(fname)}&lastname=${encodeURIComponent(lname)}`;
            } else {
                finalUrl += `${sep}${param || "q"}=${encodeURIComponent(query)}`;
            }
            
            const resp = await axios.get(finalUrl, axiosConfig);
            resultData = resp.data;
        }

        res.json({ 
            success: true, 
            latency: `${Date.now() - startTime}ms`, 
            payload: resultData 
        });

    } catch (err) {
        const errType = err.response ? `API_ERR_${err.response.status}` : "NETWORK_TIMEOUT";
        fs.appendFileSync(ERROR_LOG, `[${new Date().toISOString()}] ${errType}: ${err.message}\n`);
        res.status(500).json({ success: false, error: errType, details: err.message });
    }
});

/**
 * USER AUTHENTICATION API
 */
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.username === username && u.password === password);
    
    if (user) {
        if (user.locked) return res.status(403).json({ error: "ACCOUNT_LOCKED" });
        if (user.role !== 'admin' && Date.now() > user.expiry) {
            return res.status(403).json({ error: "SUBSCRIPTION_EXPIRED" });
        }
        
        req.session.user = { username: user.username, role: user.role };
        return res.json({ success: true });
    }
    res.status(401).json({ success: false, error: "INVALID_CREDENTIALS" });
});

app.post('/api/redeem', (req, res) => {
    const { key, username, password } = req.body;
    let db = loadDB();

    try {
        const kIdx = db.pending_keys.findIndex(k => k.key === key && !k.used);
        if (kIdx === -1) return res.status(400).json({ error: "KEY_INVALID_OR_USED" });
        
        if (db.users.find(u => u.username === username)) {
            return res.status(400).json({ error: "USERNAME_TAKEN" });
        }

        const plan = db.pending_keys[kIdx].plan;
        let days = (plan === 'week') ? 7 : (plan === 'day') ? 1 : (plan === 'lifetime') ? 3650 : 30;
        
        db.users.push({ 
            username, password, role: 'user', locked: false, 
            expiry: Date.now() + (days * 86400000) 
        });
        
        db.pending_keys[kIdx].used = true;
        db.pending_keys[kIdx].usedBy = username;
        db.pending_keys[kIdx].usedAt = Date.now();
        
        saveDB(db);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "REDEEM_PROCESS_FAILED" });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('TITAN_SID');
        res.redirect('/login');
    });
});

/**
 * MAINTENANCE & CRON SERVICE
 * Runs hourly to preserve data integrity and manage backups.
 */
setInterval(() => {
    try {
        const db = loadDB();
        const ts = new Date().toISOString().replace(/:/g, '-').split('.')[0];
        const backupName = `db_bkp_${ts}.json`;
        fs.writeFileSync(path.join(BACKUP_DIR, backupName), JSON.stringify(db));
        
        const files = fs.readdirSync(BACKUP_DIR)
            .filter(f => f.endsWith('.json'))
            .sort((a, b) => {
                return fs.statSync(path.join(BACKUP_DIR, a)).mtime - fs.statSync(path.join(BACKUP_DIR, b)).mtime;
            });
        
        while (files.length > 20) {
            const oldFile = files.shift();
            fs.unlinkSync(path.join(BACKUP_DIR, oldFile));
        }
        console.log(`[MAINTENANCE] Backup created: ${backupName}`);
    } catch (err) {
        console.error("[MAINTENANCE] Error during scheduled backup:", err);
    }
}, 3600000);

/**
 * BOOTSTRAP LISTENER
 */
const server = http.createServer(app);
server.listen(PORT, '0.0.0.0', () => {
    process.stdout.write('\x1Bc'); // Clear terminal
    console.log(" ");
    console.log(" \x1b[31m████████╗██╗████████╗ █████╗ ███╗   ██╗\x1b[0m");
    console.log(" \x1b[31m╚══██╔══╝██║╚══██╔══╝██╔══██╗████╗  ██║\x1b[0m");
    console.log(" \x1b[31m   ██║   ██║   ██║   ███████║██╔██╗ ██║\x1b[0m");
    console.log(" \x1b[31m   ██║   ██║   ██║   ██╔══██║██║╚██╗██║\x1b[0m");
    console.log(" \x1b[31m   ██║   ██║   ██║   ██║  ██║██║ ╚████║\x1b[0m");
    console.log(" \x1b[31m   ╚═╝   ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝\x1b[0m");
    console.log(" ");
    console.log(` \x1b[37m[NODE]\x1b[0m Titan Omega Kernel Online`);
    console.log(` \x1b[37m[PORT]\x1b[0m Listening on 0.0.0.0:${PORT}`);
    console.log(` \x1b[37m[VERS]\x1b[0m v6.4.1 Enterprise Build`);
    console.log(" ");
});