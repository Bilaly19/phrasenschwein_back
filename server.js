import express from 'express';
import fs from 'fs';
import cors from 'cors';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

const app = express();
const PORT = 3000;

const DATA_FILE = './data.json';
const USERS_FILE = './users.json';

app.use(cors({
    origin: 'https://phrasenschwein-front.vercel.app',
    credentials: true
}));

// Hilfsfunktionen für Daten
function readData() {
    const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
    if (!data.valuePerClick) data.valuePerClick = 0.5;
    return data;
}
function writeData(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}
function readUsers() {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8'));
}
function writeUsers(data) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
}

// Auth-Middleware
function authMiddleware(req, res, next) {
    const token = req.headers.authorization;
    const usersData = readUsers();
    if (!token || !usersData.sessions?.[token]) {
        return res.status(401).json({ message: 'Nicht eingeloggt' });
    }
    req.user = usersData.sessions[token]; // z. B. "bilal"
    next();
}

// GET: alle Namen (öffentlich)
app.get('/api/names', (req, res) => {
    const { valuePerClick, ...rest } = readData();
    res.json(rest);
});

// GET: Konfiguration
app.get('/api/config', (req, res) => {
    const data = readData();
    res.json({ valuePerClick: data.valuePerClick });
});

// POST: Konfiguration speichern (nur eingeloggte Nutzer)
app.post('/api/config', authMiddleware, (req, res) => {
    const data = readData();
    data.valuePerClick = req.body.valuePerClick;
    writeData(data);
    res.json({ message: 'Wert gespeichert' });
});

// POST: Namen hinzufügen
app.post('/api/add', authMiddleware, (req, res) => {
    const data = readData();
    const name = req.body.name;
    if (!data[name]) {
        data[name] = {
            count: 0,
            lastClickedAt: null
        };
        writeData(data);
        res.status(201).json({ message: 'Hinzugefügt' });
    } else {
        res.status(400).json({ message: 'Name existiert bereits' });
    }
});

// POST: Zähler erhöhen
app.post('/api/increment/:name', authMiddleware, (req, res) => {
    const data = readData();
    const name = req.params.name;
    if (data[name]) {
        data[name].count++;
        data[name].lastClickedAt = new Date().toISOString();
        writeData(data);
        res.json({ message: 'Zähler erhöht' });
    } else {
        res.status(404).json({ message: 'Name nicht gefunden' });
    }
});

// POST: Alle Zähler zurücksetzen
app.post('/api/reset', authMiddleware, (req, res) => {
    const data = readData();
    for (const name in data) {
        if (name !== 'valuePerClick') {
            data[name].count = 0;
            data[name].lastClickedAt = null;
        }
    }
    writeData(data);
    res.json({ message: 'Zurückgesetzt' });
});

// DELETE: Namen löschen
app.delete('/api/delete/:name', authMiddleware, (req, res) => {
    const data = readData();
    const name = req.params.name;
    if (data[name]) {
        delete data[name];
        writeData(data);
        res.json({ message: 'Name gelöscht' });
    } else {
        res.status(404).json({ message: 'Name nicht gefunden' });
    }
});

// POST: Benutzer registrieren
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const usersData = readUsers();

    if (usersData.users?.[username]) {
        return res.status(400).json({ message: 'Benutzer existiert bereits' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    if (!usersData.users) usersData.users = {};
    if (!usersData.sessions) usersData.sessions = {};

    usersData.users[username] = {
        passwordHash,
        createdAt: new Date().toISOString()
    };

    writeUsers(usersData);
    res.status(201).json({ message: 'Benutzer registriert' });
});

// POST: Benutzer einloggen
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const usersData = readUsers();
    const user = usersData.users?.[username];

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        return res.status(401).json({ message: 'Login fehlgeschlagen' });
    }

    const token = uuidv4();
    usersData.sessions[token] = username;
    writeUsers(usersData);
    res.json({ token, username });
});

// POST: Logout (Session löschen)
app.post('/api/logout', (req, res) => {
    const token = req.headers.authorization;
    const usersData = readUsers();

    if (token && usersData.sessions?.[token]) {
        delete usersData.sessions[token];
        writeUsers(usersData);
    }

    res.json({ message: 'Abgemeldet' });
});

// Server starten
app.listen(PORT, () => {
    console.log(`Server läuft auf http://localhost:${PORT}`);
});
