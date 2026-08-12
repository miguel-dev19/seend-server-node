const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { WebSocketServer } = require('ws');
const http = require('http');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const JWT_SECRET = process.env.JWT_SECRET || 'seend-secret-2024';
const PORT = process.env.PORT || 8080;

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(30) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    profile_pic TEXT DEFAULT '',
    info TEXT DEFAULT 'Hola! Estoy usando Seend.',
    last_seen TIMESTAMP DEFAULT NOW(),
    is_online BOOLEAN DEFAULT FALSE,
    is_typing BOOLEAN DEFAULT FALSE
  );
  CREATE TABLE IF NOT EXISTS global_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id UUID NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
  );
`);

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Token requerido' });
  try {
    const token = header.replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.user_id;
    req.username = decoded.username;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token invalido' });
  }
}

const clients = new Map();

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const token = url.searchParams.get('token');
  let userId;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    userId = decoded.user_id;
  } catch (e) { ws.close(); return; }

  if (clients.has(userId)) clients.get(userId).close();
  clients.set(userId, ws);
  pool.query('UPDATE users SET is_online=true, last_seen=NOW() WHERE id=$1', [userId]);
  broadcastStatus(userId, true);
  sendGlobalHistory(userId);

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      handleMessage(userId, msg);
    } catch (e) { console.error('Error parsing:', e); }
  });

  ws.on('close', () => {
    clients.delete(userId);
    pool.query('UPDATE users SET is_online=false, is_typing=false, last_seen=NOW() WHERE id=$1', [userId]);
    broadcastStatus(userId, false);
    broadcastTyping(userId, false);
  });
});

async function handleMessage(senderId, msg) {
  const { type, data } = msg;
  const chatId = data?.chat_id;
  const content = data?.content;
  const msgId = uuidv4();
  const now = new Date().toISOString();

  if (type === 'message' && chatId === 'global') {
    await pool.query('INSERT INTO global_messages (id, sender_id, content) VALUES ($1, $2, $3)', [msgId, senderId, content]);
    
    const userResult = await pool.query('SELECT username, profile_pic FROM users WHERE id=$1', [senderId]);
    const user = userResult.rows[0] || { username: 'Usuario', profile_pic: '' };
    
    const resp = { type: 'message', message: { id: msgId, chat_id: 'global', sender_id: senderId, content, status: 'delivered', created_at: now, sender_name: user.username, sender_avatar: user.profile_pic } };
    
    clients.forEach((ws) => {
      try { ws.send(JSON.stringify(resp)); } catch (e) {}
    });
  }
  else if (type === 'typing') {
    broadcastTyping(senderId, data?.is_typing);
  }
}

function broadcastTyping(userId, isTyping) {
  const msg = JSON.stringify({ type: 'typing', chat_id: 'global', user_id: userId, typing: isTyping });
  clients.forEach((ws, id) => {
    if (id !== userId) {
      try { ws.send(msg); } catch (e) {}
    }
  });
}

// Paginación: envía 20 mensajes, luego 20 más cuando la app lo pida
async function sendGlobalHistory(userId, offset = 0) {
  if (!clients.has(userId)) return;
  const limit = 20;
  const { rows } = await pool.query(
    `SELECT gm.id, gm.sender_id, gm.content, gm.created_at, u.username, u.profile_pic
     FROM global_messages gm JOIN users u ON gm.sender_id = u.id
     ORDER BY gm.created_at DESC LIMIT $1 OFFSET $2`,
    [limit, offset]
  );
  
  // Enviar del más antiguo al más reciente
  rows.reverse().forEach((row) => {
    clients.get(userId).send(JSON.stringify({
      type: 'message',
      message: {
        id: row.id, chat_id: 'global', sender_id: row.sender_id,
        content: row.content, status: 'delivered', created_at: row.created_at,
        sender_name: row.username, sender_avatar: row.profile_pic
      }
    }));
  });
}

// Endpoint para cargar más mensajes
app.get('/api/global/messages', auth, async (req, res) => {
  const offset = parseInt(req.query.offset) || 0;
  const limit = 20;
  const { rows } = await pool.query(
    `SELECT gm.id, gm.sender_id, gm.content, gm.created_at, u.username, u.profile_pic
     FROM global_messages gm JOIN users u ON gm.sender_id = u.id
     ORDER BY gm.created_at DESC LIMIT $1 OFFSET $2`,
    [limit, offset]
  );
  res.json(rows.reverse());
});

function broadcastStatus(userId, online) {
  const msg = JSON.stringify({ type: 'user_status', user_id: userId, online, last_seen: new Date().toISOString() });
  clients.forEach((ws, id) => { if (id !== userId) { try { ws.send(msg); } catch (e) {} } });
}

// Auth
app.post('/api/auth/register', async (req, res) => {
  const { username, password, photo } = req.body;
  if (!username || !password || username.length < 3 || password.length < 6) return res.status(400).json({ error: 'Datos invalidos' });
  const exists = await pool.query('SELECT 1 FROM users WHERE username=$1', [username]);
  if (exists.rows.length) return res.status(409).json({ error: 'Usuario ya existe' });
  const hash = await bcrypt.hash(password, 10);
  const id = uuidv4();
  await pool.query('INSERT INTO users (id, username, password_hash, profile_pic) VALUES ($1,$2,$3,$4)', [id, username, hash, photo || '']);
  const token = jwt.sign({ user_id: id, username }, JWT_SECRET, { expiresIn: '24h' });
  res.status(201).json({ token, user: { id, username, profile_pic: photo || '', info: 'Hola! Estoy usando Seend.', is_online: true } });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
  if (!rows.length || !(await bcrypt.compare(password, rows[0].password_hash))) return res.status(401).json({ error: 'Credenciales invalidas' });
  const user = rows[0];
  await pool.query('UPDATE users SET is_online=true, last_seen=NOW() WHERE id=$1', [user.id]);
  const token = jwt.sign({ user_id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, user: { id: user.id, username: user.username, profile_pic: user.profile_pic, info: user.info, is_online: true } });
});

app.get('/api/auth/check-username/:username', async (req, res) => {
  const { rows } = await pool.query('SELECT 1 FROM users WHERE username=$1', [req.params.username]);
  res.json({ username: req.params.username, available: !rows.length, message: rows.length ? 'No disponible' : 'Disponible' });
});

app.get('/api/users', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, profile_pic, info, last_seen, is_online FROM users WHERE id!=$1 ORDER BY is_online DESC LIMIT 100', [req.userId]);
  res.json(rows);
});

app.get('/api/users/:id', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, profile_pic, info, last_seen, is_online FROM users WHERE id=$1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'No encontrado' });
  res.json(rows[0]);
});

app.delete('/api/users/account', auth, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Contraseña requerida' });
  const { rows } = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.userId]);
  if (!rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
  const valid = await bcrypt.compare(password, rows[0].password_hash);
  if (!valid) return res.status(401).json({ error: 'Contraseña incorrecta' });
  await pool.query('DELETE FROM users WHERE id=$1', [req.userId]);
  res.json({ message: 'Cuenta eliminada' });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

server.on('upgrade', (req, socket, head) => {
  if (req.url.startsWith('/api/ws')) {
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  } else {
    socket.destroy();
  }
});

server.listen(PORT, () => console.log(`Seend server en puerto ${PORT}`));

setInterval(() => {
  try { require('https').get('https://seend-server.onrender.com/api/health', () => {}); } catch(e) {}
}, 300000);
