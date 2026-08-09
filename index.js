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

// Crear tablas
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
  CREATE TABLE IF NOT EXISTS chats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user1_id UUID REFERENCES users(id) ON DELETE CASCADE,
    user2_id UUID REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user1_id, user2_id)
  );
  CREATE TABLE IF NOT EXISTS pending_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_id UUID REFERENCES chats(id) ON DELETE CASCADE,
    sender_id UUID NOT NULL,
    receiver_id UUID NOT NULL,
    content TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW()
  );
`);

// Middleware JWT
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

// WebSocket
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
  sendPending(userId);

  ws.on('message', (data) => {
    const msg = JSON.parse(data);
    handleMessage(userId, msg);
  });

  ws.on('close', () => {
    clients.delete(userId);
    pool.query('UPDATE users SET is_online=false, is_typing=false, last_seen=NOW() WHERE id=$1', [userId]);
    broadcastStatus(userId, false);
  });
});

async function handleMessage(senderId, msg) {
  const { type, data } = msg;
  const chatId = data?.chat_id;
  const content = data?.content;
  const receiverId = data?.receiver_id;
  const msgId = uuidv4();
  const now = new Date().toISOString();

  if (type === 'message') {
    const resp = { type: 'message', message: { id: msgId, chat_id: chatId, sender_id: senderId, content, status: 'sent', created_at: now } };
    
    if (clients.has(receiverId)) {
      clients.get(receiverId).send(JSON.stringify(resp));
      const delivered = { type: 'message', message: { id: msgId, chat_id: chatId, sender_id: senderId, content, status: 'delivered', created_at: now } };
      if (clients.has(senderId)) clients.get(senderId).send(JSON.stringify(delivered));
    } else {
      await pool.query('INSERT INTO pending_messages (id, chat_id, sender_id, receiver_id, content) VALUES ($1,$2,$3,$4,$5)', [msgId, chatId, senderId, receiverId, content]);
    }
    if (clients.has(senderId)) clients.get(senderId).send(JSON.stringify(resp));
  }
  else if (type === 'typing') {
    const isTyping = data?.is_typing;
    const { rows } = await pool.query('SELECT CASE WHEN user1_id=$1 THEN user2_id ELSE user1_id END AS other FROM chats WHERE id=$2', [senderId, chatId]);
    const otherId = rows[0]?.other;
    if (otherId && clients.has(otherId)) {
      clients.get(otherId).send(JSON.stringify({ type: 'typing', chat_id: chatId, user_id: senderId, typing: isTyping }));
    }
  }
  else if (type === 'read') {
    const messageId = data?.message_id;
    await pool.query('DELETE FROM pending_messages WHERE id=$1', [messageId]);
    if (clients.has(senderId)) {
      clients.get(senderId).send(JSON.stringify({ type: 'read_receipt', chat_id: chatId, message_id: messageId, read_by: senderId }));
    }
  }
}

async function sendPending(userId) {
  if (!clients.has(userId)) return;
  const { rows } = await pool.query('SELECT id, chat_id, sender_id, content, created_at FROM pending_messages WHERE receiver_id=$1 ORDER BY created_at', [userId]);
  for (const row of rows) {
    clients.get(userId).send(JSON.stringify({ type: 'message', message: { id: row.id, chat_id: row.chat_id, sender_id: row.sender_id, content: row.content, status: 'delivered', created_at: row.created_at } }));
    await pool.query('DELETE FROM pending_messages WHERE id=$1', [row.id]);
  }
}

function broadcastStatus(userId, online) {
  const msg = JSON.stringify({ type: 'user_status', user_id: userId, online, last_seen: new Date().toISOString() });
  clients.forEach((ws, id) => { if (id !== userId) ws.send(msg); });
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

// Users
app.get('/api/users', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, profile_pic, info, last_seen, is_online FROM users WHERE id!=$1 ORDER BY is_online DESC LIMIT 100', [req.userId]);
  res.json(rows);
});

app.get('/api/users/:id', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, profile_pic, info, last_seen, is_online FROM users WHERE id=$1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'No encontrado' });
  res.json(rows[0]);
});

// Chats
app.get('/api/chats', auth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT c.id, 
      CASE WHEN c.user1_id=$1 THEN u2.username ELSE u1.username END as username,
      CASE WHEN c.user1_id=$1 THEN u2.profile_pic ELSE u1.profile_pic END as profile_pic,
      CASE WHEN c.user1_id=$1 THEN u2.id ELSE u1.id END as other_id,
      CASE WHEN c.user1_id=$1 THEN u2.is_online ELSE u1.is_online END as is_online,
      CASE WHEN c.user1_id=$1 THEN u2.info ELSE u1.info END as info,
      COALESCE((SELECT content FROM pending_messages WHERE chat_id=c.id ORDER BY created_at DESC LIMIT 1), '') as last_message,
      COALESCE((SELECT created_at FROM pending_messages WHERE chat_id=c.id ORDER BY created_at DESC LIMIT 1)::text, '') as last_time,
      COALESCE((SELECT status FROM pending_messages WHERE chat_id=c.id AND receiver_id=$1 ORDER BY created_at DESC LIMIT 1), '') as last_msg_status,
      (SELECT COUNT(*) FROM pending_messages WHERE chat_id=c.id AND receiver_id=$1) as unread_count
    FROM chats c
    JOIN users u1 ON c.user1_id=u1.id JOIN users u2 ON c.user2_id=u2.id
    WHERE c.user1_id=$1 OR c.user2_id=$1 ORDER BY last_time DESC NULLS LAST
  `, [req.userId]);
  res.json(rows.map(r => ({ id: r.id, other_user: { id: r.other_id, username: r.username, profile_pic: r.profile_pic, info: r.info, is_online: r.is_online }, last_message: r.last_message, last_time: r.last_time, unread_count: parseInt(r.unread_count) || 0, last_msg_status: r.last_msg_status })));
});

app.post('/api/chats/user/:id', auth, async (req, res) => {
  if (req.userId === req.params.id) return res.status(400).json({ error: 'No puedes chatear contigo mismo' });
  const { rows } = await pool.query("SELECT id FROM chats WHERE (user1_id=$1 AND user2_id=$2) OR (user1_id=$2 AND user2_id=$1)", [req.userId, req.params.id]);
  if (rows.length) return res.json({ chat_id: rows[0].id });
  const id = uuidv4();
  await pool.query('INSERT INTO chats (id, user1_id, user2_id) VALUES ($1,$2,$3)', [id, req.userId, req.params.id]);
  res.json({ chat_id: id });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

// WebSocket upgrade
server.on('upgrade', (req, socket, head) => {
  if (req.url.startsWith('/api/ws')) {
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  } else {
    socket.destroy();
  }
});

server.listen(PORT, () => console.log(`Seend server en puerto ${PORT}`));

// Keep-alive cada 5 minutos para evitar cold start
setInterval(() => {
  try { require("https").get("https://seend-server.onrender.com/api/health", () => {}); } catch(e) {}
}, 300000);

// Keep-alive cada 5 minutos para evitar cold start
setInterval(() => {
  try { require("https").get("https://seend-server.onrender.com/api/health", () => {}); } catch(e) {}
}, 300000);
