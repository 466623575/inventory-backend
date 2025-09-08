const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const app = express();

// 中间件
app.use(cors());
app.use(express.json());

// 数据库初始化
const dbPath = path.join(__dirname, 'database.db');
const db = new sqlite3.Database(dbPath);

// 创建表
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    purchase_amount REAL NOT NULL,
    rent_amount REAL NOT NULL,
    status TEXT DEFAULT '在库',
    in_date TEXT NOT NULL,
    notes TEXT,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// 密钥
const JWT_SECRET = process.env.JWT_SECRET || 'inventory-secret-key';

// 用户注册
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ message: '用户名和密码必填' });
    }
    
    // 检查用户是否已存在
    db.get("SELECT id FROM users WHERE username = ?", [username], async (err, row) => {
      if (err) return res.status(500).json({ message: '数据库错误' });
      if (row) return res.status(400).json({ message: '用户名已存在' });
      
      // 哈希密码
      const hashedPassword = await bcrypt.hash(password, 10);
      
      // 创建用户
      db.run("INSERT INTO users (username, password) VALUES (?, ?)", 
        [username, hashedPassword], function(err) {
        if (err) return res.status(500).json({ message: '创建用户失败' });
        
        // 生成JWT令牌
        const token = jwt.sign({ userId: this.lastID, username }, JWT_SECRET);
        
        res.status(201).json({
          message: '用户注册成功',
          token,
          user: { id: this.lastID, username }
        });
      });
    });
  } catch (error) {
    res.status(500).json({ message: '服务器错误' });
  }
});

// 用户登录
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ message: '用户名和密码必填' });
    }
    
    // 查找用户
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
      if (err) return res.status(500).json({ message: '数据库错误' });
      if (!user) return res.status(400).json({ message: '用户名或密码错误' });
      
      // 验证密码
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) return res.status(400).json({ message: '用户名或密码错误' });
      
      // 生成JWT令牌
      const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET);
      
      res.json({
        message: '登录成功',
        token,
        user: { id: user.id, username: user.username }
      });
    });
  } catch (error) {
    res.status(500).json({ message: '服务器错误' });
  }
});

// 获取物品列表
app.get('/api/items', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: '需要认证' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    db.all("SELECT * FROM items WHERE user_id = ?", [decoded.userId], (err, items) => {
      if (err) return res.status(500).json({ message: '数据库错误' });
      res.json({ data: items });
    });
  } catch (error) {
    res.status(403).json({ message: '无效的令牌' });
  }
});

// 添加物品
app.post('/api/items', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: '需要认证' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { id, name, category, purchaseAmount, rentAmount, inDate, notes } = req.body;
    
    if (!id || !name || !category || !purchaseAmount || !rentAmount || !inDate) {
      return res.status(400).json({ message: '请填写所有必填字段' });
    }
    
    db.run(`INSERT INTO items (id, name, category, purchase_amount, rent_amount, in_date, notes, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [id, name, category, purchaseAmount, rentAmount, inDate, notes || '', decoded.userId], 
            function(err) {
      if (err) return res.status(500).json({ message: '添加物品失败' });
      
      res.status(201).json({
        message: '物品添加成功',
        data: { id, name, category, purchaseAmount, rentAmount, inDate, notes, status: '在库' }
      });
    });
  } catch (error) {
    res.status(403).json({ message: '无效的令牌' });
  }
});

// 启动服务器
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`服务器运行在端口 ${PORT}`);
});