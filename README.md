// Kullanıcı giriş, yetkilendirme ve ürün yönetimi (Node.js + Express + JWT)
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();
const app = express();
app.use(express.json());

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'inventory_db'
});

db.connect(err => {
    if (err) throw err;
    console.log('MySQL Bağlantısı Başarılı');
});

// Yetkilendirme Middleware
const authenticate = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'Yetkisiz erişim' });

    jwt.verify(token.split(' ')[1], process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Geçersiz token' });
        req.user = decoded;
        next();
    });
};

const authorize = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) {
        return res.status(403).json({ error: 'Yetkisiz işlem' });
    }
    next();
};

// Kullanıcı Kaydı
app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
    db.query(query, [username, hashedPassword, role], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Kullanıcı başarıyla kaydedildi!' });
    });
});

// Kullanıcı Girişi
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], async (err, results) => {
        if (err || results.length === 0) return res.status(401).json({ error: 'Geçersiz kullanıcı' });
        
        const user = results[0];
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) return res.status(401).json({ error: 'Geçersiz şifre' });
        
        const token = jwt.sign({ userId: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Ürünleri Listeleme (Herkes erişebilir)
app.get('/products', authenticate, (req, res) => {
    const query = 'SELECT * FROM products';
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// Yeni Ürün Ekleme (Sadece Yönetici)
app.post('/products/add', authenticate, authorize(['admin']), (req, res) => {
    const { name, barcode, category, stock_quantity } = req.body;
    const query = 'INSERT INTO products (name, barcode, category, stock_quantity) VALUES (?, ?, ?, ?)';
    db.query(query, [name, barcode, category, stock_quantity], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Ürün başarıyla eklendi!' });
    });
});

// Barkod ile Ürün Arama (Herkes erişebilir)
app.get('/scan/:barcode', authenticate, (req, res) => {
    const { barcode } = req.params;
    const query = 'SELECT * FROM products WHERE barcode = ?';
    db.query(query, [barcode], (err, results) => {
        if (err || results.length === 0) return res.status(404).json({ error: 'Ürün bulunamadı' });
        res.json(results[0]);
    });
});

// Envanter Sayımı Kaydetme (Sadece Sayım Görevlisi ve Yönetici)
app.post('/inventory/count', authenticate, authorize(['admin', 'counter']), (req, res) => {
    const { user_id, product_id, counted_quantity } = req.body;
    const query = 'INSERT INTO inventory_counts (user_id, product_id, counted_quantity, timestamp) VALUES (?, ?, ?, NOW())';
    db.query(query, [user_id, product_id, counted_quantity], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Sayım başarıyla kaydedildi!' });
    });
});

// Stok Raporlama (Sadece Yönetici)
app.get('/reports/summary', authenticate, authorize(['admin']), (req, res) => {
    const query = `
        SELECT p.name, p.stock_quantity, 
               (SELECT SUM(ic.counted_quantity) FROM inventory_counts ic WHERE ic.product_id = p.id) AS total_counted
        FROM products p`;
    
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        
        const report = results.map(item => ({
            product: item.name,
            stock_quantity: item.stock_quantity,
            counted_quantity: item.total_counted || 0,
            difference: (item.total_counted || 0) - item.stock_quantity
        }));
        
        res.json(report);
    });
});

app.listen(3000, () => console.log('Sunucu 3000 portunda çalışıyor!'));
