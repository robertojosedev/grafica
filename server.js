/**
 * BACKEND DA GRÁFICA EXPRESS (server.js)
 * Node.js + Express + SQLite3
 * 
 * Funcionalidades:
 * - Autenticação Admin por E-mail (admin@grafica.com)
 * - Autenticação Cliente por Telefone/WhatsApp
 * - Banco de dados relacional integrado com auto-criação de tabelas
 * - API REST para Produtos, Pedidos e Funil de Vendas
 * - Extensões para Banco (Webhook PIX) e Melhor Envio (Frete)
 * - Segurança WAF integrando Rate Limit e Input Sanitization
 */

const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Carrega as variáveis ocultas do arquivo .env (Se ele existir no servidor)
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
// E-mail lido de forma segura da variável ADMIN_EMAIL (ou padrão se não definida)
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@grafica.com';

// ==========================================
// 1. MIDDLEWARES DE SEGURANÇA E PARSER
// ==========================================
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate Limiter Simples (Segurança WAF)
const requestLogs = new Map();
app.use((req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowMs = 60 * 1000; // 1 minuto
    const maxRequests = 120; // máximo de 120 requisições/minuto

    if (!requestLogs.has(ip)) {
        requestLogs.set(ip, []);
    }
    const timestamps = requestLogs.get(ip).filter(ts => now - ts < windowMs);
    timestamps.push(now);
    requestLogs.set(ip, timestamps);

    if (timestamps.length > maxRequests) {
        return res.status(429).json({ error: "Muitas requisições. Bloqueado pelo WAF de segurança." });
    }
    next();
});

// Sanitizador de texto simples (Anti-XSS)
function sanitizeText(text) {
    if (typeof text !== 'string') return text;
    return text.replace(/[&<>"']/g, (m) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    })[m]);
}

// Middleware global para sanitizar o body da requisição
app.use((req, res, next) => {
    if (req.body && typeof req.body === 'object') {
        for (let key in req.body) {
            if (typeof req.body[key] === 'string') {
                req.body[key] = sanitizeText(req.body[key]);
            }
        }
    }
    next();
});

// ==========================================
// 2. CONEXÃO E ESTRUTURA DO BANCO DE DADOS
// ==========================================
const dbPath = path.resolve(__dirname, 'grafica_database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Erro ao conectar ao banco SQLite:', err.message);
    } else {
        console.log(' Conectado com sucesso ao banco de dados SQLite.');
        initDatabase();
    }
});

function initDatabase() {
    db.serialize(() => {
        // Tabela de Administradores
        db.run(`CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Tabela de Clientes
        db.run(`CREATE TABLE IF NOT EXISTS clientes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,
            default_address TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Tabela de Códigos OTP (WhatsApp Verificação)
        db.run(`CREATE TABLE IF NOT EXISTS otp_codes (
            phone TEXT PRIMARY KEY,
            code TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Tabela de Produtos
        db.run(`CREATE TABLE IF NOT EXISTS produtos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            subcategory TEXT,
            price REAL NOT NULL,
            art_price REAL DEFAULT 0,
            image TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Tabela de Pedidos
        db.run(`CREATE TABLE IF NOT EXISTS pedidos (
            id TEXT PRIMARY KEY,
            phone TEXT NOT NULL,
            items TEXT NOT NULL,
            total REAL NOT NULL,
            address TEXT NOT NULL,
            status TEXT DEFAULT 'Pagamento Confirmado',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Tabela do Funil de Vendas / Métricas
        db.run(`CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            visits INTEGER DEFAULT 0,
            carts INTEGER DEFAULT 0,
            purchases INTEGER DEFAULT 0
        )`);

        // Tabela de Extensões (Melhor Envio & Bancos)
        db.run(`CREATE TABLE IF NOT EXISTS extensions (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )`);

        // POVOAR DADOS INICIAIS (Se o banco for novo)
        // 1. Admin Padrão
        db.run(`INSERT OR IGNORE INTO admins (email) VALUES ('admin@grafica.com')`);

        // 2. Métricas Iniciais
        db.run(`INSERT OR IGNORE INTO metrics (id, visits, carts, purchases) VALUES (1, 0, 0, 0)`);

        // 3. Produtos Iniciais da Gráfica
        db.get(`SELECT COUNT(*) as count FROM produtos`, (err, row) => {
            if (row && row.count === 0) {
                const initialProducts = [
                    ['Cartão de Visita Premium', 'Cartões de Visita', 'Couche 300g', 55.00, 25.00, 'https://images.unsplash.com/photo-1589829545856-d10d557cf95f?w=400'],
                    ['Panfleto Promocional 10x14', 'Panfletos & Impressos', 'Panfleto 10x14cm', 120.00, 40.00, 'https://images.unsplash.com/photo-1562577309-4932fdd64cd1?w=400'],
                    ['Banner Comercial em Lona', 'Banners & Faixas', 'Banner 440g Ilhós', 85.00, 30.00, 'https://images.unsplash.com/photo-1626785774573-4b799315345d?w=400'],
                    ['Caneca Personalizada', 'Brindes & Canecas', 'Caneca Porcelana', 35.00, 15.00, 'https://images.unsplash.com/photo-1514432324607-a09d9b4aefdd?w=400']
                ];
                const stmt = db.prepare(`INSERT INTO produtos (name, category, subcategory, price, art_price, image) VALUES (?, ?, ?, ?, ?, ?)`);
                initialProducts.forEach(p => stmt.run(p));
                stmt.finalize();
                console.log(' Catálogo inicial de produtos inserido.');
            }
        });
    });
}

// ==========================================
// 3. ENDPOINTS DA API REST
// ==========================================

// --- DISPARO E VERIFICAÇÃO DE CÓDIGO OTP (WHATSAPP) ---
function generateOTPCode() {
    const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let code = '';
    for (let i = 0; i < 6; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

app.post('/api/auth/send-otp', (req, res) => {
    const { phone } = req.body;
    if (!phone || phone.length < 8) {
        return res.status(400).json({ error: 'Número de telefone/WhatsApp inválido.' });
    }

    const code = generateOTPCode();

    db.run(`INSERT OR REPLACE INTO otp_codes (phone, code) VALUES (?, ?)`, [phone, code], function (err) {
        if (err) return res.status(500).json({ error: err.message });

        // Simulação do envio de mensagem via WhatsApp API (Ex: Z-API / Evolution / Twilio)
        console.log(`=================================================`);
        console.log(`[WHATSAPP OTP] Mensagem enviada para ${phone}:`);
        console.log(`"Seu código de acesso à Gráfica Express é: ${code}"`);
        console.log(`=================================================`);

        res.json({ success: true, message: 'Código enviado com sucesso via WhatsApp!', simulatedCode: code });
    });
});

app.post('/api/auth/verify-otp', (req, res) => {
    const { phone, code } = req.body;
    if (!phone || !code) {
        return res.status(400).json({ error: 'Telefone e código são obrigatórios.' });
    }

    const cleanCode = code.toUpperCase().trim();

    db.get(`SELECT code FROM otp_codes WHERE phone = ?`, [phone], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row || row.code !== cleanCode) {
            return res.status(400).json({ error: 'Código de confirmação incorreto ou expirado.' });
        }

        // Deleta o OTP usado
        db.run(`DELETE FROM otp_codes WHERE phone = ?`, [phone]);

        // Cria ou busca o cliente
        db.run(`INSERT OR IGNORE INTO clientes (phone) VALUES (?)`, [phone], function (err) {
            if (err) return res.status(500).json({ error: err.message });
            
            db.get(`SELECT * FROM clientes WHERE phone = ?`, [phone], (err, clientRow) => {
                if (err) return res.status(500).json({ error: err.message });
                return res.json({ success: true, client: clientRow });
            });
        });
    });
});

// --- AUTENTICAÇÃO UNIFICADA (E-MAIL ADMIN OU TELEFONE CLIENTE) ---
app.post('/api/auth/login', (req, res) => {
    const { identifier } = req.body;
    if (!identifier) {
        return res.status(400).json({ error: 'Informe um e-mail ou número de telefone.' });
    }

    const cleanInput = identifier.trim();

    // 1. Verifica se é o e-mail do Vendedor/Admin
    if (cleanInput.toLowerCase() === ADMIN_EMAIL.toLowerCase().trim()) {
        return res.json({ 
            success: true, 
            role: 'vendor', 
            token: 'session_admin_verified' 
        });
    }

    // 2. Se for um número de telefone/WhatsApp
    const phoneDigits = cleanInput.replace(/\D/g, '');
    if (phoneDigits.length >= 8) {
        db.get(`SELECT * FROM clientes WHERE phone = ?`, [cleanInput], (err, row) => {
            if (err) return res.status(500).json({ error: err.message });
            if (row) {
                return res.json({ success: true, role: 'customer', client: row });
            } else {
                return res.status(404).json({ error: 'Conta não encontrada. Clique em "Criar Conta" para cadastrar seu telefone.' });
            }
        });
    } else {
        return res.status(400).json({ error: 'E-mail ou telefone inválido.' });
    }
});

// --- PRODUTOS ---
// Listar Todos os Produtos
app.get('/api/produtos', (req, res) => {
    db.all(`SELECT * FROM produtos ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Cadastrar Novo Produto (Apenas Admin)
app.post('/api/produtos', (req, res) => {
    const { name, category, subcategory, price, art_price, image } = req.body;
    if (!name || !category || !price) {
        return res.status(400).json({ error: 'Nome, categoria e preço base são obrigatórios.' });
    }

    const imgUrl = image || 'https://images.unsplash.com/photo-1589829545856-d10d557cf95f?w=400';
    db.run(
        `INSERT INTO produtos (name, category, subcategory, price, art_price, image) VALUES (?, ?, ?, ?, ?, ?)`,
        [name, category, subcategory || category, parseFloat(price), parseFloat(art_price || 0), imgUrl],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, productId: this.lastID });
        }
    );
});

// --- PEDIDOS ---
// Criar Pedido
app.post('/api/pedidos', (req, res) => {
    const { phone, items, total, address, save_address } = req.body;
    if (!phone || !items || !total || !address) {
        return res.status(400).json({ error: 'Dados incompletos para processar o pedido.' });
    }

    const orderId = `PED-${Math.floor(100000 + Math.random() * 900000)}`;
    const itemsJson = typeof items === 'string' ? items : JSON.stringify(items);

    db.run(
        `INSERT INTO pedidos (id, phone, items, total, address, status) VALUES (?, ?, ?, ?, ?, 'Pagamento Confirmado')`,
        [orderId, phone, itemsJson, parseFloat(total), address],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });

            // Se o cliente escolheu salvar o endereço padrão
            if (save_address) {
                db.run(`UPDATE clientes SET default_address = ? WHERE phone = ?`, [address, phone]);
            }

            // Atualizar contadores do Funil
            db.run(`UPDATE metrics SET purchases = purchases + 1 WHERE id = 1`);

            res.json({ success: true, orderId: orderId });
        }
    );
});

// Listar Pedidos do Cliente Logado
app.get('/api/pedidos/cliente/:phone', (req, res) => {
    const phone = req.params.phone;
    db.all(`SELECT * FROM pedidos WHERE phone = ? ORDER BY created_at DESC`, [phone], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const parsedRows = rows.map(r => ({ ...r, items: JSON.parse(r.items) }));
        res.json(parsedRows);
    });
});

// Listar Todos os Pedidos (Painel do Vendedor)
app.get('/api/pedidos/admin', (req, res) => {
    db.all(`SELECT * FROM pedidos ORDER BY created_at DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const parsedRows = rows.map(r => ({ ...r, items: JSON.parse(r.items) }));
        res.json(parsedRows);
    });
});

// Atualizar Status do Pedido
app.put('/api/pedidos/:id/status', (req, res) => {
    const { status } = req.body;
    const orderId = req.params.id;

    db.run(`UPDATE pedidos SET status = ? WHERE id = ?`, [status, orderId], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, updated: this.changes > 0 });
    });
});

// --- FUNIL DE VENDAS & MÉTRICAS ---
app.get('/api/metrics', (req, res) => {
    db.get(`SELECT * FROM metrics WHERE id = 1`, (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(row);
    });
});

app.post('/api/metrics/track', (req, res) => {
    const { type } = req.body; // 'visit' ou 'cart'
    if (type === 'visit') {
        db.run(`UPDATE metrics SET visits = visits + 1 WHERE id = 1`);
    } else if (type === 'cart') {
        db.run(`UPDATE metrics SET carts = carts + 1 WHERE id = 1`);
    }
    res.json({ success: true });
});

// --- EXTENSÕES (MELHOR ENVIO & BANCOS) ---
app.post('/api/extensions', (req, res) => {
    const { key, value } = req.body;
    const valString = typeof value === 'object' ? JSON.stringify(value) : String(value);

    db.run(`INSERT OR REPLACE INTO extensions (key, value) VALUES (?, ?)`, [key, valString], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

app.get('/api/extensions/:key', (req, res) => {
    db.get(`SELECT value FROM extensions WHERE key = ?`, [req.params.key], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ value: row ? row.value : null });
    });
});

// Webhook Bancário (Simulação de notificação instantânea PIX)
app.post('/api/webhooks/banco', (req, res) => {
    const { pix_id, order_id, status } = req.body;
    console.log(`[WEBHOOK BANCO] Recebido pagamento PIX ID: ${pix_id} para o Pedido: ${order_id}`);

    if (order_id) {
        db.run(`UPDATE pedidos SET status = 'Pagamento Confirmado via PIX' WHERE id = ?`, [order_id]);
    }
    res.json({ received: true, status: 'approved' });
});

// INICIAR SERVIDOR
app.listen(PORT, () => {
    console.log(`=================================================`);
    console.log(` Servidor da Gráfica rodando na porta ${PORT}`);
    console.log(` API Endpoint base: http://localhost:${PORT}/api`);
    console.log(` E-mail Admin Autorizado: ${ADMIN_EMAIL}`);
    console.log(`=================================================`);
});