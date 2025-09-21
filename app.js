const express = require('express');
const axios = require('axios');
const NodeRSA = require('node-rsa');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// 环境变量配置
const BASE_URL = process.env.BASE_URL || 'https://g4f.dev';
const AUTH_TOKENS = (process.env.AUTH_TOKENS || 'sk-default,sk-false').split(',');
const PROXY_URL = process.env.PROXY_URL || 'https://proxy.mengze.vip/proxy/';
const PROXY_ENCODE = process.env.PROXY_ENCODE === 'true';
const MAX_KEYS = parseInt(process.env.MAX_KEYS || '3');
const KEY_EXPIRY_MINUTES = parseInt(process.env.KEY_EXPIRY_MINUTES || '60');
const MODEL_CACHE_DAYS = parseInt(process.env.MODEL_CACHE_DAYS || '7');
const PORT = process.env.PORT || 3000;
const USE_SQLITE = process.env.USE_SQLITE !== 'false';

// User Agent 配置
const USER_AGENTS = {
    'Chrome-Windows': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Chrome-Mac': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Safari-Mac': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Firefox-Windows': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Edge-Windows': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
};

// 内存存储
let memoryStore = {
    keys: [],
    models: null,
    modelsExpiry: null
};

// 数据库初始化
let db = null;

async function initDatabase() {
    if (!USE_SQLITE) {
        console.log('Using memory storage');
        return;
    }

    try {
        db = await open({
            filename: './data.db',
            driver: sqlite3.Database
        });

        await db.exec(`
            CREATE TABLE IF NOT EXISTS azure_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                ua_name TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )
        `);

        await db.exec(`
            CREATE TABLE IF NOT EXISTS models_cache (
                id INTEGER PRIMARY KEY,
                models TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            )
        `);

        console.log('Database initialized');
    } catch (error) {
        console.error('Database initialization failed, falling back to memory storage:', error);
        db = null;
    }
}

// Azure Key 管理器
class AzureKeyManager {
    async getKeys() {
        const now = Date.now();
        
        if (db) {
            // 删除过期的keys
            await db.run('DELETE FROM azure_keys WHERE expires_at < ?', now);
            
            // 获取有效的keys
            const keys = await db.all('SELECT * FROM azure_keys WHERE expires_at > ?', now);
            return keys;
        } else {
            // 内存存储
            memoryStore.keys = memoryStore.keys.filter(k => k.expires_at > now);
            return memoryStore.keys;
        }
    }

    async addKey(key, uaName) {
        const now = Date.now();
        const expiresAt = now + (KEY_EXPIRY_MINUTES * 60 * 1000);
        
        const keyData = {
            key: key,
            ua_name: uaName,
            created_at: now,
            expires_at: expiresAt
        };

        if (db) {
            await db.run(
                'INSERT INTO azure_keys (key, ua_name, created_at, expires_at) VALUES (?, ?, ?, ?)',
                keyData.key, keyData.ua_name, keyData.created_at, keyData.expires_at
            );
        } else {
            memoryStore.keys.push(keyData);
        }
    }

    async ensureKeys() {
        const keys = await this.getKeys();
        const needed = MAX_KEYS - keys.length;
        
        if (needed > 0) {
            for (let i = 0; i < needed; i++) {
                await this.generateNewKey();
            }
        }
        
        return await this.getKeys();
    }

    async generateNewKey() {
        try {
            // 随机选择一个UA
            const uaNames = Object.keys(USER_AGENTS);
            const uaName = uaNames[Math.floor(Math.random() * uaNames.length)];
            const userAgent = USER_AGENTS[uaName];

            // 获取公钥
            const response = await axios.post(`${BASE_URL}/backend-api/v2/public-key`, {}, {
                headers: {
                    'User-Agent': userAgent
                }
            });

            const { data, public_key, user } = response.data;

            // 构造payload
            const payload = {
                data: data,
                user: user,
                timestamp: Date.now(),
                user_agent: userAgent
            };

            // RSA加密
            const key = new NodeRSA();
            key.importKey(public_key, 'public');
            key.setOptions({ encryptionScheme: 'pkcs1' });
            
            const encrypted = key.encrypt(JSON.stringify(payload), 'base64');
            
            // 保存key
            await this.addKey(encrypted, uaName);
            
            console.log(`Generated new Azure key with UA: ${uaName}`);
            return encrypted;
        } catch (error) {
            console.error('Failed to generate Azure key:', error.message);
            throw error;
        }
    }

    async getRandomKey() {
        const keys = await this.ensureKeys();
        if (keys.length === 0) {
            throw new Error('No valid Azure keys available');
        }
        
        const randomKey = keys[Math.floor(Math.random() * keys.length)];
        return {
            key: randomKey.key,
            userAgent: USER_AGENTS[randomKey.ua_name]
        };
    }
}

const keyManager = new AzureKeyManager();

// 模型缓存管理
async function getModelsCache() {
    const now = Date.now();
    
    if (db) {
        const cache = await db.get('SELECT * FROM models_cache WHERE expires_at > ? LIMIT 1', now);
        if (cache) {
            return JSON.parse(cache.models);
        }
    } else {
        if (memoryStore.modelsExpiry && memoryStore.modelsExpiry > now) {
            return memoryStore.models;
        }
    }
    
    return null;
}

async function setModelsCache(models) {
    const expiresAt = Date.now() + (MODEL_CACHE_DAYS * 24 * 60 * 60 * 1000);
    
    if (db) {
        await db.run('DELETE FROM models_cache');
        await db.run(
            'INSERT INTO models_cache (id, models, expires_at) VALUES (1, ?, ?)',
            JSON.stringify(models), expiresAt
        );
    } else {
        memoryStore.models = models;
        memoryStore.modelsExpiry = expiresAt;
    }
}

// 鉴权中间件
function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const token = authHeader.substring(7);
    if (!AUTH_TOKENS.includes(token)) {
        return res.status(401).json({ error: 'Invalid token' });
    }
    
    next();
}

// 处理文件URL
function processFileUrl(url) {
    if (!url) return url;
    
    // 处理相对路径
    if (url.startsWith('/media/') || url.startsWith('/thumbnail/')) {
        url = `${BASE_URL}${url}`;
    }
    
    // 添加代理
    if (PROXY_ENCODE) {
        return `${PROXY_URL}${encodeURIComponent(url)}`;
    } else {
        return `${PROXY_URL}${url}`;
    }
}

// 处理响应内容中的媒体链接
function processMediaLinks(content) {
    if (!content) return content;
    
    // 处理 audio/video 标签中的 src
    content = content.replace(/src="\/media\/([^"]+)"/g, (match, path) => {
        const url = `${BASE_URL}/media/${path}`;
        return `src="${processFileUrl(url)}"`;
    });
    
    return content;
}

// GET /v1/models
app.get('/v1/models', authenticate, async (req, res) => {
    try {
        // 检查缓存
        let models = await getModelsCache();
        
        if (!models) {
            // 获取Azure key
            const { key, userAgent } = await keyManager.getRandomKey();
            
            // 请求模型列表
            const response = await axios.get(`${BASE_URL}/api/Azure/models`, {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${key}`,
                    'User-Agent': userAgent
                }
            });
            
            models = response.data.data;
            await setModelsCache(models);
        }
        
        // 转换为OpenAI格式
        const openaiModels = models.map(model => ({
            id: model.id,
            object: 'model',
            created: Math.floor(Date.now() / 1000),
            owned_by: '',
            image: model.image || false,
            vision: model.vision || false,
            audio: model.audio || false
        }));
        
        res.json({
            object: 'list',
            data: openaiModels
        });
    } catch (error) {
        console.error('Error fetching models:', error.message);
        res.status(500).json({ error: 'Failed to fetch models' });
    }
});

// POST /v1/chat/completions
app.post('/v1/chat/completions', authenticate, async (req, res) => {
    try {
        const { messages, stream = false, model } = req.body;
        
        // 获取模型信息
        let models = await getModelsCache();
        if (!models) {
            const { key, userAgent } = await keyManager.getRandomKey();
            const response = await axios.get(`${BASE_URL}/api/Azure/models`, {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${key}`,
                    'User-Agent': userAgent
                }
            });
            models = response.data.data;
            await setModelsCache(models);
        }
        
        const modelInfo = models.find(m => m.id === model);
        if (!modelInfo) {
            return res.status(400).json({ error: `Model ${model} not found` });
        }
        
        // 获取Azure key
        const { key, userAgent } = await keyManager.getRandomKey();
        
        // 处理图片生成模型
        if (modelInfo.image === true) {
            // 获取最后一个user消息的content作为prompt
            const lastUserMessage = [...messages].reverse().find(m => m.role === 'user');
            if (!lastUserMessage) {
                return res.status(400).json({ error: 'No user message found' });
            }
            
            const prompt = lastUserMessage.content;
            
            // 请求图片生成
            const response = await axios.post(
                `${BASE_URL}/api/Azure/images/generations`,
                {
                    model: model,
                    prompt: prompt
                },
                {
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${key}`,
                        'User-Agent': userAgent
                    }
                }
            );
            
            const imageData = response.data;
            const imageUrl = processFileUrl(imageData.data[0].url);
            
            // 格式化响应内容
            const content = `## 图片已生成成功\n### 提示词如下：${prompt}\n### 绘图模型：${model}\n### 绘图结果如下：\n![${prompt}](${imageUrl})`;
            
            if (stream) {
                // 流式响应
                res.setHeader('Content-Type', 'text/event-stream');
                res.setHeader('Cache-Control', 'no-cache');
                res.setHeader('Connection', 'keep-alive');
                
                const messageId = `chatcmpl-${crypto.randomBytes(16).toString('hex')}`;
                
                res.write(`data: ${JSON.stringify({
                    id: messageId,
                    object: 'chat.completion.chunk',
                    created: Math.floor(Date.now() / 1000),
                    model: model,
                    choices: [{
                        index: 0,
                        delta: { role: 'assistant', content: content },
                        finish_reason: null
                    }]
                })}\n\n`);
                
                res.write(`data: ${JSON.stringify({
                    id: messageId,
                    object: 'chat.completion.chunk',
                    created: Math.floor(Date.now() / 1000),
                    model: model,
                    choices: [{
                        index: 0,
                        delta: { content: '' },
                        finish_reason: 'stop'
                    }]
                })}\n\n`);
                
                res.write('data: [DONE]\n\n');
                res.end();
            } else {
                // 非流式响应
                res.json({
                    id: `chatcmpl-${crypto.randomBytes(16).toString('hex')}`,
                    object: 'chat.completion',
                    created: Math.floor(Date.now() / 1000),
                    model: model,
                    choices: [{
                        index: 0,
                        message: {
                            role: 'assistant',
                            content: content
                        },
                        finish_reason: 'stop'
                    }],
                    usage: {
                        prompt_tokens: 0,
                        completion_tokens: 0,
                        total_tokens: 0
                    }
                });
            }
        } else {
            // 普通聊天或音频模型
            const targetUrl = `${BASE_URL}/api/Azure/chat/completions`;
            
            if (stream) {
                // 流式转发
                res.setHeader('Content-Type', 'text/event-stream');
                res.setHeader('Cache-Control', 'no-cache');
                res.setHeader('Connection', 'keep-alive');
                
                const response = await axios.post(
                    targetUrl,
                    req.body,
                    {
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${key}`,
                            'User-Agent': userAgent
                        },
                        responseType: 'stream'
                    }
                );
                
                let buffer = '';
                
                response.data.on('data', (chunk) => {
                    buffer += chunk.toString();
                    const lines = buffer.split('\n');
                    buffer = lines.pop() || '';
                    
                    for (const line of lines) {
                        if (line.trim()) {
                            // 处理音频模型的媒体链接
                            if (modelInfo.audio === true && line.includes('src=')) {
                                const processedLine = processMediaLinks(line);
                                res.write(processedLine + '\n');
                            } else {
                                res.write(line + '\n');
                            }
                        }
                    }
                });
                
                response.data.on('end', () => {
                    if (buffer.trim()) {
                        if (modelInfo.audio === true && buffer.includes('src=')) {
                            res.write(processMediaLinks(buffer) + '\n');
                        } else {
                            res.write(buffer + '\n');
                        }
                    }
                    res.end();
                });
                
                response.data.on('error', (error) => {
                    console.error('Stream error:', error);
                    res.end();
                });
            } else {
                // 非流式转发
                const response = await axios.post(
                    targetUrl,
                    req.body,
                    {
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${key}`,
                            'User-Agent': userAgent
                        }
                    }
                );
                
                let responseData = response.data;
                
                // 处理音频模型的媒体链接
                if (modelInfo.audio === true && responseData.choices) {
                    responseData.choices = responseData.choices.map(choice => {
                        if (choice.message && choice.message.content) {
                            choice.message.content = processMediaLinks(choice.message.content);
                        }
                        return choice;
                    });
                }
                
                res.json(responseData);
            }
        }
    } catch (error) {
        console.error('Error in chat completions:', error.message);
        res.status(500).json({ error: 'Failed to process request' });
    }
});

// POST /v1/images/generations
app.post('/v1/images/generations', authenticate, async (req, res) => {
    try {
        const { model, prompt } = req.body;
        
        // 获取Azure key
        const { key, userAgent } = await keyManager.getRandomKey();
        
        // 请求图片生成
        const response = await axios.post(
            `${BASE_URL}/api/Azure/images/generations`,
            {
                model: model,
                prompt: prompt
            },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${key}`,
                    'User-Agent': userAgent
                }
            }
        );
        
        // 处理响应
        const responseData = response.data;
        if (responseData.data) {
            responseData.data = responseData.data.map(item => ({
                ...item,
                url: processFileUrl(item.url)
            }));
        }
        
        res.json(responseData);
    } catch (error) {
        console.error('Error in image generation:', error.message);
        res.status(500).json({ error: 'Failed to generate image' });
    }
});

// 健康检查
app.get('/health', (req, res) => {
    res.json({ status: 'healthy' });
});

// 启动服务器
async function start() {
    await initDatabase();
    
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Base URL: ${BASE_URL}`);
        console.log(`Auth tokens: ${AUTH_TOKENS.length} configured`);
        console.log(`Max keys: ${MAX_KEYS}`);
        console.log(`Key expiry: ${KEY_EXPIRY_MINUTES} minutes`);
    });
}

start().catch(console.error);
