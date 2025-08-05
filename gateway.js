const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { createProxyMiddleware } = require('http-proxy-middleware');
require('dotenv').config();

const app = express();

// CSRF Token Store (em produção usar Redis)
const csrfTokens = new Map();

// Função para gerar CSRF token
const generateCSRFToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Função para limpar tokens CSRF expirados
const cleanupCSRFTokens = () => {
  const now = Date.now();
  const tokenLifetime = 24 * 60 * 60 * 1000; // 24 horas
  
  for (const [token, data] of csrfTokens.entries()) {
    if (now - data.createdAt > tokenLifetime) {
      csrfTokens.delete(token);
    }
  }
};

// Limpar tokens expirados a cada hora
setInterval(cleanupCSRFTokens, 60 * 60 * 1000);

// Middleware CSRF
const csrfProtection = (req, res, next) => {
  // Bypass para endpoints que não precisam de CSRF
  const csrfExemptPaths = ['/health', '/status', '/auth/token', '/csrf/token', '/admin/endpoints'];
  if (csrfExemptPaths.includes(req.path)) {
    console.log(`🛡️ CSRF: Bypass para ${req.path}`);
    return next();
  }
  
  // Apenas métodos que modificam dados precisam de CSRF
  const csrfRequiredMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
  if (!csrfRequiredMethods.includes(req.method)) {
    console.log(`🛡️ CSRF: Método ${req.method} não requer CSRF`);
    return next();
  }
  
  const csrfToken = req.headers['x-csrf-token'] || req.body._csrf || req.query._csrf;
  
  console.log(`🛡️ CSRF: Verificando token para ${req.method} ${req.path}`, {
    hasToken: !!csrfToken,
    tokenSource: csrfToken ? (req.headers['x-csrf-token'] ? 'header' : req.body._csrf ? 'body' : 'query') : 'none'
  });
  
  if (!csrfToken) {
    console.log(`🛡️ CSRF: Token ausente para ${req.method} ${req.path}`);
    return res.status(403).json({
      error: 'CSRF Token Missing',
      message: 'CSRF token is required for this request',
      code: 'CSRF_TOKEN_MISSING'
    });
  }
  
  const tokenData = csrfTokens.get(csrfToken);
  if (!tokenData) {
    console.log(`🛡️ CSRF: Token inválido para ${req.method} ${req.path}`);
    return res.status(403).json({
      error: 'Invalid CSRF Token',
      message: 'CSRF token is invalid or expired',
      code: 'CSRF_TOKEN_INVALID'
    });
  }
  
  // Verificar se o token não expirou (24 horas)
  const now = Date.now();
  const tokenLifetime = 24 * 60 * 60 * 1000;
  if (now - tokenData.createdAt > tokenLifetime) {
    console.log(`🛡️ CSRF: Token expirado para ${req.method} ${req.path}`);
    csrfTokens.delete(csrfToken);
    return res.status(403).json({
      error: 'CSRF Token Expired',
      message: 'CSRF token has expired',
      code: 'CSRF_TOKEN_EXPIRED'
    });
  }
  
  // Token válido, continuar
  console.log(`🛡️ CSRF: Token válido para ${req.method} ${req.path}`);
  req.csrfToken = csrfToken;
  next();
};

// Configuração de CORS
const corsOptions = {
  origin: process.env.CORS_ORIGIN ? 
    (process.env.CORS_ORIGIN === '*' ? '*' : process.env.CORS_ORIGIN.split(',')) : 
    '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'x-csrf-token', 'x-admin-token']
};

// Middleware básico
app.use(helmet()); // Segurança
app.use(cors(corsOptions)); // CORS configurado
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configurações do ambiente
const config = {
  port: process.env.PORT || 80,
  upstreamUrl: process.env.UPSTREAM_URL || 'http://httpbin.org',
  apiKey: process.env.API_KEY || 'default-api-key',
  allowedEndpoints: process.env.ALLOWED_ENDPOINTS ? 
    process.env.ALLOWED_ENDPOINTS.split(',') : 
    ['/get', '/post', '/put', '/delete', '/status/*', '/anything/*', '/csrf/token'],
  rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW) || 15, // minutos
  rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX) || 100, // requests
  logLevel: process.env.LOG_LEVEL || 'info'
};

console.log('🚀 Gateway Config:', {
  upstreamUrl: config.upstreamUrl,
  allowedEndpoints: config.allowedEndpoints,
  rateLimit: `${config.rateLimitMax} req/${config.rateLimitWindow}min`
});

// Store para rate limiting avançado (em produção usar Redis)
const rateLimitStore = new Map();
const authTokens = new Map();

// Função para limpar rate limit store periodicamente
setInterval(() => {
  const now = Date.now();
  for (const [key, data] of rateLimitStore.entries()) {
    if (now - data.resetTime > 0) {
      rateLimitStore.delete(key);
    }
  }
}, 60000); // Limpa a cada minuto

// Middleware de logging
const logger = (req, res, next) => {
  const start = Date.now();
  const originalSend = res.send;
  
  res.send = function(data) {
    const duration = Date.now() - start;
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - ${res.statusCode} - ${duration}ms - ${req.ip}`);
    originalSend.call(this, data);
  };
  
  next();
};

app.use(logger);

// Rate Limiting Avançado
const advancedRateLimit = (req, res, next) => {
  const clientId = req.ip + (req.headers['x-api-key'] || '');
  const now = Date.now();
  const windowMs = config.rateLimitWindow * 60 * 1000;
  
  if (!rateLimitStore.has(clientId)) {
    rateLimitStore.set(clientId, {
      count: 1,
      resetTime: now + windowMs,
      firstRequest: now
    });
    return next();
  }
  
  const clientData = rateLimitStore.get(clientId);
  
  if (now > clientData.resetTime) {
    // Reset window
    clientData.count = 1;
    clientData.resetTime = now + windowMs;
    clientData.firstRequest = now;
  } else {
    clientData.count++;
  }
  
  // Headers informativos
  res.set({
    'X-RateLimit-Limit': config.rateLimitMax,
    'X-RateLimit-Remaining': Math.max(0, config.rateLimitMax - clientData.count),
    'X-RateLimit-Reset': new Date(clientData.resetTime).toISOString()
  });
  
  if (clientData.count > config.rateLimitMax) {
    return res.status(429).json({
      error: 'Rate limit exceeded',
      message: `Maximum ${config.rateLimitMax} requests per ${config.rateLimitWindow} minutes`,
      retryAfter: Math.ceil((clientData.resetTime - now) / 1000)
    });
  }
  
  next();
};

// Middleware de autenticação
const authenticate = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  const authHeader = req.headers.authorization;
  
  // Bypass para alguns endpoints
  if (req.path === '/health' || req.path === '/status' || req.path === '/csrf/token' || req.path === '/admin/endpoints') {
    return next();
  }
  
  // Verificar API Key
  if (apiKey) {
    if (apiKey !== config.apiKey) {
      return res.status(401).json({ 
        error: 'Invalid API Key',
        message: 'Provided API key is not valid'
      });
    }
    req.authType = 'api-key';
    return next();
  }
  
  // Sem autenticação válida
  return res.status(401).json({ 
    error: 'Authentication Required',
    message: 'Provide valid API key (x-api-key header) or JWT token (Authorization: Bearer)'
  });
};

// Middleware de autorização de endpoints
const authorizeEndpoint = (req, res, next) => {
  const requestPath = req.path;
  
  // Bypass para endpoints internos do gateway
  if (requestPath === '/health' || requestPath === '/status' || requestPath === '/csrf/token' || requestPath === '/auth/token' || requestPath === '/admin/endpoints') {
    return next();
  }
  
  // Verificar se o endpoint é permitido
  const isAllowed = config.allowedEndpoints.some(pattern => {
    if (pattern.endsWith('/*')) {
      const basePath = pattern.slice(0, -2);
      return requestPath.startsWith(basePath);
    }
    return requestPath === pattern;
  });
  
  if (!isAllowed) {
    return res.status(403).json({
      error: 'Endpoint Not Allowed',
      message: `Endpoint ${requestPath} is not in the allowed list`
    });
  }
  
  next();
};

// Middleware de transformação de request
const transformRequest = (req, res, next) => {
  // Adicionar headers customizados
  req.headers['x-gateway'] = 'nodejs-kong-like';
  req.headers['x-forwarded-by'] = 'api-gateway';
  req.headers['x-client-ip'] = req.ip;
  
  // Log da transformação
  if (config.logLevel === 'debug') {
    console.log('Request transformation:', {
      originalPath: req.path,
      headers: req.headers,
      authType: req.authType
    });
  }
  
  next();
};

// Aplicar middlewares na ordem correta
app.use(advancedRateLimit);
app.use(authenticate);
app.use(authorizeEndpoint);
app.use(transformRequest);
app.use(csrfProtection); // Adicionar CSRF protection ANTES do proxy

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    gateway: 'nodejs-kong-like',
    version: '1.0.0'
  });
});

// Endpoint para gerar token JWT (para testes)
app.post('/auth/token', (req, res) => {
  const { username, apiKey } = req.body;
  
  if (apiKey !== config.apiKey) {
    return res.status(401).json({ error: 'Invalid API Key' });
  }
  
  const token = jwt.sign(
    { 
      username: username || 'test-user',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hora
    },
    config.jwtSecret
  );
  
  res.json({
    access_token: token,
    token_type: 'Bearer',
    expires_in: 3600
  });
});

// Endpoint para gerar token CSRF (para testes)
app.get('/csrf/token', (req, res) => {
  const csrfToken = generateCSRFToken();
  csrfTokens.set(csrfToken, { createdAt: Date.now() });
  res.json({ csrfToken });
});

// Endpoint para listar ALLOWED_ENDPOINTS (apenas com ADMIN_TOOLS_TOKEN)
app.get('/admin/endpoints', (req, res) => {
  const adminToken = req.headers['x-admin-token'] || req.headers['authorization']?.replace('Bearer ', '');
  
  if (!adminToken || adminToken !== process.env.ADMIN_TOOLS_TOKEN) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Valid admin token required',
      code: 'ADMIN_TOKEN_REQUIRED'
    });
  }
  
  res.json({
    allowedEndpoints: config.allowedEndpoints,
    total: config.allowedEndpoints.length,
    timestamp: new Date().toISOString(),
    gateway: 'nodejs-kong-like'
  });
});

// Proxy para o upstream
const proxyOptions = {
  target: config.upstreamUrl,
  changeOrigin: true,
  logLevel: config.logLevel === 'debug' ? 'debug' : 'error',
  onProxyReq: (proxyReq, req, res) => {
    // Log do proxy
    console.log(`🔄 Proxying: ${req.method} ${req.path} → ${config.upstreamUrl}${req.path}`);
  },
  onProxyRes: (proxyRes, req, res) => {
    // Adicionar headers de resposta customizados
    proxyRes.headers['x-gateway-response'] = 'nodejs-kong-like';
    proxyRes.headers['x-response-time'] = Date.now() - req.startTime;
  },
  onError: (err, req, res) => {
    console.error('❌ Proxy Error:', err.message);
    res.status(502).json({
      error: 'Bad Gateway',
      message: 'Error connecting to upstream service',
      upstream: config.upstreamUrl
    });
  }
};

// Aplicar proxy para todas as rotas restantes
app.use('/', createProxyMiddleware(proxyOptions));

// Error handler global
app.use((error, req, res, next) => {
  console.error('❌ Global Error:', error);
  res.status(500).json({
    error: 'Internal Server Error',
    message: 'Something went wrong in the gateway'
  });
});

// Servidor principal (Gateway)
const server = app.listen(config.port, () => {
  console.log(`\n🎉 API Gateway rodando!`);
  console.log(`📡 Gateway: http://localhost:${config.port}`);
  console.log(`🎯 Upstream: ${config.upstreamUrl}`);
  console.log(`🔐 API Key: ${config.apiKey}`);
  console.log(`📊 Rate Limit: ${config.rateLimitMax} req/${config.rateLimitWindow}min`);
  console.log(`🛡️  Endpoints Permitidos:`, config.allowedEndpoints);
  console.log(`🛡️  CSRF Protection: Ativo`);
});

// Logs de inicialização
console.log(`\n📋 Para testar:`);
console.log(`curl -H "x-api-key: ${config.apiKey}" http://localhost:${config.port}/get`);
console.log(`\n📋 Para gerar JWT:`);
console.log(`curl -X POST http://localhost:${config.port}/auth/token -H "Content-Type: application/json" -d '{"username":"test","apiKey":"${config.apiKey}"}'`);
console.log(`\n📋 Para gerar CSRF Token:`);
console.log(`curl http://localhost:${config.port}/csrf/token`);
console.log(`\n📋 Para testar com CSRF (POST):`);
console.log(`curl -X POST http://localhost:${config.port}/post -H "x-api-key: ${config.apiKey}" -H "x-csrf-token: SEU_CSRF_TOKEN" -H "Content-Type: application/json" -d '{"test":"data"}'`);

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('\n🛑 Shutting down gracefully...');
  server.close(() => {
    console.log('✅ Gateway closed');
    process.exit(0);
  });
});

module.exports = app;