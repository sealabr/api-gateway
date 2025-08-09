# 🚀 API Gateway Node.js - Kong-like

Um API Gateway completo em Node.js que simula as principais funcionalidades do Kong, incluindo rate limiting, autenticação, autorização e proxy reverso.

## ✨ Funcionalidades

- 🛡️ **Autenticação**: API Key e JWT Token
- ⏱️ **Rate Limiting**: Controle de taxa personalizável
- 🔐 **Autorização**: Controle de endpoints permitidos
- 🔄 **Proxy Reverso**: Encaminhamento para serviços upstream
- 📊 **Logging**: Logs detalhados de requests
- 👨‍💼 **Admin API**: Interface administrativa
- 🏥 **Health Check**: Monitoramento de saúde
- 🛡️ **Segurança**: Headers de segurança com Helmet
- 🌐 **CORS**: Configuração flexível de CORS

## 🚀 Instalação e Uso

### 1. Instalar dependências
```bash
npm install
```

### 2. Configurar ambiente
Copie o arquivo `.env` e ajuste as configurações:

```bash
# Configurações essenciais
PORT=8000
UPSTREAM_URL=http://httpbin.org
API_KEY=minha-api-key-super-secreta
ALLOWED_ENDPOINTS=/get,/post,/put,/delete,/status/*,/anything/*
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100
CORS_ORIGIN=*
LOG_LEVEL=info
ADMIN_TOOLS_TOKEN=admin-secret-token
```

### 3. Executar
```bash
# Produção
npm start

# Desenvolvimento (com nodemon)
npm run dev
```

### 4. Testar
```bash
# Testes básicos
npm test

# Testes de CORS
npm run test:cors
```

## 📡 Endpoints

### Gateway Principal (Porta 8000)

#### Health Check
```bash
GET /health
# Retorna: { "status": "healthy", "timestamp": "...", "gateway": "nodejs-kong-like" }
```

#### Autenticação JWT
```bash
POST /auth/token
Content-Type: application/json
{
  "username": "test-user",
  "apiKey": "minha-api-key-super-secreta"
}
# Retorna: { "access_token": "jwt-token...", "token_type": "Bearer", "expires_in": 3600 }
```

#### Requests Autenticados
```bash
# Com API Key
GET /get
x-api-key: minha-api-key-super-secreta

# Com JWT Token
GET /get  
Authorization: Bearer your-jwt-token-here
```

### Admin API (Porta 8001)

#### Estatísticas
```bash
GET /stats
# Retorna estatísticas do gateway
```

#### Limpar Rate Limits
```bash
DELETE /rate-limits
# Remove todos os rate limits ativos
```

## 🔐 Autenticação

### API Key
Adicione o header `x-api-key` com sua chave:
```bash
curl -H "x-api-key: minha-api-key-super-secreta" http://localhost:8000/get
```

### JWT Token
1. Gere um token:
```bash
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"test","apiKey":"minha-api-key-super-secreta"}'
```

2. Use o token:
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8000/get
```

## ⏱️ Rate Limiting

O gateway implementa rate limiting inteligente:

- **Window-based**: Controla requests por janela de tempo
- **Per-client**: Rate limit individual por IP + API Key
- **Headers informativos**: 
  - `X-RateLimit-Limit`: Limite máximo
  - `X-RateLimit-Remaining`: Requests restantes
  - `X-RateLimit-Reset`: Quando o limite reseta

### Configuração
```env
RATE_LIMIT_WINDOW=15  # minutos
RATE_LIMIT_MAX=100    # requests por window
```

### Response quando limite excedido:
```json
{
  "error": "Rate limit exceeded",
  "message": "Maximum 100 requests per 15 minutes",
  "retryAfter": 900
}
```

## 🌐 Configuração CORS

O gateway suporta configuração flexível de CORS (Cross-Origin Resource Sharing) para controlar quais domínios podem acessar a API.

### Configuração CORS_ORIGIN

```env
# Permitir todos os domínios (padrão)
CORS_ORIGIN=*

# Permitir domínio específico
CORS_ORIGIN=https://meuapp.com

# Permitir múltiplos domínios (separados por vírgula)
CORS_ORIGIN=https://app1.com,https://app2.com,http://localhost:3000

# Permitir subdomínios específicos
CORS_ORIGIN=https://*.meudominio.com
```

### Como Funciona

O `CORS_ORIGIN` controla o header `Access-Control-Allow-Origin`:

- **`*`**: Permite requisições de qualquer domínio (menos seguro)
- **Domínio específico**: `https://meuapp.com` - só permite requisições deste domínio
- **Múltiplos domínios**: Lista separada por vírgula para permitir vários domínios
- **Subdomínios**: `https://*.meudominio.com` - permite todos os subdomínios

### Headers CORS Configurados

O gateway automaticamente configura:

```javascript
{
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'x-api-key', 
    'x-csrf-token', 
    'x-admin-token'
  ]
}
```

### Exemplos de Uso

#### 1. Desenvolvimento Local
```env
CORS_ORIGIN=http://localhost:3000,http://localhost:8080
```
**Uso**: Para desenvolvimento com React, Vue, Angular rodando em portas locais.

#### 2. Produção - Domínio Específico
```env
CORS_ORIGIN=https://meuapp.com
```
**Uso**: Para produção com domínio específico (mais seguro).

#### 3. Múltiplos Ambientes
```env
CORS_ORIGIN=https://app.com,https://staging.app.com,http://localhost:3000
```
**Uso**: Para aplicações com múltiplos ambientes (dev, staging, prod).

#### 4. Permitir Todos (Desenvolvimento)
```env
CORS_ORIGIN=*
```
**Uso**: Para desenvolvimento/testes (menos seguro, não usar em produção).

#### 5. Subdomínios
```env
CORS_ORIGIN=https://*.meudominio.com
```
**Uso**: Para permitir todos os subdomínios de um domínio específico.

### Testando CORS

#### Teste Manual com curl
```bash
# Teste com curl
curl -H "Origin: https://meuapp.com" \
     -H "Access-Control-Request-Method: POST" \
     -H "Access-Control-Request-Method: Content-Type" \
     -X OPTIONS http://localhost:8000/get

# Resposta esperada:
# Access-Control-Allow-Origin: https://meuapp.com
# Access-Control-Allow-Methods: GET,POST,PUT,DELETE,PATCH,OPTIONS
# Access-Control-Allow-Headers: Content-Type,Authorization,x-api-key,x-csrf-token,x-admin-token
```

#### Teste Automatizado
Execute o script de teste CORS:

```bash
# Instalar axios se necessário
npm install axios

# Executar testes CORS
node test-cors.js
```

O script testa:
- ✅ Origins permitidos
- ❌ Origins bloqueados  
- 🚀 Requisições reais com CORS
- 📊 Headers de resposta CORS

## 🎯 Autorização de Endpoints

Configure quais endpoints são permitidos:

```env
# Endpoints específicos
ALLOWED_ENDPOINTS=/get,/post,/put,/delete

# Com wildcards (/* permite sub-rotas)
ALLOWED_ENDPOINTS=/api/*,/v1/*,/status/*,/health

# Com wildcards no meio da URL
ALLOWED_ENDPOINTS=/bot/*/tokenByName,/users/*/profile
```

### Exemplos:
- `/api/*` ✅ permite `/api/users`, `/api/orders`, etc.
- `/status/*` ✅ permite `/status/200`, `/status/404`, etc.
- `/bot/*/tokenByName` ✅ permite `/bot/empresa123/tokenByName`, `/bot/empresa456/tokenByName`, etc.
- `/users/*/profile` ✅ permite `/users/123/profile`, `/users/john/profile`, etc.
- `/exact-path` ✅ permite apenas `/exact-path`

## 📊 Monitoramento

### Logs
O gateway loga automaticamente:
```
2024-01-15T10:30:45.123Z - GET /get - 200 - 45ms - 192.168.1.100
🔄 Proxying: GET /get → http://httpbin.org/get
```

### Métricas via Admin API
```bash
curl http://localhost:8001/stats
```

```json
{
  "rateLimitEntries": 5,
  "upstreamUrl": "http://httpbin.org",
  "allowedEndpoints": ["/get", "/post", "/status/*"],
  "rateLimitConfig": {
    "window": 15,
    "max": 100
  },
  "activeConnections": "active"
}
```

## 🔧 Configurações Avançadas

### Variáveis de Ambiente

```env
# Portas
PORT=8000

# Upstream
UPSTREAM_URL=http://httpbin.org

# Segurança
API_KEY=minha-api-key-super-secreta

# Endpoints
ALLOWED_ENDPOINTS=/get,/post,/put,/delete,/status/*,/anything/*,/bot/*/tokenByName

# Rate Limiting
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100

# CORS
CORS_ORIGIN=*

# Logs
LOG_LEVEL=info

# Admin
ADMIN_TOOLS_TOKEN=admin-secret-token
```
