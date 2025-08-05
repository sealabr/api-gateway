#!/usr/bin/env node

const axios = require('axios');

const BASE_URL = 'http://localhost:8000';
const ADMIN_URL = 'http://localhost:8001';
const API_KEY = 'minha-api-key-super-secreta';

console.log('🧪 Iniciando testes do API Gateway...\n');

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function testHealthCheck() {
  console.log('✅ Teste 1: Health Check');
  try {
    const response = await axios.get(`${BASE_URL}/health`);
    console.log('Status:', response.status);
    console.log('Data:', response.data);
    console.log('✅ Health check OK\n');
  } catch (error) {
    console.error('❌ Health check failed:', error.message);
  }
}

async function testWithoutAuth() {
  console.log('🔐 Teste 2: Request sem autenticação');
  try {
    const response = await axios.get(`${BASE_URL}/get`);
    console.log('❌ Não deveria funcionar sem auth');
  } catch (error) {
    console.log('✅ Bloqueado corretamente:', error.response.status, error.response.data.error);
  }
  console.log();
}

async function testWithApiKey() {
  console.log('🔑 Teste 3: Request com API Key');
  try {
    const response = await axios.get(`${BASE_URL}/get`, {
      headers: {
        'x-api-key': API_KEY
      }
    });
    console.log('✅ Request autorizado:', response.status);
    console.log('Headers recebidos:', Object.keys(response.headers));
    console.log('Rate limit remaining:', response.headers['x-ratelimit-remaining']);
  } catch (error) {
    console.error('❌ Falha com API key:', error.response?.data || error.message);
  }
  console.log();
}

async function testJWTToken() {
  console.log('🎫 Teste 4: Gerando e usando JWT Token');
  
  try {
    // Gerar token
    const tokenResponse = await axios.post(`${BASE_URL}/auth/token`, {
      username: 'testuser',
      apiKey: API_KEY
    });
    
    const token = tokenResponse.data.access_token;
    console.log('✅ Token gerado:', token.substring(0, 50) + '...');
    
    // Usar token
    const response = await axios.get(`${BASE_URL}/json`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    console.log('✅ Request com JWT OK:', response.status);
    console.log('Data:', response.data);
  } catch (error) {
    console.error('❌ Falha com JWT:', error.response?.data || error.message);
  }
  console.log();
}

async function testForbiddenEndpoint() {
  console.log('🚫 Teste 5: Endpoint não permitido');
  try {
    const response = await axios.get(`${BASE_URL}/forbidden-endpoint`, {
      headers: {
        'x-api-key': API_KEY
      }
    });
    console.log('❌ Não deveria permitir endpoint proibido');
  } catch (error) {
    console.log('✅ Endpoint bloqueado corretamente:', error.response.status, error.response.data.error);
  }
  console.log();
}

async function testRateLimit() {
  console.log('⏱️ Teste 6: Rate Limiting (fazendo 5 requests rápidos)');
  
  for (let i = 1; i <= 5; i++) {
    try {
      const response = await axios.get(`${BASE_URL}/get`, {
        headers: {
          'x-api-key': API_KEY
        }
      });
      
      console.log(`Request ${i}: Status ${response.status}, Remaining: ${response.headers['x-ratelimit-remaining']}`);
    } catch (error) {
      if (error.response?.status === 429) {
        console.log(`Request ${i}: ✅ Rate limit atingido (429)`);
      } else {
        console.error(`Request ${i}: ❌ Erro:`, error.response?.data || error.message);
      }
    }
    
    await sleep(100); // Pequena pausa
  }
  console.log();
}

async function testAdminAPI() {
  console.log('👨‍💼 Teste 7: Admin API - Estatísticas');
  try {
    const response = await axios.get(`${ADMIN_URL}/stats`);
    console.log('✅ Admin API OK');
    console.log('Stats:', JSON.stringify(response.data, null, 2));
  } catch (error) {
    console.error('❌ Admin API falhou:', error.message);
  }
  console.log();
}

async function testDifferentMethods() {
  console.log('🔄 Teste 8: Diferentes métodos HTTP');
  
  const methods = [
    { method: 'GET', url: '/get' },
    { method: 'POST', url: '/post', data: { test: 'data' } },
    { method: 'PUT', url: '/put', data: { update: 'data' } },
    { method: 'DELETE', url: '/delete' }
  ];
  
  for (const { method, url, data } of methods) {
    try {
      const config = {
        method: method.toLowerCase(),
        url: `${BASE_URL}${url}`,
        headers: {
          'x-api-key': API_KEY,
          'Content-Type': 'application/json'
        }
      };
      
      if (data) config.data = data;
      
      const response = await axios(config);
      console.log(`✅ ${method} ${url}: Status ${response.status}`);
    } catch (error) {
      console.error(`❌ ${method} ${url}:`, error.response?.status || error.message);
    }
  }
  console.log();
}

async function runAllTests() {
  console.log('🚀 Certifique-se de que o gateway está rodando em http://localhost:8000\n');
  
  await testHealthCheck();
  await testWithoutAuth();
  await testWithApiKey();
  await testJWTToken();
  await testForbiddenEndpoint();
  await testRateLimit();
  await testAdminAPI();
  await testDifferentMethods();
  
  console.log('🏁 Testes concluídos!');
  console.log('\n📊 Para ver stats em tempo real:');
  console.log(`curl ${ADMIN_URL}/stats`);
  console.log('\n🧹 Para limpar rate limits:');
  console.log(`curl -X DELETE ${ADMIN_URL}/rate-limits`);
}

// Verificar se axios está disponível
if (require.main === module) {
  // Instalar axios se não estiver disponível
  try {
    require('axios');
    runAllTests().catch(console.error);
  } catch (error) {
    console.log('📦 Instalando axios para testes...');
    const { execSync } = require('child_process');
    execSync('npm install axios', { stdio: 'inherit' });
    console.log('✅ Axios instalado, rodando testes...\n');
    delete require.cache[require.resolve('axios')];
    runAllTests().catch(console.error);
  }
}