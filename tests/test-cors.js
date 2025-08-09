const axios = require('axios');

// Configurações de teste
const GATEWAY_URL = 'http://localhost:8000';
const TEST_ENDPOINTS = ['/get', '/post', '/status/200'];

// Função para testar CORS
async function testCORS(origin, expectedSuccess = true) {
  console.log(`\n🌐 Testando CORS com Origin: ${origin}`);
  console.log('─'.repeat(50));
  
  for (const endpoint of TEST_ENDPOINTS) {
    try {
      const response = await axios({
        method: 'OPTIONS',
        url: `${GATEWAY_URL}${endpoint}`,
        headers: {
          'Origin': origin,
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'Content-Type,Authorization,x-api-key'
        }
      });
      
      console.log(`✅ ${endpoint}:`);
      console.log(`   Access-Control-Allow-Origin: ${response.headers['access-control-allow-origin']}`);
      console.log(`   Access-Control-Allow-Methods: ${response.headers['access-control-allow-methods']}`);
      console.log(`   Access-Control-Allow-Headers: ${response.headers['access-control-allow-headers']}`);
      
    } catch (error) {
      if (expectedSuccess) {
        console.log(`❌ ${endpoint}: Erro inesperado - ${error.message}`);
      } else {
        console.log(`✅ ${endpoint}: Bloqueado corretamente (esperado)`);
      }
    }
  }
}

// Função para testar requisição real
async function testRealRequest(origin, apiKey) {
  console.log(`\n🚀 Testando requisição real com Origin: ${origin}`);
  console.log('─'.repeat(50));
  
  try {
    const response = await axios({
      method: 'GET',
      url: `${GATEWAY_URL}/get`,
      headers: {
        'Origin': origin,
        'x-api-key': apiKey
      }
    });
    
    console.log(`✅ Requisição bem-sucedida:`);
    console.log(`   Status: ${response.status}`);
    console.log(`   Access-Control-Allow-Origin: ${response.headers['access-control-allow-origin']}`);
    console.log(`   Data: ${JSON.stringify(response.data, null, 2)}`);
    
  } catch (error) {
    console.log(`❌ Erro na requisição: ${error.message}`);
    if (error.response) {
      console.log(`   Status: ${error.response.status}`);
      console.log(`   Data: ${JSON.stringify(error.response.data, null, 2)}`);
    }
  }
}

// Função principal
async function runCORSTests() {
  console.log('🧪 Testes de CORS para API Gateway');
  console.log('='.repeat(60));
  
  // Teste 1: Origin permitido (localhost)
  await testCORS('http://localhost:3000', true);
  
  // Teste 2: Origin permitido (domínio específico)
  await testCORS('https://meuapp.com', true);
  
  // Teste 3: Origin não permitido (quando CORS_ORIGIN não é *)
  await testCORS('https://evil-site.com', false);
  
  // Teste 4: Requisição real
  await testRealRequest('http://localhost:3000', 'default-api-key');
  
  console.log('\n📋 Resumo dos testes:');
  console.log('• CORS_ORIGIN=* permite qualquer origem');
  console.log('• CORS_ORIGIN=https://meuapp.com só permite este domínio');
  console.log('• CORS_ORIGIN=domain1.com,domain2.com permite múltiplos domínios');
  console.log('• Headers CORS são aplicados automaticamente');
}

// Executar testes se chamado diretamente
if (require.main === module) {
  runCORSTests().catch(console.error);
}

module.exports = { testCORS, testRealRequest }; 