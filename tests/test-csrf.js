const axios = require('axios');

const BASE_URL = 'http://localhost:80';
const API_KEY = 'default-api-key';

async function testCSRF() {
  console.log('🧪 Testando proteção CSRF...\n');

  try {
    // 1. Gerar token CSRF
    console.log('1️⃣ Gerando token CSRF...');
    const csrfResponse = await axios.get(`${BASE_URL}/csrf/token`);
    const csrfToken = csrfResponse.data.csrfToken;
    console.log(`✅ Token CSRF gerado: ${csrfToken.substring(0, 10)}...\n`);

    // 2. Testar POST sem CSRF token (deve falhar)
    console.log('2️⃣ Testando POST sem CSRF token (deve falhar)...');
    try {
      await axios.post(`${BASE_URL}/post`, 
        { test: 'data' },
        { 
          headers: { 
            'x-api-key': API_KEY,
            'Content-Type': 'application/json'
          }
        }
      );
      console.log('❌ ERRO: POST sem CSRF token foi aceito!');
    } catch (error) {
      if (error.response && error.response.status === 403) {
        console.log('✅ POST sem CSRF token foi bloqueado corretamente');
      } else {
        console.log('❌ Erro inesperado:', error.message);
      }
    }
    console.log('');

    // 3. Testar POST com CSRF token válido (deve funcionar)
    console.log('3️⃣ Testando POST com CSRF token válido...');
    try {
      const response = await axios.post(`${BASE_URL}/post`, 
        { test: 'data' },
        { 
          headers: { 
            'x-api-key': API_KEY,
            'x-csrf-token': csrfToken,
            'Content-Type': 'application/json'
          }
        }
      );
      console.log('✅ POST com CSRF token foi aceito');
      console.log(`📊 Status: ${response.status}`);
    } catch (error) {
      console.log('❌ POST com CSRF token falhou:', error.message);
    }
    console.log('');

    // 4. Testar GET (não deve precisar de CSRF)
    console.log('4️⃣ Testando GET (não deve precisar de CSRF)...');
    try {
      const response = await axios.get(`${BASE_URL}/get`, {
        headers: { 'x-api-key': API_KEY }
      });
      console.log('✅ GET funcionou sem CSRF token');
      console.log(`📊 Status: ${response.status}`);
    } catch (error) {
      console.log('❌ GET falhou:', error.message);
    }
    console.log('');

    // 5. Testar POST com CSRF token inválido (deve falhar)
    console.log('5️⃣ Testando POST com CSRF token inválido...');
    try {
      await axios.post(`${BASE_URL}/post`, 
        { test: 'data' },
        { 
          headers: { 
            'x-api-key': API_KEY,
            'x-csrf-token': 'token-invalido',
            'Content-Type': 'application/json'
          }
        }
      );
      console.log('❌ ERRO: POST com token inválido foi aceito!');
    } catch (error) {
      if (error.response && error.response.status === 403) {
        console.log('✅ POST com token inválido foi bloqueado corretamente');
      } else {
        console.log('❌ Erro inesperado:', error.message);
      }
    }

  } catch (error) {
    console.error('❌ Erro no teste:', error.message);
  }
}

// Executar teste
testCSRF(); 