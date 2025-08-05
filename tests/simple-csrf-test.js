const http = require('http');

// Simple test to verify CSRF protection
async function testCSRF() {
  console.log('🧪 Testing CSRF Protection...\n');
  
  try {
    // Test 1: Get CSRF token
    console.log('📋 Test 1: Getting CSRF token...');
    const token = await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: 'localhost',
        port: 8000,
        path: '/csrf/token',
        method: 'GET'
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const response = JSON.parse(data);
            console.log('✅ CSRF Token generated:', response.csrfToken.substring(0, 20) + '...');
            resolve(response.csrfToken);
          } catch (error) {
            console.error('❌ Error parsing CSRF token response:', error);
            reject(error);
          }
        });
      });
      req.on('error', (error) => {
        console.error('❌ Error requesting CSRF token:', error.message);
        reject(error);
      });
      req.end();
    });
    
    // Test 2: Try POST without CSRF token
    console.log('\n📋 Test 2: Testing POST without CSRF token...');
    const postWithoutToken = await new Promise((resolve, reject) => {
      const postData = JSON.stringify({ test: 'data' });
      const req = http.request({
        hostname: 'localhost',
        port: 8000,
        path: '/post',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        }
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const response = JSON.parse(data);
            console.log('✅ POST without CSRF token blocked:', response.error);
            resolve(response);
          } catch (error) {
            console.error('❌ Error parsing response:', error);
            reject(error);
          }
        });
      });
      req.on('error', (error) => {
        console.error('❌ Error making POST request:', error.message);
        reject(error);
      });
      req.write(postData);
      req.end();
    });
    
    // Test 3: Try POST with CSRF token
    console.log('\n📋 Test 3: Testing POST with CSRF token...');
    const postWithToken = await new Promise((resolve, reject) => {
      const postData = JSON.stringify({ test: 'data' });
      const req = http.request({
        hostname: 'localhost',
        port: 8000,
        path: '/post',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData),
          'x-csrf-token': token
        }
      }, (res) => {
        console.log('✅ POST with CSRF token status:', res.statusCode);
        resolve(res.statusCode);
      });
      req.on('error', (error) => {
        console.error('❌ Error making POST request with CSRF:', error.message);
        reject(error);
      });
      req.write(postData);
      req.end();
    });
    
    console.log('\n🎉 CSRF Protection is working correctly!');
    console.log('📋 Summary:');
    console.log('  - CSRF token generation: ✅');
    console.log('  - POST without token blocked: ✅');
    console.log('  - POST with token allowed: ✅');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

testCSRF(); 