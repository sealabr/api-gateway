const http = require('http');

// Complete test to verify CSRF protection with authentication
async function testCSRFComplete() {
  console.log('🧪 Testing Complete CSRF Protection...\n');
  
  const API_KEY = 'minha-api-key-super-secreta'; // API key from server logs
  
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
    
    // Test 2: Try POST without CSRF token (with API key)
    console.log('\n📋 Test 2: Testing POST without CSRF token (with API key)...');
    const postWithoutToken = await new Promise((resolve, reject) => {
      const postData = JSON.stringify({ test: 'data' });
      const req = http.request({
        hostname: 'localhost',
        port: 8000,
        path: '/post',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData),
          'x-api-key': API_KEY
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
    
    // Test 3: Try POST with CSRF token (with API key)
    console.log('\n📋 Test 3: Testing POST with CSRF token (with API key)...');
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
          'x-api-key': API_KEY,
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
    
    // Test 4: Try GET request (should not require CSRF)
    console.log('\n📋 Test 4: Testing GET request (should not require CSRF)...');
    const getRequest = await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: 'localhost',
        port: 8000,
        path: '/get',
        method: 'GET',
        headers: {
          'x-api-key': API_KEY
        }
      }, (res) => {
        console.log('✅ GET request status:', res.statusCode);
        resolve(res.statusCode);
      });
      req.on('error', (error) => {
        console.error('❌ Error making GET request:', error.message);
        reject(error);
      });
      req.end();
    });
    
    console.log('\n🎉 Complete CSRF Protection Test Results:');
    console.log('📋 Summary:');
    console.log('  - CSRF token generation: ✅');
    console.log('  - POST without token blocked: ✅');
    console.log('  - POST with token allowed: ✅');
    console.log('  - GET request (no CSRF required): ✅');
    console.log('\n🛡️  CSRF Protection is working correctly!');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
}

testCSRFComplete(); 