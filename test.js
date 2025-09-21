const axios = require('axios');

const API_URL = process.env.API_URL || 'http://localhost:3000';
const AUTH_TOKEN = process.env.AUTH_TOKEN || 'sk-default';

async function testHealth() {
    console.log('\n=== Testing Health Endpoint ===');
    try {
        const response = await axios.get(`${API_URL}/health`);
        console.log('✅ Health check passed:', response.data);
    } catch (error) {
        console.error('❌ Health check failed:', error.message);
    }
}

async function testModels() {
    console.log('\n=== Testing Models Endpoint ===');
    try {
        const response = await axios.get(`${API_URL}/v1/models`, {
            headers: {
                'Authorization': `Bearer ${AUTH_TOKEN}`
            }
        });
        console.log(`✅ Found ${response.data.data.length} models`);
        console.log('Models:', response.data.data.map(m => m.id).join(', '));
    } catch (error) {
        console.error('❌ Models test failed:', error.message);
    }
}

async function testChat() {
    console.log('\n=== Testing Chat Completion ===');
    try {
        const response = await axios.post(`${API_URL}/v1/chat/completions`, {
            model: 'gpt-4.1',
            messages: [
                { role: 'user', content: 'Say hello in one word' }
            ],
            stream: false
        }, {
            headers: {
                'Authorization': `Bearer ${AUTH_TOKEN}`,
                'Content-Type': 'application/json'
            }
        });
        console.log('✅ Chat response:', response.data.choices[0].message.content);
    } catch (error) {
        console.error('❌ Chat test failed:', error.message);
    }
}

async function testStreamChat() {
    console.log('\n=== Testing Stream Chat ===');
    try {
        const response = await axios.post(`${API_URL}/v1/chat/completions`, {
            model: 'gpt-4.1',
            messages: [
                { role: 'user', content: 'Count from 1 to 5' }
            ],
            stream: true
        }, {
            headers: {
                'Authorization': `Bearer ${AUTH_TOKEN}`,
                'Content-Type': 'application/json'
            },
            responseType: 'stream'
        });

        console.log('✅ Stream started...');
        
        response.data.on('data', (chunk) => {
            const lines = chunk.toString().split('\n');
            for (const line of lines) {
                if (line.startsWith('data: ')) {
                    const data = line.substring(6);
                    if (data !== '[DONE]') {
                        try {
                            const json = JSON.parse(data);
                            if (json.choices[0].delta.content) {
                                process.stdout.write(json.choices[0].delta.content);
                            }
                        } catch (e) {}
                    }
                }
            }
        });

        response.data.on('end', () => {
            console.log('\n✅ Stream completed');
        });
    } catch (error) {
        console.error('❌ Stream test failed:', error.message);
    }
}

async function runTests() {
    console.log('Starting API tests...');
    console.log(`API URL: ${API_URL}`);
    console.log(`Auth Token: ${AUTH_TOKEN}`);
    
    await testHealth();
    await testModels();
    await testChat();
    await testStreamChat();
    
    console.log('\n=== Tests Completed ===');
}

runTests().catch(console.error);
