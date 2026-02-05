/**
 * Test Client for Honeypot API
 * Simulates scam conversations to test the system
 */

const API_URL = 'http://localhost:3000/api/honeypot';
const API_KEY = 'your_secret_api_key_here'; // Replace with your actual API key

// Test scenarios
const testScenarios = [
    {
        name: 'Banking Fraud Scenario',
        messages: [
            "URGENT: Your SBI account will be blocked in 24 hours due to KYC verification failure. Call immediately on 9876543210",
            "Sir, I am calling from State Bank of India. Your account has been flagged for suspicious activity. We need to verify your details.",
            "Please share your account number and registered mobile number for verification.",
            "For security purposes, I will send you an OTP. Please share it with me to complete the verification.",
            "Sir, to unblock your account, please transfer Rs. 500 to this UPI ID: sbi.verify@ybl for verification charges."
        ]
    },
    {
        name: 'Lottery Scam Scenario',
        messages: [
            "Congratulations! You have won Rs. 25,00,000 in the Google Anniversary Lottery! Claim now!",
            "To claim your prize, please share your bank account details for direct transfer.",
            "Sir, there is a processing fee of Rs. 5000. Please pay to this account: HDFC Bank, A/C: 50100234567890, IFSC: HDFC0001234",
            "After payment, your prize money will be credited within 24 hours. This is 100% genuine."
        ]
    },
    {
        name: 'Tech Support Scam',
        messages: [
            "Microsoft Security Alert: Your computer has been compromised! Call our toll-free number 1800-XXX-XXXX immediately!",
            "Hello, I am Alex from Microsoft Technical Support. We detected malware on your computer accessing your banking information.",
            "To remove the virus, I need remote access to your computer. Please download AnyDesk and share the code.",
            "For removing the virus permanently, you need to pay Rs. 15,000 for our security software. Pay via UPI: microsoft.support@paytm"
        ]
    }
];

async function sendMessage(sessionId, text, conversationHistory = []) {
    const payload = {
        sessionId,
        message: {
            sender: 'scammer',
            text,
            timestamp: Date.now()
        },
        conversationHistory,
        metadata: {
            channel: 'SMS',
            language: 'English',
            locale: 'IN'
        }
    };

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': API_KEY
            },
            body: JSON.stringify(payload)
        });

        const result = await response.json();
        return result;
    } catch (error) {
        console.error('Request failed:', error.message);
        return null;
    }
}

async function runScenario(scenario) {
    console.log('\n' + '='.repeat(60));
    console.log(`🧪 Testing: ${scenario.name}`);
    console.log('='.repeat(60));

    const sessionId = `test-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    const conversationHistory = [];

    for (let i = 0; i < scenario.messages.length; i++) {
        const message = scenario.messages[i];
        console.log(`\n📤 Scammer [${i + 1}/${scenario.messages.length}]: "${message}"`);

        const result = await sendMessage(sessionId, message, conversationHistory);

        if (result) {
            console.log(`📥 Honeypot: "${result.reply}"`);

            // Update conversation history
            conversationHistory.push({
                sender: 'scammer',
                text: message,
                timestamp: Date.now()
            });
            conversationHistory.push({
                sender: 'user',
                text: result.reply,
                timestamp: Date.now()
            });
        } else {
            console.log('❌ Failed to get response');
            break;
        }

        // Wait a bit between messages
        await new Promise(resolve => setTimeout(resolve, 1500));
    }

    // Check session status
    console.log('\n📊 Getting session status...');
    try {
        const statusResponse = await fetch(`http://localhost:3000/api/session/${sessionId}`, {
            headers: { 'x-api-key': API_KEY }
        });
        const status = await statusResponse.json();
        console.log('Session Status:', JSON.stringify(status.data, null, 2));
    } catch (error) {
        console.log('Could not get session status:', error.message);
    }

    return sessionId;
}

async function runAllTests() {
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log('║         🧪 HONEYPOT API TEST CLIENT                      ║');
    console.log('╚══════════════════════════════════════════════════════════╝');

    // Check if server is running
    try {
        const healthResponse = await fetch('http://localhost:3000/health');
        const health = await healthResponse.json();
        console.log('\n✅ Server is running:', health.message);
    } catch (error) {
        console.error('\n❌ Server is not running. Please start the server first with: npm run dev');
        process.exit(1);
    }

    // Run each scenario
    for (const scenario of testScenarios) {
        await runScenario(scenario);
        console.log('\n⏳ Waiting before next scenario...');
        await new Promise(resolve => setTimeout(resolve, 2000));
    }

    console.log('\n' + '='.repeat(60));
    console.log('✅ All test scenarios completed!');
    console.log('='.repeat(60));
}

// Run tests
runAllTests().catch(console.error);
