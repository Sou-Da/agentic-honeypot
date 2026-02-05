# 🍯 Agentic Honeypot API - Enhanced Edition

AI-powered Scam Detection & Intelligence Extraction System built with **Node.js** and **Google Gemini AI**.

**Enhanced with comprehensive training data from official sources: RBI, NPCI, CERT-In, SBI, HDFC, ICICI, and other banking authorities.**

## 🎯 Enhanced Features

### 🔍 Advanced Scam Detection (20+ Categories)
- **KYC Fraud**: Fake KYC update requests with malicious links
- **UPI/Banking Fraud**: QR code scams, fake transaction alerts, UPI PIN theft
- **Digital Arrest**: CBI/Police impersonation with arrest threats
- **Lottery/Prize Scams**: Fake lottery wins requiring "processing fees"
- **Job Scams**: Fake WFH jobs requiring security deposits
- **Investment/Crypto Scams**: Guaranteed returns, trading group scams
- **Pig Butchering**: Long-term relationship building for financial fraud
- **Romance Scams**: Matrimonial/dating platform exploitation
- **Authority Impersonation**: Police, Income Tax, Customs threats
- **OTP Theft**: "Accidental OTP" social engineering
- **Delivery Scams**: Fake India Post/FedEx package notifications
- **Loan Scams**: Pre-approved loans with advance fees
- **Utility Scams**: Fake electricity/phone disconnection threats
- **Traffic Scams**: Fake e-challan payment links
- **Remote Access Scams**: AnyDesk/TeamViewer installation requests

### ✅ Legitimate Message Recognition
- Official bank transaction alerts (VM-SBIINB, TM-HDFCBK format)
- Genuine OTP messages with proper sender IDs
- Authentic delivery notifications (Amazon, Swiggy, etc.)
- Real government notifications (UIDAI, IRCTC, EPFO)
- Normal personal communications

### 🤖 Multi-Persona Honeypot Agent
- **Persona A**: Confused elderly person (default)
- **Persona B**: Cautious small business owner
- **Persona C**: Desperate job seeker
- Automatically selects persona based on scam type

### 📡 Multi-Channel Support
- SMS (with sender ID analysis)
- WhatsApp
- Email
- Phone calls (transcribed)
- Social media messages

## 🚀 Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment

Create a `.env` file in the root directory:

```env
GEMINI_API_KEY=your_gemini_api_key_here
HONEYPOT_API_KEY=your_secret_api_key_here
PORT=3000
NODE_ENV=development
```

**Get your Gemini API Key**: [Google AI Studio](https://aistudio.google.com/app/apikey)

### 3. Start the Server

```bash
# Development mode (with auto-reload)
npm run dev

# Production mode
npm start
```

## 📂 Enhanced Project Structure

```
├── src/
│   ├── config/
│   │   └── prompts.js              # Enhanced AI prompts with training data
│   ├── controllers/
│   │   └── honeypotController.js   # Main business logic
│   ├── data/
│   │   └── trainingData.js         # 80+ scam examples, 40+ legitimate examples
│   ├── middleware/
│   │   └── auth.js                 # API key authentication
│   ├── routes/
│   │   └── index.js                # API routes
│   ├── services/
│   │   ├── geminiService.js        # Enhanced Gemini AI with training context
│   │   ├── sessionManager.js       # Session state management
│   │   └── reportingService.js     # GUVI callback reporting
│   └── server.js                   # Express server entry point
├── test/
│   ├── testClient.js               # Basic test scenarios
│   └── comprehensiveTest.js        # Full test suite (25+ tests)
├── .env
├── package.json
└── README.md
```

## 📡 API Endpoints

### Main Endpoint

```
POST /api/honeypot
Headers:
  Content-Type: application/json
  x-api-key: YOUR_SECRET_API_KEY
```

#### Request Body

```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Dear customer, your KYC has expired. Update now: http://sbi-kyc.xyz",
    "timestamp": 1770005528731
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

#### Response

```json
{
  "status": "success",
  "reply": "Arey beta, I am not understanding this KYC thing. Can you explain slowly?",
  "scamAnalysis": {
    "isScam": true,
    "confidence": 0.95,
    "scamType": "kyc_fraud",
    "indicators": ["fake_link", "urgency", "account_threat"],
    "riskScore": 9
  }
}
```

### Other Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/session/:sessionId` | GET | Get session status |
| `/api/session/:sessionId/history` | GET | Get conversation history |
| `/api/session/:sessionId/report` | POST | Force extract & report |

## 🧪 Testing

### Basic Test
```bash
node test/testClient.js
```

### Comprehensive Test Suite
```bash
node test/comprehensiveTest.js
```

Tests include:
- 15 scam detection tests (KYC, UPI, digital arrest, lottery, job, crypto, etc.)
- 10 legitimate message tests (bank alerts, OTPs, delivery, personal)

## 🔧 How It Works

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Incoming       │────▶│  Scam Detection  │────▶│  Is Scam?       │
│  Message        │     │  (20+ patterns)  │     │                 │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                        ┌─────────── YES ─────────────────┘
                        │
                        ▼
          ┌─────────────────────────┐
          │  Select Persona         │
          │  (Based on scam type)   │
          └───────────┬─────────────┘
                      │
                      ▼
          ┌─────────────────────────┐
          │  Generate Response      │
          │  (Engage scammer)       │
          └───────────┬─────────────┘
                      │
                      ▼
          ┌─────────────────────────┐
          │  Extract Intelligence   │
          │  (Accounts, UPIs, etc)  │
          └───────────┬─────────────┘
                      │
                      ▼
          ┌─────────────────────────┐
          │  Report to Authorities  │
          │  (GUVI endpoint)        │
          └─────────────────────────┘
```

## 📊 Training Data Sources

### Scam Examples (80+)
| Category | Examples | Source |
|----------|----------|--------|
| KYC Fraud | 6 | RBI, SBI, HDFC |
| UPI/Banking | 7 | NPCI, Bank advisories |
| Digital Arrest | 6 | CERT-In, Police |
| Lottery/Prize | 5 | RBI fraud alerts |
| Job Scams | 5 | Cyber crime reports |
| Investment | 6 | SEBI warnings |
| Romance | 3 | Cyber crime database |
| Delivery | 3 | India Post advisories |
| OTP Theft | 3 | Bank security bulletins |
| Loan | 3 | RBI guidelines |
| Utility | 2 | State utility warnings |
| Government | 4 | PIB Fact Check |

### Legitimate Examples (40+)
| Category | Examples | Verification |
|----------|----------|--------------|
| Bank Transactions | 5 | Official SMS format |
| OTP Messages | 4 | TRAI sender ID format |
| Service Notifications | 4 | Official domains |
| Bank Notifications | 4 | Verified patterns |
| Government Notices | 4 | Official sender IDs |
| Promotional | 3 | Opt-out compliance |
| Salary/Business | 2 | NEFT/IMPS format |
| Personal | 4 | Natural language |

## 🔐 Security

- API key authentication required for all endpoints
- No real personal information is ever shared
- Scammer engagement uses fake persona details only
- All extracted intelligence is for reporting only

## 📤 Intelligence Extraction

The enhanced system extracts:

### Financial Intelligence
- Bank account numbers with IFSC codes
- UPI IDs (name@bank format)
- Crypto wallet addresses
- Payment app details
- Amounts demanded

### Contact Intelligence
- Phone numbers (all formats)
- Email addresses
- Telegram/WhatsApp handles

### Digital Assets
- Phishing links with purpose classification
- Malicious app names
- Fake websites

### Organizational Intelligence
- Fake company names
- Impersonated entities
- Reference/case numbers
- Scammer identities

### Behavioral Intelligence
- Tactics used
- Script patterns
- Sophistication level

## 🎭 Agent Personas

### Persona A - Confused Elderly (Default)
**Ramesh Kumar / Kamala Devi**, 65-70 years old
- Retired bank clerk / school teacher
- Very limited tech skills
- Uses Hindi-English mix: "beta", "arey", "achha"
- Shows confusion and worry

### Persona B - Cautious Business Owner
**Priya Sharma**, 35-40 years old
- Small business owner
- Basic smartphone user
- Interested but suspicious
- Best for: Investment scams, job scams

### Persona C - Desperate Job Seeker
**Rahul Verma**, 25-30 years old
- Recent graduate, unemployed
- Eager to believe opportunities
- Best for: Job scams, task-based scams

## 📈 Detection Capabilities

### Red Flags Detected
- Urgency phrases (24 hours, immediately, act now)
- Threat phrases (blocked, legal action, arrest)
- Too good to be true (lottery, guaranteed returns)
- Suspicious domains (.xyz, .info, bit.ly)
- Payment requests (processing fee, advance)
- OTP/PIN requests
- Remote access requests (AnyDesk, TeamViewer)

### Legitimate Patterns Recognized
- Official sender IDs (VM-SBIINB, TM-HDFCBK)
- TRAI format headers (XY-ABCDE)
- Secure domains (sbi.co.in, hdfcbank.com)
- Transaction reference formats
- Proper OTP warnings

## 🚀 Deployment

For production deployment:
1. Use a cloud platform (Railway, Render, Heroku, GCP)
2. Set environment variables securely
3. Use Redis for session management
4. Add rate limiting
5. Set up monitoring and alerting

## 📝 License

MIT License

## 🙏 Acknowledgments

- RBI (Reserve Bank of India) for fraud awareness content
- NPCI for UPI security guidelines
- CERT-In for cyber threat intelligence
- State Bank of India (SBI), HDFC Bank, ICICI Bank for fraud prevention materials
- PIB Fact Check for scam alerts
- Cyber Crime Portal (cybercrime.gov.in) for case studies
