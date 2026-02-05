/**
 * Enhanced Gemini AI Service - Handles all AI-related operations
 * Updated with multi-channel support and comprehensive scam detection
 */

import { GoogleGenerativeAI } from '@google/generative-ai';
import {
    SCAM_DETECTION_PROMPT,
    HONEYPOT_AGENT_PROMPT,
    INTELLIGENCE_EXTRACTION_PROMPT,
    CONTINUATION_CHECK_PROMPT,
    CHANNEL_DETECTION_PROMPT
} from '../config/prompts.js';
import {
    SCAM_EXAMPLES,
    LEGITIMATE_EXAMPLES,
    SCAM_INDICATORS,
    LEGITIMATE_PATTERNS,
    CHANNEL_PATTERNS
} from '../data/trainingData.js';

class GeminiService {
    constructor() {
        this.genAI = null;
        this.model = null;
        this.trainingContext = null;
    }

    /**
     * Initialize the Gemini AI service
     */
    initialize(apiKey) {
        if (!apiKey) {
            throw new Error('GEMINI_API_KEY is required');
        }
        this.genAI = new GoogleGenerativeAI(apiKey);
        this.model = this.genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
        this.buildTrainingContext();
        console.log('✅ Gemini AI Service initialized with enhanced training data');
        console.log('   📊 Loaded scam categories:', Object.keys(SCAM_EXAMPLES).length);
        console.log('   ✅ Loaded legitimate categories:', Object.keys(LEGITIMATE_EXAMPLES).length);
    }

    /**
     * Build training context from the training data
     */
    buildTrainingContext() {
        // Build examples for each scam category
        const scamExamples = Object.entries(SCAM_EXAMPLES)
            .map(([category, examples]) => {
                const exampleList = examples.slice(0, 3).map(e =>
                    `  - "${e.message}" [${e.scamType}] [${e.channel}]`
                ).join('\n');
                return `### ${category.toUpperCase()}:\n${exampleList}`;
            }).join('\n\n');

        // Build examples for legitimate messages
        const legitExamples = Object.entries(LEGITIMATE_EXAMPLES)
            .map(([category, examples]) => {
                const exampleList = examples.slice(0, 2).map(e =>
                    `  - "${e.message}" [${e.channel}] [Sender: ${e.sender || 'N/A'}]`
                ).join('\n');
                return `### ${category.toUpperCase()}:\n${exampleList}`;
            }).join('\n\n');

        this.trainingContext = {
            scamExamples,
            legitExamples,
            indicators: SCAM_INDICATORS,
            legitPatterns: LEGITIMATE_PATTERNS,
            channelPatterns: CHANNEL_PATTERNS
        };
    }

    /**
     * Parse JSON response from Gemini, handling markdown code blocks
     */
    parseJsonResponse(text) {
        try {
            // Remove markdown code blocks if present
            let cleanText = text.trim();
            if (cleanText.startsWith('```json')) {
                cleanText = cleanText.slice(7);
            } else if (cleanText.startsWith('```')) {
                cleanText = cleanText.slice(3);
            }
            if (cleanText.endsWith('```')) {
                cleanText = cleanText.slice(0, -3);
            }
            return JSON.parse(cleanText.trim());
        } catch (error) {
            console.error('Failed to parse JSON response:', text);
            throw new Error('Invalid JSON response from AI');
        }
    }

    /**
     * Format conversation history for the AI model
     */
    formatConversationHistory(conversationHistory) {
        if (!conversationHistory || conversationHistory.length === 0) {
            return 'No previous conversation.';
        }

        return conversationHistory.map(msg => {
            const sender = msg.sender === 'scammer' ? 'Scammer' : 'You (Honeypot)';
            const timestamp = msg.timestamp ? ` [${new Date(msg.timestamp).toLocaleTimeString()}]` : '';
            return `${sender}${timestamp}: ${msg.text}`;
        }).join('\n');
    }

    /**
     * Detect the channel/source of a message
     */
    async detectChannel(message) {
        const prompt = `${CHANNEL_DETECTION_PROMPT}

MESSAGE TO ANALYZE:
"${message.text}"

SENDER INFO (if available): ${message.sender || 'Unknown'}
METADATA: ${JSON.stringify(message.metadata || {})}

Analyze and determine the likely channel.`;

        try {
            const result = await this.model.generateContent(prompt);
            const response = result.response.text();
            return this.parseJsonResponse(response);
        } catch (error) {
            console.error('Channel detection error:', error);
            return {
                detectedChannel: 'unknown',
                channelConfidence: 0.5,
                channelIndicators: [],
                authenticityScore: 0.5,
                senderType: 'unknown'
            };
        }
    }

    /**
     * Enhanced scam detection with training data context
     */
    async detectScam(message, conversationHistory = [], options = {}) {
        const formattedHistory = this.formatConversationHistory(conversationHistory);

        // Include relevant training examples based on message content
        const relevantExamples = this.getRelevantExamples(message.text);

        const prompt = `${SCAM_DETECTION_PROMPT}

## TRAINING EXAMPLES FOR CONTEXT:

### KNOWN SCAM PATTERNS:
${relevantExamples.scams}

### LEGITIMATE MESSAGE PATTERNS:
${relevantExamples.legitimate}

### KEY SCAM INDICATORS:
- Urgency phrases: ${SCAM_INDICATORS.urgency_phrases.slice(0, 10).join(', ')}
- Threat phrases: ${SCAM_INDICATORS.threat_phrases.slice(0, 10).join(', ')}
- Suspicious domains: ${SCAM_INDICATORS.suspicious_domains.slice(0, 10).join(', ')}

### LEGITIMATE SENDER IDs:
${LEGITIMATE_PATTERNS.official_sender_ids.join(', ')}

---

CONVERSATION HISTORY:
${formattedHistory}

CURRENT MESSAGE TO ANALYZE:
Sender: ${message.sender || 'Unknown'}
Channel: ${options.channel || 'Unknown'}
Text: ${message.text}

Analyze this message considering both the training examples and your knowledge. Provide your assessment in the specified JSON format.`;

        try {
            const result = await this.model.generateContent(prompt);
            const response = result.response.text();
            const analysis = this.parseJsonResponse(response);

            // Enrich with additional metadata
            analysis.analysisTimestamp = new Date().toISOString();
            analysis.modelVersion = 'gemini-1.5-flash-enhanced';

            return analysis;
        } catch (error) {
            console.error('Scam detection error:', error);
            // Default to suspicious if detection fails
            return {
                isScam: false,
                confidence: 0.5,
                scamType: 'unknown',
                indicators: ['detection_error'],
                reasoning: 'Unable to complete analysis',
                riskScore: 5
            };
        }
    }

    /**
     * Get relevant training examples based on message content
     */
    getRelevantExamples(messageText) {
        const lowerMessage = messageText.toLowerCase();
        let relevantScams = [];
        let relevantLegit = [];

        // Check for KYC-related keywords
        if (lowerMessage.includes('kyc') || lowerMessage.includes('update') || lowerMessage.includes('expire')) {
            relevantScams.push(...(SCAM_EXAMPLES.kyc_scams || []).slice(0, 2));
        }

        // Check for UPI/banking keywords
        if (lowerMessage.includes('upi') || lowerMessage.includes('bank') || lowerMessage.includes('account') ||
            lowerMessage.includes('credit') || lowerMessage.includes('debit')) {
            relevantScams.push(...(SCAM_EXAMPLES.upi_banking_fraud || []).slice(0, 2));
            relevantLegit.push(...(LEGITIMATE_EXAMPLES.bank_transactions || []).slice(0, 2));
        }

        // Check for lottery/prize keywords
        if (lowerMessage.includes('won') || lowerMessage.includes('prize') || lowerMessage.includes('lottery') ||
            lowerMessage.includes('congratulations')) {
            relevantScams.push(...(SCAM_EXAMPLES.lottery_scams || []).slice(0, 2));
        }

        // Check for job-related keywords
        if (lowerMessage.includes('job') || lowerMessage.includes('salary') || lowerMessage.includes('earn') ||
            lowerMessage.includes('work from home') || lowerMessage.includes('hiring')) {
            relevantScams.push(...(SCAM_EXAMPLES.job_scams || []).slice(0, 2));
        }

        // Check for authority/arrest keywords
        if (lowerMessage.includes('police') || lowerMessage.includes('cbi') || lowerMessage.includes('arrest') ||
            lowerMessage.includes('legal') || lowerMessage.includes('court')) {
            relevantScams.push(...(SCAM_EXAMPLES.impersonation_scams || []).slice(0, 2));
        }

        // Check for investment keywords
        if (lowerMessage.includes('invest') || lowerMessage.includes('return') || lowerMessage.includes('profit') ||
            lowerMessage.includes('crypto') || lowerMessage.includes('bitcoin')) {
            relevantScams.push(...(SCAM_EXAMPLES.investment_scams || []).slice(0, 2));
        }

        // Check for OTP keywords
        if (lowerMessage.includes('otp') || lowerMessage.includes('code') || lowerMessage.includes('verify')) {
            relevantScams.push(...(SCAM_EXAMPLES.otp_scams || []).slice(0, 2));
            relevantLegit.push(...(LEGITIMATE_EXAMPLES.otp_messages || []).slice(0, 2));
        }

        // Check for delivery keywords
        if (lowerMessage.includes('delivery') || lowerMessage.includes('package') || lowerMessage.includes('parcel') ||
            lowerMessage.includes('customs')) {
            relevantScams.push(...(SCAM_EXAMPLES.delivery_scams || []).slice(0, 2));
            relevantLegit.push(...(LEGITIMATE_EXAMPLES.service_notifications || []).slice(0, 2));
        }

        // If no specific keywords matched, provide general examples
        if (relevantScams.length === 0) {
            relevantScams = [
                ...(SCAM_EXAMPLES.kyc_scams || []).slice(0, 1),
                ...(SCAM_EXAMPLES.upi_banking_fraud || []).slice(0, 1),
                ...(SCAM_EXAMPLES.lottery_scams || []).slice(0, 1)
            ];
        }

        if (relevantLegit.length === 0) {
            relevantLegit = [
                ...(LEGITIMATE_EXAMPLES.bank_transactions || []).slice(0, 2),
                ...(LEGITIMATE_EXAMPLES.otp_messages || []).slice(0, 1)
            ];
        }

        return {
            scams: relevantScams.map(e => `- "${e.message}" [Type: ${e.scamType}]`).join('\n'),
            legitimate: relevantLegit.map(e => `- "${e.message}" [Sender: ${e.sender || 'Known'}]`).join('\n')
        };
    }

    /**
     * Generate a honeypot response to engage the scammer
     * Enhanced with varied responses and conversation flow
     */
    async generateHoneypotResponse(message, conversationHistory = [], metadata = {}) {
        const formattedHistory = this.formatConversationHistory(conversationHistory);
        const scamType = metadata.scamType || 'unknown';
        const messageCount = conversationHistory.length;

        // Extract previous honeypot responses to avoid repetition
        const previousResponses = conversationHistory
            .filter(msg => msg.sender === 'honeypot' || msg.sender === 'victim')
            .map(msg => msg.text)
            .slice(-5); // Last 5 responses

        const responsesToAvoid = previousResponses.length > 0
            ? `\n## ⚠️ DO NOT USE THESE PHRASES (already used):\n${previousResponses.map((r, i) => `${i + 1}. "${r}"`).join('\n')}\n`
            : '';

        // Determine conversation stage for varied responses
        const conversationStage = this.getConversationStage(messageCount);

        // Select persona based on scam type
        const personaGuidance = this.getPersonaGuidance(scamType);

        // Get stage-specific instructions
        const stageInstructions = this.getStageInstructions(conversationStage, scamType);

        const contextInfo = metadata.channel
            ? `Communication channel: ${metadata.channel}, Language: ${metadata.language || 'English'}, Locale: ${metadata.locale || 'IN'}`
            : 'Communication channel: SMS, Language: English, Locale: IN';

        // Generate unique seed based on message count to encourage variety
        const varietySeed = `Response #${messageCount + 1} - Be creative and different!`;

        const prompt = `${HONEYPOT_AGENT_PROMPT}

## 🚨 CRITICAL: AVOID REPETITION
${responsesToAvoid}
Your response MUST be completely different from the above. Use different words, different sentence structure, different questions.

## ${varietySeed}

## CURRENT SCAM CONTEXT:
Scam Type Detected: ${scamType}
${personaGuidance}

## CONVERSATION STAGE: ${conversationStage.toUpperCase()} (Message ${messageCount + 1})
${stageInstructions}

## WHAT TO DO NOW (Message ${messageCount + 1}):
${this.getSpecificAction(messageCount, scamType)}

CONTEXT: ${contextInfo}

FULL CONVERSATION SO FAR:
${formattedHistory || 'This is the first message.'}

SCAMMER'S LATEST MESSAGE: "${message.text}"

## GENERATE YOUR RESPONSE:
- Must be UNIQUE (not similar to previous responses)
- Use Hindi-English naturally
- Show genuine emotion for this stage
- Try to extract: UPI ID, phone number, bank details, links
- 2-4 sentences max
- No quotes or labels

YOUR REPLY:`;

        try {
            const result = await this.model.generateContent(prompt);
            let response = result.response.text().trim();

            // Clean up any accidental formatting
            if (response.startsWith('"') && response.endsWith('"')) {
                response = response.slice(1, -1);
            }
            if (response.startsWith("'") && response.endsWith("'")) {
                response = response.slice(1, -1);
            }
            // Remove any prefixes
            response = response.replace(/^(honeypot|victim|response|reply|your reply):\s*/i, '');
            response = response.replace(/^["']|["']$/g, '');

            // Check if response is too similar to previous ones
            const isDuplicate = previousResponses.some(prev =>
                this.calculateSimilarity(prev.toLowerCase(), response.toLowerCase()) > 0.7
            );

            if (isDuplicate) {
                console.log('⚠️ Duplicate response detected, generating alternative...');
                return this.getVariedFallbackResponse(scamType, messageCount, previousResponses);
            }

            return response;
        } catch (error) {
            console.error('Honeypot response generation error:', error);
            return this.getVariedFallbackResponse(scamType, messageCount, previousResponses);
        }
    }

    /**
     * Calculate similarity between two strings (simple word overlap)
     */
    calculateSimilarity(str1, str2) {
        const words1 = new Set(str1.split(/\s+/));
        const words2 = new Set(str2.split(/\s+/));
        const intersection = [...words1].filter(w => words2.has(w));
        const union = new Set([...words1, ...words2]);
        return intersection.length / union.size;
    }

    /**
     * Get specific action for the current message count
     */
    getSpecificAction(messageCount, scamType) {
        const actions = [
            "Ask who they are and which organization they represent",
            "Express confusion and ask them to explain in simple terms",
            "Show worry about your money and ask for their name",
            "Mention you'll ask your son/daughter and request their phone number",
            "Ask for their UPI ID saying you'll send money that way",
            "Request them to send a link so you can verify",
            "Ask for their employee ID and department name",
            "Say the previous link didn't work, ask for another one",
            "Mention network issues and ask for their callback number",
            "Ask for branch address saying you'll visit in person",
            "Request their manager's contact for verification",
            "Say your family member is asking who's calling",
            "Pretend OTP didn't come and ask them to resend",
            "Ask for alternate UPI ID as the first one isn't working",
            "Request official email confirmation of the issue"
        ];

        const index = Math.min(messageCount, actions.length - 1);
        return actions[index];
    }

    /**
     * Determine conversation stage based on message count
     */
    getConversationStage(messageCount) {
        if (messageCount <= 1) return 'initial_contact';
        if (messageCount <= 3) return 'building_confusion';
        if (messageCount <= 6) return 'showing_concern';
        if (messageCount <= 10) return 'trying_to_comply';
        if (messageCount <= 15) return 'getting_suspicious';
        return 'deep_engagement';
    }

    /**
     * Get stage-specific instructions
     */
    getStageInstructions(stage, scamType) {
        const instructions = {
            'initial_contact': `
                - Act completely confused and caught off guard
                - Ask who they are and what they want
                - Show you don't understand technical terms
                - Use phrases like "Who is this?", "What account?", "I don't understand"`,

            'building_confusion': `
                - Start showing worry about your money/account
                - Ask for clarification on specific details
                - Mention family members ("Let me ask my son", "My daughter handles this")
                - Start asking for their details ("Which bank are you from?", "What is your name?")`,

            'showing_concern': `
                - Express genuine worry and fear
                - Ask what will happen to your money
                - Request specific instructions step by step
                - Ask for official documentation or proof
                - Try to extract their phone number, name, or UPI ID`,

            'trying_to_comply': `
                - Pretend to look for information they requested
                - Give FAKE partial information ("My account starts with 5...")
                - Ask multiple clarifying questions about WHY they need info
                - Request them to call you on a different number (extract phone)
                - Ask "Can you send me link/message to verify?"`,

            'getting_suspicious': `
                - Start asking verifying questions
                - Mention you want to call the bank first
                - Ask for their manager's name or branch details
                - Say your family member is suspicious
                - Still engage but more cautiously`,

            'deep_engagement': `
                - Continue extracting information
                - Pretend to have technical difficulties
                - Ask them to repeat important details
                - Mention you'll send money "after verification"
                - Request alternative payment methods to get more IDs`
        };
        return instructions[stage] || instructions['initial_contact'];
    }

    /**
     * Get variation rules based on message count
     */
    getVariationRules(messageCount) {
        const rules = [
            "Message 1-2: Short confused responses, 1-2 sentences",
            "Message 3-4: Longer worried responses, ask clarifying questions",
            "Message 5-6: Show you're trying to help but confused, mention family",
            "Message 7-8: Ask for their specific details (phone, UPI, name)",
            "Message 9-10: Pretend you're looking for your info, ask for links",
            "Message 11+: Stall with technical issues, ask them to repeat things"
        ];
        return rules.slice(0, Math.min(messageCount + 2, rules.length)).join('\n');
    }

    /**
     * Get persona guidance based on scam type
     */
    getPersonaGuidance(scamType) {
        const guidanceMap = {
            'kyc_fraud': 'Use Persona A (Elderly). Show confusion about technology. Ask for step-by-step guidance.',
            'banking_fraud': 'Use Persona A (Elderly). Express worry about money. Ask for official verification.',
            'upi_fraud': 'Use Persona A (Elderly). Pretend unfamiliarity with UPI. Ask for UPI ID details.',
            'lottery_scam': 'Use Persona A (Elderly). Show excitement but request verification. Ask about payment details.',
            'job_scam': 'Use Persona C (Job Seeker). Show eagerness but ask about company details and contract.',
            'investment_scam': 'Use Persona B (Cautious). Show interest but request proof of returns and company details.',
            'crypto_scam': 'Use Persona A (Elderly). Pretend not to understand crypto. Ask for simple explanation.',
            'pig_butchering': 'Use any persona. Build rapport slowly. Show interest but caution.',
            'romance_scam': 'Match their energy. Be interested but ask verifying questions.',
            'digital_arrest': 'Use Persona A (Elderly). Show fear. Ask for officer details and case number.',
            'authority_impersonation': 'Use Persona A. Show respect for authority. Request official documentation.',
            'otp_theft': 'Use Persona A. Show confusion. Stall and ask why they need the OTP.',
            'delivery_scam': 'Use Persona A. Ask about package details and tracking number.',
            'loan_scam': 'Use Persona B. Show interest but ask about RBI registration and terms.',
            'tech_support_scam': 'Use Persona A. Pretend to follow instructions slowly. Ask for callbacks.'
        };

        return guidanceMap[scamType] || 'Use Persona A (Confused Elderly). General engagement tactics.';
    }

    /**
     * Get varied fallback response based on scam type and message count
     * Now filters out previously used responses
     */
    getVariedFallbackResponse(scamType, messageCount, previousResponses = []) {
        // Extensive fallback responses organized by conversation stage
        const stageResponses = {
            early: [
                "Arey beta, who is speaking? I am not understanding properly.",
                "Kya bol rahe ho? My phone is not clear, please repeat.",
                "What? Which account? I have many accounts...",
                "Please wait, my glasses are not here. What you said?",
                "Hello? Yes yes, I am listening. What is the matter?",
                "Accha accha, but first tell me your name please.",
                "Ek minute... aap kahan se bol rahe ho?",
                "Ji haan... main sun raha hoon... kya baat hai?",
                "Account? Kaunsa account? SBI ya PNB?",
                "Aap bank se ho? Kaunsi branch?"
            ],
            middle: [
                "Oh my god, my money! Please help me beta. What should I do?",
                "Wait wait, let me call my son first. He handles all this.",
                "Arey, I am very worried now. Which bank you are from? Tell me name.",
                "Please send me in writing. I cannot remember all this.",
                "Beta, what is your phone number? I want to call you back on landline.",
                "My UPI is not working. Can you give your UPI? I will send from my son's phone.",
                "Bahut tension ho gayi mujhe... kya karun bataiye?",
                "Aapka naam kya hai? Mujhe apne bête ko batana hai kaun call kar raha hai.",
                "Employee ID batao apna, main note kar loon...",
                "Ek kaam karo, mujhe email kar do saari details.",
                "Aap video call pe face dikha sakte ho verification ke liye?",
                "Mera beta police mein hai, usko poochna padega pehle..."
            ],
            late: [
                "Still not working beta. Network problem maybe. Give me your number, I will call.",
                "I typed OTP but it showing error. Let me try again... what was it?",
                "My daughter is asking who is calling. What should I tell her?",
                "Send me link again, previous one not opening. Very slow net.",
                "Wait, I am going to bank. Give me branch address, I will meet you there.",
                "You are from which department? Give me your employee ID I will note down.",
                "Aapke paas alternate number hai? Ye wala cut ho raha hai...",
                "Main bank jaake personally milna chahta hoon, address do branch ka.",
                "Mera damad CBI mein hai, usse baat karwa doon kya?",
                "Telegram pe message karo, WhatsApp pe nahi aa raha.",
                "Dusra UPI ID do, ye wala reject ho gaya.",
                "Manager se baat karwa do please, important matter hai.",
                "Letter bhejo ghar pe, main sign karke bhej dunga.",
                "Apni ID card ki photo bhejo WhatsApp pe verification ke liye."
            ]
        };

        // Select based on message count
        let responses;
        if (messageCount <= 2) {
            responses = stageResponses.early;
        } else if (messageCount <= 6) {
            responses = stageResponses.middle;
        } else {
            responses = stageResponses.late;
        }

        // Filter out responses that are similar to previous ones
        const availableResponses = responses.filter(r =>
            !previousResponses.some(prev =>
                this.calculateSimilarity(prev.toLowerCase(), r.toLowerCase()) > 0.5
            )
        );

        // If all responses used, use full list but pick different one
        const finalResponses = availableResponses.length > 0 ? availableResponses : responses;

        // Pick random response from available ones
        const randomIndex = Math.floor(Math.random() * finalResponses.length);
        return finalResponses[randomIndex];
    }

    /**
     * Enhanced intelligence extraction from the conversation
     */
    async extractIntelligence(conversationHistory, metadata = {}) {
        const formattedHistory = this.formatConversationHistory(conversationHistory);

        const prompt = `${INTELLIGENCE_EXTRACTION_PROMPT}

ADDITIONAL CONTEXT:
Detected Scam Type: ${metadata.scamType || 'Unknown'}
Channel: ${metadata.channel || 'Unknown'}
Session Duration: ${metadata.sessionDuration || 'Unknown'}
Message Count: ${conversationHistory.length}

COMPLETE CONVERSATION:
${formattedHistory}

Extract all scam-related intelligence from this conversation with high precision. Flag confidence levels for each piece of information. Provide the result in the specified JSON format.`;

        try {
            const result = await this.model.generateContent(prompt);
            const response = result.response.text();
            const intelligence = this.parseJsonResponse(response);

            // Add metadata
            intelligence.extractionTimestamp = new Date().toISOString();
            intelligence.conversationLength = conversationHistory.length;
            intelligence.sessionMetadata = metadata;

            return intelligence;
        } catch (error) {
            console.error('Intelligence extraction error:', error);
            return {
                scamClassification: {
                    primaryType: 'unknown',
                    confidence: 0.0
                },
                financialIntel: {
                    bankAccounts: [],
                    upiIds: [],
                    cryptoAddresses: [],
                    paymentApps: [],
                    amountsDemanded: []
                },
                contactIntel: {
                    phoneNumbers: [],
                    emailAddresses: [],
                    socialMedia: []
                },
                digitalAssets: {
                    phishingLinks: [],
                    maliciousApps: [],
                    fakeWebsites: []
                },
                organizationalIntel: {
                    fakeCompanies: [],
                    fakeDepartments: [],
                    fakeReferences: [],
                    scammerIdentities: []
                },
                behavioralIntel: {
                    tacticsUsed: [],
                    scriptPatterns: [],
                    sophisticationLevel: 'unknown'
                },
                riskAssessment: {
                    threatLevel: 'unknown'
                },
                actionableRecommendations: [],
                summary: 'Unable to extract intelligence due to an error'
            };
        }
    }

    /**
     * Enhanced continuation check with detailed analysis
     */
    async shouldContinueEngagement(conversationHistory, messageCount, metadata = {}) {
        const formattedHistory = this.formatConversationHistory(conversationHistory);

        const prompt = `${CONTINUATION_CHECK_PROMPT}

SESSION METADATA:
Scam Type: ${metadata.scamType || 'Unknown'}
Channel: ${metadata.channel || 'Unknown'}
Session Start: ${metadata.sessionStart || 'Unknown'}
Intelligence Extracted So Far: ${JSON.stringify(metadata.intelligenceSummary || {})}

CONVERSATION (${messageCount} messages exchanged):
${formattedHistory}

Based on the conversation, analyze and determine if the honeypot agent should continue engagement.`;

        try {
            const result = await this.model.generateContent(prompt);
            const response = result.response.text();
            return this.parseJsonResponse(response);
        } catch (error) {
            console.error('Continuation check error:', error);
            // Default behavior based on message count
            return {
                shouldContinue: messageCount < 15,
                confidenceInDecision: 0.5,
                engagementPhase: messageCount < 5 ? 'building_trust' : 'active_extraction',
                scammerSuspicionLevel: 'unknown',
                intelligenceYield: 'unknown',
                reason: 'Default behavior due to analysis error',
                suggestedAction: messageCount < 15 ? 'continue_normal' : 'extract_and_report',
                riskLevel: 'medium'
            };
        }
    }

    /**
     * Batch analyze multiple messages for scam patterns
     */
    async batchAnalyze(messages) {
        const results = [];
        for (const msg of messages) {
            try {
                const analysis = await this.detectScam(msg);
                results.push({
                    message: msg,
                    analysis,
                    timestamp: new Date().toISOString()
                });
            } catch (error) {
                results.push({
                    message: msg,
                    error: error.message,
                    timestamp: new Date().toISOString()
                });
            }
        }
        return results;
    }

    /**
     * Calculate scam risk score based on multiple factors
     */
    calculateRiskScore(analysis) {
        let score = 0;

        // Base score from confidence
        score += (analysis.confidence || 0) * 40;

        // Urgency level contribution
        const urgencyScores = { 'low': 5, 'medium': 15, 'high': 25, 'critical': 35 };
        score += urgencyScores[analysis.urgencyLevel] || 10;

        // Indicator count
        score += Math.min((analysis.indicators?.length || 0) * 3, 15);

        // Scam type severity
        const severeTypes = ['digital_arrest', 'authority_impersonation', 'banking_fraud', 'upi_fraud'];
        if (severeTypes.includes(analysis.scamType)) {
            score += 10;
        }

        return Math.min(Math.round(score / 10), 10);
    }
}

// Export singleton instance
export const geminiService = new GeminiService();
