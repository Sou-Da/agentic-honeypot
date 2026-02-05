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
     */
    async generateHoneypotResponse(message, conversationHistory = [], metadata = {}) {
        const formattedHistory = this.formatConversationHistory(conversationHistory);
        const scamType = metadata.scamType || 'unknown';

        // Select persona based on scam type
        const personaGuidance = this.getPersonaGuidance(scamType);

        const contextInfo = metadata.channel
            ? `Communication channel: ${metadata.channel}, Language: ${metadata.language || 'English'}, Locale: ${metadata.locale || 'IN'}`
            : 'Communication channel: SMS, Language: English, Locale: IN';

        const prompt = `${HONEYPOT_AGENT_PROMPT}

## CURRENT SCAM CONTEXT:
Scam Type Detected: ${scamType}
${personaGuidance}

CONTEXT: ${contextInfo}

CONVERSATION HISTORY:
${formattedHistory}

SCAMMER'S LATEST MESSAGE: "${message.text}"

MESSAGE COUNT SO FAR: ${conversationHistory.length}

Based on the scam type and conversation stage, generate a natural, in-character response that:
1. Engages the scammer further
2. Attempts to extract specific intelligence (bank accounts, UPI IDs, links, names)
3. Shows appropriate emotional response (confusion, worry, excitement)
4. Does NOT reveal that you know it's a scam
5. Uses natural Hindi-English mixing if appropriate

Remember: Respond ONLY with the message text, nothing else.`;

        try {
            const result = await this.model.generateContent(prompt);
            const response = result.response.text().trim();

            // Clean up any accidental formatting
            let cleanResponse = response;
            if (cleanResponse.startsWith('"') && cleanResponse.endsWith('"')) {
                cleanResponse = cleanResponse.slice(1, -1);
            }

            return cleanResponse;
        } catch (error) {
            console.error('Honeypot response generation error:', error);
            // Fallback responses based on scam type
            return this.getFallbackResponse(scamType);
        }
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
     * Get fallback response based on scam type
     */
    getFallbackResponse(scamType) {
        const fallbackMap = {
            'kyc_fraud': "Arey beta, I am not understanding this KYC thing. Can you explain slowly?",
            'banking_fraud': "Oh my! My account? Please tell me what to do, I am very worried about my money.",
            'upi_fraud': "UPI? My son set it up, I don't know how it works. Can you guide me?",
            'lottery_scam': "I won lottery? Really? But I never bought any ticket... how is this possible?",
            'job_scam': "This job sounds very good! But what company is this? Can you send me offer letter?",
            'investment_scam': "Guaranteed returns? My friend lost money in shares. How is this safe?",
            'digital_arrest': "Please don't arrest me sir! I am honest person. What case is this?",
            'authority_impersonation': "Sir/Madam, I am very scared. What should I do? Please help me.",
            'otp_theft': "OTP? Let me check my phone... wait, why do you need the OTP?",
            'default': "Please wait, I am not understanding. Can you explain again, beta?"
        };

        return fallbackMap[scamType] || fallbackMap['default'];
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
