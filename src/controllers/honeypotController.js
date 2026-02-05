/**
 * Honeypot Controller - Main business logic for scam detection and engagement
 */

import { geminiService } from '../services/geminiService.js';
import { sessionManager } from '../services/sessionManager.js';
import { reportingService } from '../services/reportingService.js';

/**
 * Main message handler endpoint
 */
export async function handleMessage(req, res) {
    const startTime = Date.now();
    const { sessionId, message, conversationHistory = [], metadata = {} } = req.body;

    try {
        console.log(`\n📨 Incoming message for session: ${sessionId}`);
        console.log(`   From: ${message.sender}`);
        console.log(`   Text: "${message.text.substring(0, 100)}${message.text.length > 100 ? '...' : ''}"`);

        // Get or create session
        const session = sessionManager.getOrCreateSession(sessionId);

        // Sync conversation history if provided
        if (conversationHistory.length > 0 && session.conversationHistory.length === 0) {
            conversationHistory.forEach(msg => {
                session.conversationHistory.push({
                    sender: msg.sender,
                    text: msg.text,
                    timestamp: msg.timestamp || Date.now()
                });
            });
            session.messageCount = conversationHistory.length;
        }

        // Add the current message
        sessionManager.addMessage(sessionId, message);

        // Store metadata
        session.metadata = { ...session.metadata, ...metadata };

        // Step 1: Detect scam intent
        console.log('🔍 Analyzing for scam intent...');
        const detection = await geminiService.detectScam(
            message,
            session.conversationHistory.slice(0, -1) // Exclude the message we just added
        );

        console.log(`   Detection result: isScam=${detection.isScam}, confidence=${detection.confidence?.toFixed(2)}`);

        // Update session with detection results
        sessionManager.updateScamStatus(sessionId, detection);

        // Step 2: Generate honeypot response
        console.log('🎭 Generating honeypot response...');
        const honeypotResponse = await geminiService.generateHoneypotResponse(
            message,
            session.conversationHistory.slice(0, -1),
            metadata
        );

        // Add honeypot response to history
        sessionManager.addHoneypotResponse(sessionId, honeypotResponse);

        console.log(`   Response: "${honeypotResponse.substring(0, 100)}${honeypotResponse.length > 100 ? '...' : ''}"`);

        // Step 3: Check if we should extract intelligence and report
        if (session.scamDetected && session.messageCount >= 4) {
            console.log('📊 Checking engagement continuation...');
            const continuation = await geminiService.shouldContinueEngagement(
                session.conversationHistory,
                session.messageCount
            );

            if (continuation.suggestedAction === 'extract_and_report' ||
                session.messageCount >= 15 ||
                !continuation.shouldContinue) {
                // Extract intelligence
                console.log('🔎 Extracting intelligence...');
                const intelligence = await geminiService.extractIntelligence(session.conversationHistory);
                sessionManager.storeIntelligence(sessionId, intelligence);

                // Report to GUVI
                if (!session.reported) {
                    console.log('📤 Reporting to GUVI...');
                    const reportResult = await reportingService.sendFinalResult(session);
                    if (reportResult.success) {
                        sessionManager.markAsReported(sessionId);
                    }
                }
            }
        }

        // Calculate response time
        const responseTime = Date.now() - startTime;
        console.log(`⏱️  Response time: ${responseTime}ms`);

        // Return response
        return res.json({
            status: 'success',
            reply: honeypotResponse
        });

    } catch (error) {
        console.error('❌ Error processing message:', error);
        return res.status(500).json({
            status: 'error',
            reply: "I am having some technical difficulties. Can you please repeat that?",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
}

/**
 * Get session status and statistics
 */
export async function getSessionStatus(req, res) {
    const { sessionId } = req.params;

    const session = sessionManager.getSession(sessionId);
    if (!session) {
        return res.status(404).json({
            status: 'error',
            message: 'Session not found'
        });
    }

    const stats = sessionManager.getSessionStats(sessionId);

    return res.json({
        status: 'success',
        data: {
            ...stats,
            hasIntelligence: !!session.extractedIntelligence,
            intelligenceSummary: session.extractedIntelligence?.summary
        }
    });
}

/**
 * Force extract intelligence and report for a session
 */
export async function forceExtractAndReport(req, res) {
    const { sessionId } = req.params;

    const session = sessionManager.getSession(sessionId);
    if (!session) {
        return res.status(404).json({
            status: 'error',
            message: 'Session not found'
        });
    }

    try {
        // Extract intelligence
        console.log(`🔎 Force extracting intelligence for session: ${sessionId}`);
        const intelligence = await geminiService.extractIntelligence(session.conversationHistory);
        sessionManager.storeIntelligence(sessionId, intelligence);

        // Report to GUVI
        console.log('📤 Reporting to GUVI...');
        const reportResult = await reportingService.sendFinalResult(session);

        if (reportResult.success) {
            sessionManager.markAsReported(sessionId);
        }

        return res.json({
            status: 'success',
            data: {
                intelligence,
                reported: reportResult.success,
                reportResponse: reportResult.response
            }
        });
    } catch (error) {
        console.error('Error in force extract:', error);
        return res.status(500).json({
            status: 'error',
            message: error.message
        });
    }
}

/**
 * Get conversation history for a session
 */
export async function getConversationHistory(req, res) {
    const { sessionId } = req.params;

    const history = sessionManager.getConversationHistory(sessionId);

    return res.json({
        status: 'success',
        data: {
            sessionId,
            messageCount: history.length,
            history
        }
    });
}

/**
 * Health check endpoint
 */
export async function healthCheck(req, res) {
    return res.json({
        status: 'success',
        message: 'Honeypot API is running',
        timestamp: new Date().toISOString(),
        activeSessions: sessionManager.getActiveSessionCount()
    });
}
