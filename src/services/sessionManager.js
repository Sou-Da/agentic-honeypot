/**
 * Session Manager - Handles conversation sessions and state
 */

class SessionManager {
    constructor() {
        // In-memory session storage (use Redis/Database for production)
        this.sessions = new Map();

        // Session cleanup interval (clean up old sessions every hour)
        this.cleanupInterval = setInterval(() => this.cleanupOldSessions(), 60 * 60 * 1000);
    }

    /**
     * Create or get a session
     */
    getOrCreateSession(sessionId) {
        if (!this.sessions.has(sessionId)) {
            this.sessions.set(sessionId, {
                sessionId,
                createdAt: Date.now(),
                updatedAt: Date.now(),
                scamDetected: false,
                scamConfidence: 0,
                scamType: null,
                agentActivated: false,
                messageCount: 0,
                conversationHistory: [],
                extractedIntelligence: null,
                indicators: [],
                metadata: {},
                reported: false
            });
            console.log(`📝 New session created: ${sessionId}`);
        }
        return this.sessions.get(sessionId);
    }

    /**
     * Update session with new message
     */
    addMessage(sessionId, message) {
        const session = this.getOrCreateSession(sessionId);
        session.conversationHistory.push({
            sender: message.sender,
            text: message.text,
            timestamp: message.timestamp || Date.now()
        });
        session.messageCount++;
        session.updatedAt = Date.now();
        return session;
    }

    /**
     * Update scam detection status
     */
    updateScamStatus(sessionId, detection) {
        const session = this.getOrCreateSession(sessionId);

        // Update if more confident or if first detection
        if (detection.isScam && detection.confidence > session.scamConfidence) {
            session.scamDetected = true;
            session.scamConfidence = detection.confidence;
            session.scamType = detection.scamType;
            session.indicators = [...new Set([...session.indicators, ...detection.indicators])];

            if (!session.agentActivated) {
                session.agentActivated = true;
                console.log(`🎭 Agent activated for session: ${sessionId}`);
            }
        }

        session.updatedAt = Date.now();
        return session;
    }

    /**
     * Add honeypot response to history
     */
    addHoneypotResponse(sessionId, responseText) {
        const session = this.getOrCreateSession(sessionId);
        session.conversationHistory.push({
            sender: 'user',
            text: responseText,
            timestamp: Date.now()
        });
        session.messageCount++;
        session.updatedAt = Date.now();
        return session;
    }

    /**
     * Store extracted intelligence
     */
    storeIntelligence(sessionId, intelligence) {
        const session = this.getOrCreateSession(sessionId);
        session.extractedIntelligence = intelligence;
        session.updatedAt = Date.now();
        return session;
    }

    /**
     * Mark session as reported
     */
    markAsReported(sessionId) {
        const session = this.sessions.get(sessionId);
        if (session) {
            session.reported = true;
            session.reportedAt = Date.now();
        }
        return session;
    }

    /**
     * Get session by ID
     */
    getSession(sessionId) {
        return this.sessions.get(sessionId);
    }

    /**
     * Get full conversation history
     */
    getConversationHistory(sessionId) {
        const session = this.sessions.get(sessionId);
        return session ? session.conversationHistory : [];
    }

    /**
     * Get session statistics
     */
    getSessionStats(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return null;

        return {
            sessionId: session.sessionId,
            messageCount: session.messageCount,
            scamDetected: session.scamDetected,
            scamConfidence: session.scamConfidence,
            scamType: session.scamType,
            agentActivated: session.agentActivated,
            duration: Date.now() - session.createdAt,
            reported: session.reported
        };
    }

    /**
     * Clean up old sessions (older than 24 hours)
     */
    cleanupOldSessions() {
        const maxAge = 24 * 60 * 60 * 1000; // 24 hours
        const now = Date.now();
        let cleaned = 0;

        for (const [sessionId, session] of this.sessions) {
            if (now - session.updatedAt > maxAge) {
                this.sessions.delete(sessionId);
                cleaned++;
            }
        }

        if (cleaned > 0) {
            console.log(`🧹 Cleaned up ${cleaned} old sessions`);
        }
    }

    /**
     * Get all active sessions count
     */
    getActiveSessionCount() {
        return this.sessions.size;
    }
}

// Export singleton instance
export const sessionManager = new SessionManager();
