/**
 * Reporting Service - Handles sending final results to GUVI evaluation endpoint
 */

const GUVI_CALLBACK_URL = 'https://hackathon.guvi.in/api/updateHoneyPotFinalResult';

class ReportingService {
    constructor() {
        this.reportQueue = [];
        this.retryAttempts = 3;
        this.retryDelay = 2000; // 2 seconds
    }

    /**
     * Sleep utility for retry delays
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Send the final result to GUVI evaluation endpoint
     */
    async sendFinalResult(sessionData) {
        const payload = this.formatPayload(sessionData);

        console.log(`📤 Sending final result for session: ${sessionData.sessionId}`);
        console.log('Payload:', JSON.stringify(payload, null, 2));

        for (let attempt = 1; attempt <= this.retryAttempts; attempt++) {
            try {
                const response = await fetch(GUVI_CALLBACK_URL, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(payload)
                });

                if (response.ok) {
                    const result = await response.json().catch(() => ({}));
                    console.log(`✅ Successfully reported session ${sessionData.sessionId} to GUVI`);
                    return {
                        success: true,
                        response: result
                    };
                } else {
                    const errorText = await response.text().catch(() => 'Unknown error');
                    console.error(`❌ Failed to report (attempt ${attempt}): ${response.status} - ${errorText}`);
                }
            } catch (error) {
                console.error(`❌ Network error (attempt ${attempt}):`, error.message);
            }

            if (attempt < this.retryAttempts) {
                console.log(`⏳ Retrying in ${this.retryDelay / 1000} seconds...`);
                await this.sleep(this.retryDelay);
            }
        }

        console.error(`❌ Failed to report session ${sessionData.sessionId} after ${this.retryAttempts} attempts`);
        return {
            success: false,
            error: 'Max retry attempts exceeded'
        };
    }

    /**
     * Format the payload according to GUVI's requirements
     */
    formatPayload(sessionData) {
        const intelligence = sessionData.extractedIntelligence || {};

        return {
            sessionId: sessionData.sessionId,
            scamDetected: sessionData.scamDetected || false,
            totalMessagesExchanged: sessionData.messageCount || 0,
            extractedIntelligence: {
                bankAccounts: intelligence.bankAccounts || [],
                upiIds: intelligence.upiIds || [],
                phishingLinks: intelligence.phishingLinks || [],
                phoneNumbers: intelligence.phoneNumbers || [],
                suspiciousKeywords: intelligence.suspiciousKeywords || []
            },
            agentNotes: this.generateAgentNotes(sessionData, intelligence)
        };
    }

    /**
     * Generate agent notes summarizing the scam engagement
     */
    generateAgentNotes(sessionData, intelligence) {
        const notes = [];

        if (sessionData.scamType) {
            notes.push(`Scam Type: ${sessionData.scamType}`);
        }

        if (sessionData.scamConfidence) {
            notes.push(`Detection Confidence: ${(sessionData.scamConfidence * 100).toFixed(1)}%`);
        }

        if (sessionData.indicators && sessionData.indicators.length > 0) {
            notes.push(`Indicators: ${sessionData.indicators.join(', ')}`);
        }

        if (intelligence.scammerTactics && intelligence.scammerTactics.length > 0) {
            notes.push(`Tactics Used: ${intelligence.scammerTactics.join(', ')}`);
        }

        if (intelligence.summary) {
            notes.push(`Summary: ${intelligence.summary}`);
        }

        const duration = sessionData.updatedAt - sessionData.createdAt;
        notes.push(`Engagement Duration: ${Math.round(duration / 1000)}s`);

        return notes.join(' | ');
    }

    /**
     * Check if session should be reported
     */
    shouldReport(session) {
        // Report if scam detected and not already reported
        if (!session.scamDetected) return false;
        if (session.reported) return false;

        // Report if we have intelligence or enough messages
        if (session.extractedIntelligence) return true;
        if (session.messageCount >= 5) return true;

        return false;
    }

    /**
     * Queue a session for reporting
     */
    queueForReporting(session) {
        if (!this.reportQueue.find(s => s.sessionId === session.sessionId)) {
            this.reportQueue.push(session);
            console.log(`📋 Session ${session.sessionId} queued for reporting`);
        }
    }

    /**
     * Process the report queue
     */
    async processQueue() {
        while (this.reportQueue.length > 0) {
            const session = this.reportQueue.shift();
            await this.sendFinalResult(session);
        }
    }
}

// Export singleton instance
export const reportingService = new ReportingService();
