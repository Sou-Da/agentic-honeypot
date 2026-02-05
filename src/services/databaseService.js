/**
 * 🛡️ SQLite Database Service for Long-Term Memory
 * ================================================
 * Stores scammer data, chat logs, and intelligence permanently.
 * Data persists across server restarts.
 */

import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class DatabaseService {
    constructor() {
        this.db = null;
        this.dbPath = path.join(__dirname, '../../data/honeypot.db');
    }

    /**
     * Initialize the database and create tables
     */
    initialize() {
        try {
            // Ensure data directory exists
            const dataDir = path.dirname(this.dbPath);
            if (!fs.existsSync(dataDir)) {
                fs.mkdirSync(dataDir, { recursive: true });
            }

            this.db = new Database(this.dbPath);
            this.db.pragma('journal_mode = WAL'); // Better performance

            this.createTables();
            console.log('✅ Database initialized:', this.dbPath);

            // Log current stats
            const stats = this.getStats();
            console.log(`   📊 Total Sessions: ${stats.totalSessions}`);
            console.log(`   🔴 Scams Detected: ${stats.scamsDetected}`);
            console.log(`   💬 Messages Logged: ${stats.totalMessages}`);

            return true;
        } catch (error) {
            console.error('❌ Database initialization failed:', error);
            console.log('   ℹ️ Run: npm install better-sqlite3');
            return false;
        }
    }

    /**
     * Create database tables if they don't exist
     */
    createTables() {
        // Sessions table - stores each scammer interaction session
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                channel TEXT,
                scam_detected BOOLEAN DEFAULT 0,
                scam_type TEXT,
                confidence REAL,
                status TEXT DEFAULT 'active',
                message_count INTEGER DEFAULT 0,
                intelligence_extracted BOOLEAN DEFAULT 0,
                reported BOOLEAN DEFAULT 0,
                report_timestamp DATETIME,
                metadata TEXT
            )
        `);

        // Messages table - stores all conversation messages
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_scam_message BOOLEAN DEFAULT 0,
                scam_analysis TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        `);

        // Intelligence table - stores extracted scammer intelligence
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                extracted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                bank_accounts TEXT,
                upi_ids TEXT,
                phone_numbers TEXT,
                email_addresses TEXT,
                phishing_links TEXT,
                crypto_addresses TEXT,
                scammer_names TEXT,
                organization_names TEXT,
                tactics_used TEXT,
                threat_level TEXT,
                risk_score INTEGER,
                summary TEXT,
                raw_data TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        `);

        // Scammers table - unique scammer identifiers
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS scammers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT UNIQUE NOT NULL,
                identifier_type TEXT NOT NULL,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                session_count INTEGER DEFAULT 1,
                total_messages INTEGER DEFAULT 0,
                scam_types TEXT,
                confidence_avg REAL,
                notes TEXT
            )
        `);

        // Daily stats table - for dashboard charts
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS daily_stats (
                date DATE PRIMARY KEY,
                total_sessions INTEGER DEFAULT 0,
                scams_detected INTEGER DEFAULT 0,
                legitimate_messages INTEGER DEFAULT 0,
                messages_exchanged INTEGER DEFAULT 0,
                intelligence_extracted INTEGER DEFAULT 0,
                unique_scammers INTEGER DEFAULT 0,
                top_scam_type TEXT,
                avg_confidence REAL
            )
        `);

        // Create indexes for faster queries
        this.db.exec(`
            CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at);
            CREATE INDEX IF NOT EXISTS idx_sessions_scam ON sessions(scam_detected);
            CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
            CREATE INDEX IF NOT EXISTS idx_intelligence_session ON intelligence(session_id);
            CREATE INDEX IF NOT EXISTS idx_scammers_identifier ON scammers(identifier);
        `);
    }

    // =========================================================================
    // SESSION METHODS
    // =========================================================================

    /**
     * Create or get a session
     */
    createSession(sessionId, metadata = {}) {
        const stmt = this.db.prepare(`
            INSERT OR IGNORE INTO sessions (id, channel, metadata)
            VALUES (?, ?, ?)
        `);
        stmt.run(sessionId, metadata.channel || 'unknown', JSON.stringify(metadata));
        return this.getSession(sessionId);
    }

    /**
     * Get session by ID
     */
    getSession(sessionId) {
        const stmt = this.db.prepare('SELECT * FROM sessions WHERE id = ?');
        const session = stmt.get(sessionId);
        if (session && session.metadata) {
            try {
                session.metadata = JSON.parse(session.metadata);
            } catch (e) {
                session.metadata = {};
            }
        }
        return session;
    }

    /**
     * Update session with scam detection results
     */
    updateSessionScamAnalysis(sessionId, analysis) {
        const stmt = this.db.prepare(`
            UPDATE sessions 
            SET scam_detected = ?, scam_type = ?, confidence = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        `);
        stmt.run(
            analysis.isScam ? 1 : 0,
            analysis.scamType || null,
            analysis.confidence || null,
            sessionId
        );
    }

    /**
     * Update session status
     */
    updateSessionStatus(sessionId, status) {
        const stmt = this.db.prepare(`
            UPDATE sessions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
        `);
        stmt.run(status, sessionId);
    }

    /**
     * Increment message count for session
     */
    incrementMessageCount(sessionId) {
        const stmt = this.db.prepare(`
            UPDATE sessions 
            SET message_count = message_count + 1, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        `);
        stmt.run(sessionId);
    }

    /**
     * Mark session as reported
     */
    markSessionReported(sessionId) {
        const stmt = this.db.prepare(`
            UPDATE sessions 
            SET reported = 1, report_timestamp = CURRENT_TIMESTAMP, status = 'completed'
            WHERE id = ?
        `);
        stmt.run(sessionId);
    }

    /**
     * Get all sessions
     */
    getAllSessions(limit = 100) {
        const stmt = this.db.prepare(`
            SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?
        `);
        return stmt.all(limit);
    }

    // =========================================================================
    // MESSAGE METHODS
    // =========================================================================

    /**
     * Log a message
     */
    logMessage(sessionId, sender, text, scamAnalysis = null) {
        const stmt = this.db.prepare(`
            INSERT INTO messages (session_id, sender, text, is_scam_message, scam_analysis)
            VALUES (?, ?, ?, ?, ?)
        `);
        stmt.run(
            sessionId,
            sender,
            text,
            scamAnalysis?.isScam ? 1 : 0,
            scamAnalysis ? JSON.stringify(scamAnalysis) : null
        );
        this.incrementMessageCount(sessionId);
    }

    /**
     * Get messages for a session
     */
    getSessionMessages(sessionId, limit = 100) {
        const stmt = this.db.prepare(`
            SELECT * FROM messages WHERE session_id = ? ORDER BY timestamp ASC LIMIT ?
        `);
        return stmt.all(sessionId, limit);
    }

    /**
     * Get recent messages across all sessions
     */
    getRecentMessages(limit = 50) {
        const stmt = this.db.prepare(`
            SELECT m.*, s.scam_type, s.channel
            FROM messages m
            JOIN sessions s ON m.session_id = s.id
            ORDER BY m.timestamp DESC
            LIMIT ?
        `);
        return stmt.all(limit);
    }

    // =========================================================================
    // INTELLIGENCE METHODS
    // =========================================================================

    /**
     * Store extracted intelligence
     */
    storeIntelligence(sessionId, intelligence) {
        const stmt = this.db.prepare(`
            INSERT INTO intelligence (
                session_id, bank_accounts, upi_ids, phone_numbers, email_addresses,
                phishing_links, crypto_addresses, scammer_names, organization_names,
                tactics_used, threat_level, risk_score, summary, raw_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        stmt.run(
            sessionId,
            JSON.stringify(intelligence.financialIntel?.bankAccounts || []),
            JSON.stringify(intelligence.financialIntel?.upiIds || []),
            JSON.stringify(intelligence.contactIntel?.phoneNumbers || []),
            JSON.stringify(intelligence.contactIntel?.emailAddresses || []),
            JSON.stringify(intelligence.digitalAssets?.phishingLinks || []),
            JSON.stringify(intelligence.financialIntel?.cryptoAddresses || []),
            JSON.stringify(intelligence.organizationalIntel?.scammerIdentities || []),
            JSON.stringify(intelligence.organizationalIntel?.fakeCompanies || []),
            JSON.stringify(intelligence.behavioralIntel?.tacticsUsed || []),
            intelligence.riskAssessment?.threatLevel || 'unknown',
            intelligence.riskAssessment?.riskScore || 0,
            intelligence.summary || '',
            JSON.stringify(intelligence)
        );

        // Mark session as having intelligence extracted
        const updateStmt = this.db.prepare(`
            UPDATE sessions SET intelligence_extracted = 1 WHERE id = ?
        `);
        updateStmt.run(sessionId);

        // Track unique scammer identifiers
        this.trackScammerIdentifiers(sessionId, intelligence);
    }

    /**
     * Track unique scammer identifiers
     */
    trackScammerIdentifiers(sessionId, intelligence) {
        const identifiers = [];

        // Collect all identifiers
        if (intelligence.contactIntel?.phoneNumbers) {
            (Array.isArray(intelligence.contactIntel.phoneNumbers)
                ? intelligence.contactIntel.phoneNumbers
                : []).forEach(phone => {
                    const phoneNum = typeof phone === 'object' ? phone.number : phone;
                    if (phoneNum) identifiers.push({ value: phoneNum, type: 'phone' });
                });
        }
        if (intelligence.financialIntel?.upiIds) {
            (Array.isArray(intelligence.financialIntel.upiIds)
                ? intelligence.financialIntel.upiIds
                : []).forEach(upi => {
                    const upiId = typeof upi === 'object' ? upi.id : upi;
                    if (upiId) identifiers.push({ value: upiId, type: 'upi' });
                });
        }
        if (intelligence.contactIntel?.emailAddresses) {
            (Array.isArray(intelligence.contactIntel.emailAddresses)
                ? intelligence.contactIntel.emailAddresses
                : []).forEach(email => {
                    const addr = typeof email === 'object' ? email.email : email;
                    if (addr) identifiers.push({ value: addr, type: 'email' });
                });
        }

        // Upsert each identifier
        const upsertStmt = this.db.prepare(`
            INSERT INTO scammers (identifier, identifier_type, last_seen, session_count, total_messages)
            VALUES (?, ?, CURRENT_TIMESTAMP, 1, 1)
            ON CONFLICT(identifier) DO UPDATE SET
                last_seen = CURRENT_TIMESTAMP,
                session_count = session_count + 1
        `);

        identifiers.forEach(id => {
            if (id.value && id.value.trim()) {
                try {
                    upsertStmt.run(id.value.trim(), id.type);
                } catch (e) {
                    // Ignore duplicate errors
                }
            }
        });
    }

    /**
     * Get intelligence for a session
     */
    getSessionIntelligence(sessionId) {
        const stmt = this.db.prepare('SELECT * FROM intelligence WHERE session_id = ?');
        return stmt.get(sessionId);
    }

    /**
     * Get all intelligence records
     */
    getAllIntelligence(limit = 100) {
        const stmt = this.db.prepare(`
            SELECT i.*, s.scam_type, s.channel, s.created_at as session_created
            FROM intelligence i
            JOIN sessions s ON i.session_id = s.id
            ORDER BY i.extracted_at DESC
            LIMIT ?
        `);
        return stmt.all(limit);
    }

    // =========================================================================
    // STATISTICS METHODS
    // =========================================================================

    /**
     * Get overall statistics
     */
    getStats() {
        if (!this.db) {
            return {
                totalSessions: 0,
                scamsDetected: 0,
                totalMessages: 0,
                intelligenceCount: 0,
                uniqueScammers: 0,
                reportedSessions: 0,
                scamTypeBreakdown: [],
                last24Hours: { sessions: 0, scams: 0 },
                avgConfidence: 0,
                detectionRate: 0
            };
        }

        const totalSessions = this.db.prepare('SELECT COUNT(*) as count FROM sessions').get().count;
        const scamsDetected = this.db.prepare('SELECT COUNT(*) as count FROM sessions WHERE scam_detected = 1').get().count;
        const totalMessages = this.db.prepare('SELECT COUNT(*) as count FROM messages').get().count;
        const intelligenceCount = this.db.prepare('SELECT COUNT(*) as count FROM intelligence').get().count;
        const uniqueScammers = this.db.prepare('SELECT COUNT(*) as count FROM scammers').get().count;
        const reportedSessions = this.db.prepare('SELECT COUNT(*) as count FROM sessions WHERE reported = 1').get().count;

        // Scam type breakdown
        const scamTypes = this.db.prepare(`
            SELECT scam_type, COUNT(*) as count 
            FROM sessions 
            WHERE scam_type IS NOT NULL 
            GROUP BY scam_type 
            ORDER BY count DESC
        `).all();

        // Last 24 hours stats
        const last24h = this.db.prepare(`
            SELECT 
                COUNT(*) as sessions,
                SUM(CASE WHEN scam_detected = 1 THEN 1 ELSE 0 END) as scams
            FROM sessions 
            WHERE created_at > datetime('now', '-24 hours')
        `).get();

        // Average confidence
        const avgConfidence = this.db.prepare(`
            SELECT AVG(confidence) as avg FROM sessions WHERE confidence IS NOT NULL
        `).get().avg;

        return {
            totalSessions,
            scamsDetected,
            totalMessages,
            intelligenceCount,
            uniqueScammers,
            reportedSessions,
            scamTypeBreakdown: scamTypes,
            last24Hours: last24h || { sessions: 0, scams: 0 },
            avgConfidence: avgConfidence ? (avgConfidence * 100).toFixed(1) : 0,
            detectionRate: totalSessions > 0 ? ((scamsDetected / totalSessions) * 100).toFixed(1) : 0
        };
    }

    /**
     * Get daily statistics for charts
     */
    getDailyStats(days = 30) {
        const stmt = this.db.prepare(`
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as sessions,
                SUM(CASE WHEN scam_detected = 1 THEN 1 ELSE 0 END) as scams,
                SUM(message_count) as messages
            FROM sessions
            WHERE created_at > datetime('now', '-' || ? || ' days')
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        `);
        return stmt.all(days);
    }

    /**
     * Get hourly distribution
     */
    getHourlyDistribution() {
        const stmt = this.db.prepare(`
            SELECT 
                strftime('%H', created_at) as hour,
                COUNT(*) as count
            FROM sessions
            GROUP BY strftime('%H', created_at)
            ORDER BY hour
        `);
        return stmt.all();
    }

    /**
     * Get top scammers
     */
    getTopScammers(limit = 10) {
        const stmt = this.db.prepare(`
            SELECT * FROM scammers 
            ORDER BY session_count DESC, last_seen DESC 
            LIMIT ?
        `);
        return stmt.all(limit);
    }

    /**
     * Get unique phishing links
     */
    getPhishingLinks() {
        const results = this.db.prepare(`
            SELECT phishing_links FROM intelligence WHERE phishing_links != '[]'
        `).all();

        const allLinks = new Set();
        results.forEach(r => {
            try {
                const links = JSON.parse(r.phishing_links);
                links.forEach(l => {
                    const url = typeof l === 'object' ? l.url : l;
                    if (url) allLinks.add(url);
                });
            } catch (e) { }
        });

        return Array.from(allLinks);
    }

    /**
     * Get unique UPI IDs
     */
    getScammerUPIs() {
        const results = this.db.prepare(`
            SELECT upi_ids FROM intelligence WHERE upi_ids != '[]'
        `).all();

        const allUPIs = new Set();
        results.forEach(r => {
            try {
                const upis = JSON.parse(r.upi_ids);
                upis.forEach(u => {
                    const id = typeof u === 'object' ? u.id : u;
                    if (id) allUPIs.add(id);
                });
            } catch (e) { }
        });

        return Array.from(allUPIs);
    }

    /**
     * Export data for reporting
     */
    exportData() {
        const sessions = this.db.prepare('SELECT * FROM sessions ORDER BY created_at DESC').all();
        const intelligence = this.db.prepare('SELECT * FROM intelligence ORDER BY extracted_at DESC').all();
        const scammers = this.db.prepare('SELECT * FROM scammers ORDER BY session_count DESC').all();
        const stats = this.getStats();

        return {
            exportedAt: new Date().toISOString(),
            stats,
            sessions,
            intelligence,
            scammers
        };
    }

    /**
     * Close database connection
     */
    close() {
        if (this.db) {
            this.db.close();
            console.log('Database connection closed');
        }
    }
}

// Export singleton instance
export const databaseService = new DatabaseService();
export default databaseService;
