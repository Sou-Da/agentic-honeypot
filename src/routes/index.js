/**
 * API Routes
 */

import { Router } from 'express';
import { authMiddleware, validateRequest } from '../middleware/auth.js';
import {
    handleMessage,
    getSessionStatus,
    forceExtractAndReport,
    getConversationHistory,
    healthCheck
} from '../controllers/honeypotController.js';

const router = Router();

// Public routes
router.get('/health', healthCheck);
router.get('/', (req, res) => {
    res.json({
        name: 'Agentic Honeypot API',
        version: '1.0.0',
        description: 'AI-powered scam detection and intelligence extraction system',
        endpoints: {
            'POST /api/honeypot': 'Main message handling endpoint',
            'GET /api/session/:sessionId': 'Get session status',
            'GET /api/session/:sessionId/history': 'Get conversation history',
            'POST /api/session/:sessionId/report': 'Force extract and report',
            'GET /health': 'Health check'
        }
    });
});

// Protected routes
router.post('/api/honeypot', authMiddleware, validateRequest, handleMessage);
router.get('/api/session/:sessionId', authMiddleware, getSessionStatus);
router.get('/api/session/:sessionId/history', authMiddleware, getConversationHistory);
router.post('/api/session/:sessionId/report', authMiddleware, forceExtractAndReport);

export default router;
