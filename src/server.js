/**
 * Agentic Honeypot API Server
 * AI-powered scam detection and intelligence extraction system
 */

import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import routes from './routes/index.js';
import { geminiService } from './services/geminiService.js';

// Load environment variables
dotenv.config();

// Create Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging middleware
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} ${req.path}`);
    next();
});

// Routes
app.use('/', routes);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        status: 'error',
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        status: 'error',
        message: 'Endpoint not found'
    });
});

// Initialize services and start server
async function startServer() {
    try {
        // Initialize Gemini service
        const geminiApiKey = process.env.GEMINI_API_KEY;
        if (!geminiApiKey) {
            console.error('❌ GEMINI_API_KEY is not set in environment variables');
            console.log('   Please create a .env file with your Gemini API key');
            console.log('   Example: GEMINI_API_KEY=your_api_key_here');
            process.exit(1);
        }

        geminiService.initialize(geminiApiKey);

        // Start server
        app.listen(PORT, () => {
            console.log('');
            console.log('╔══════════════════════════════════════════════════════════╗');
            console.log('║                                                          ║');
            console.log('║   🍯 AGENTIC HONEYPOT API SERVER                         ║');
            console.log('║   AI-Powered Scam Detection & Intelligence Extraction    ║');
            console.log('║                                                          ║');
            console.log('╠══════════════════════════════════════════════════════════╣');
            console.log(`║   🌐 Server running on: http://localhost:${PORT}            ║`);
            console.log(`║   📡 Environment: ${process.env.NODE_ENV || 'development'}                        ║`);
            console.log('║   🔐 API Key Protection: Enabled                         ║');
            console.log('║   🤖 Gemini AI: Connected                                ║');
            console.log('║                                                          ║');
            console.log('╠══════════════════════════════════════════════════════════╣');
            console.log('║   Endpoints:                                             ║');
            console.log('║   POST /api/honeypot     - Handle scam messages          ║');
            console.log('║   GET  /api/session/:id  - Get session status            ║');
            console.log('║   GET  /health           - Health check                  ║');
            console.log('║                                                          ║');
            console.log('╚══════════════════════════════════════════════════════════╝');
            console.log('');
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully...');
    process.exit(0);
});

// Start the server
startServer();
