/**
 * Authentication Middleware - API Key validation
 */

export function authMiddleware(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    const expectedApiKey = process.env.HONEYPOT_API_KEY;

    // Skip auth in development if no key is set
    if (!expectedApiKey && process.env.NODE_ENV === 'development') {
        console.warn('⚠️  No HONEYPOT_API_KEY set, skipping authentication');
        return next();
    }

    if (!apiKey) {
        return res.status(401).json({
            status: 'error',
            message: 'Missing API key. Include x-api-key header.'
        });
    }

    if (apiKey !== expectedApiKey) {
        return res.status(403).json({
            status: 'error',
            message: 'Invalid API key'
        });
    }

    next();
}

/**
 * Validate request body structure
 */
export function validateRequest(req, res, next) {
    const { sessionId, message } = req.body;

    if (!sessionId) {
        return res.status(400).json({
            status: 'error',
            message: 'sessionId is required'
        });
    }

    if (!message || !message.text) {
        return res.status(400).json({
            status: 'error',
            message: 'message.text is required'
        });
    }

    // Set defaults
    if (!message.sender) {
        message.sender = 'scammer';
    }
    if (!message.timestamp) {
        message.timestamp = Date.now();
    }

    next();
}
