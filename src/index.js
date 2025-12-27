import express from 'express';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { analyzeUrl } from './analyzer.js';
import { basicAuthMiddleware } from './auth.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Security headers
app.use(helmet());

// Logging
app.use(morgan('combined'));

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Rate limiting
const windowMinutes = Number(process.env.RATE_LIMIT_WINDOW_MINUTES || 15);
const maxRequests = Number(process.env.RATE_LIMIT_MAX_REQUESTS || 100);
const limiter = rateLimit({
  windowMs: windowMinutes * 60 * 1000,
  max: maxRequests,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Simple in-memory log store
const detectionLogs = [];

// Health
app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// Auth-protected API group
app.use(['/check-url', '/logs'], basicAuthMiddleware);

// POST /check-url { url }
app.post('/check-url', (req, res) => {
  const url = req.body?.url || req.query?.url;
  if (!url) {
    return res.status(400).json({ error: 'Missing url parameter' });
  }
  const result = analyzeUrl(url);

  const logEntry = {
    timestamp: new Date().toISOString(),
    url,
    ...result,
    ip: req.ip,
    userAgent: req.get('user-agent') || ''
  };
  detectionLogs.push(logEntry);
  if (detectionLogs.length > 1000) detectionLogs.shift();

  return res.json({
    ismalicious: result.isMalicious,
    riskLevel: result.riskLevel,
    reason: result.reason
  });
});

// GET /logs - recent logs (auth protected)
app.get('/logs', (_req, res) => {
  res.json({ count: detectionLogs.length, logs: detectionLogs.slice(-500).reverse() });
});

// Dashboard static
app.use('/', express.static(path.join(__dirname, '..', 'public')));

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`Server listening on port ${port}`);
});




