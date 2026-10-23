import express from 'express';
import { createServer as createViteServer } from 'vite';
import { spawn, ChildProcess } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';

const PORT = 3000;
const PYTHON_PORT = Number(process.env.BAYORA_BACKEND_PORT || 8000);
const PYTHON_HOST = '127.0.0.1';

let pythonProc: ChildProcess | null = null;

function startPythonBackend(): Promise<void> {
  return new Promise((resolve) => {
    pythonProc = spawn('python3', ['-m', 'backend.app.main'], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        BAYORA_BACKEND_HOST: PYTHON_HOST,
        BAYORA_BACKEND_PORT: String(PYTHON_PORT),
        BAYORA_DB_PATH: process.env.BAYORA_DB_PATH || path.join(process.cwd(), 'bayora.db'),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    pythonProc.stdout?.on('data', (chunk) => {
      process.stdout.write(`[python-backend] ${chunk}`);
    });
    pythonProc.stderr?.on('data', (chunk) => {
      process.stderr.write(`[python-backend] ${chunk}`);
    });

    let attempts = 0;
    const checkReady = () => {
      attempts++;
      const req = http.get(`http://${PYTHON_HOST}:${PYTHON_PORT}/api/health`, (res) => {
        if (res.statusCode === 200) {
          resolve();
        } else if (attempts < 30) {
          setTimeout(checkReady, 150);
        } else {
          resolve();
        }
      });
      req.on('error', () => {
        if (attempts < 30) {
          setTimeout(checkReady, 150);
        } else {
          resolve();
        }
      });
      req.end();
    };

    setTimeout(checkReady, 120);
  });
}

function proxyToPython(req: express.Request, res: express.Response): void {
  const bodyStr = req.body && Object.keys(req.body).length > 0 ? JSON.stringify(req.body) : '';
  const forwardHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (req.headers['x-bayora-role']) {
    forwardHeaders['X-Bayora-Role'] = String(req.headers['x-bayora-role']);
  }
  if (req.headers['x-bayora-actor']) {
    forwardHeaders['X-Bayora-Actor'] = String(req.headers['x-bayora-actor']);
  }
  if (bodyStr) {
    forwardHeaders['Content-Length'] = String(Buffer.byteLength(bodyStr));
  }

  const proxyReq = http.request(
    {
      hostname: PYTHON_HOST,
      port: PYTHON_PORT,
      path: req.originalUrl,
      method: req.method,
      headers: forwardHeaders,
    },
    (proxyRes) => {
      let rawData = '';
      proxyRes.setEncoding('utf8');
      proxyRes.on('data', (chunk) => {
        rawData += chunk;
      });
      proxyRes.on('end', () => {
        res.status(proxyRes.statusCode || 500);
        res.setHeader('Content-Type', 'application/json');
        res.send(rawData);
      });
    }
  );

  proxyReq.on('error', (err) => {
    res.status(502).json({
      error: 'CONTROL_PLANE_UNAVAILABLE',
      detail: `Failed to reach Python FastAPI/SQLite control plane: ${err.message}`,
    });
  });

  if (bodyStr) {
    proxyReq.write(bodyStr);
  }
  proxyReq.end();
}

async function startServer() {
  await startPythonBackend();

  const app = express();
  app.use(express.json({ limit: '1mb' }));

  // Proxy all /api/* calls directly to the Python Control Plane backend
  app.all('/api/*splat', (req, res) => {
    proxyToPython(req, res);
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*splat', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Bayora Full-Stack Server] Listening on http://0.0.0.0:${PORT} (proxying /api/* -> Python :${PYTHON_PORT})`);
  });
}

process.on('SIGTERM', () => {
  if (pythonProc) pythonProc.kill();
  process.exit(0);
});

startServer();
