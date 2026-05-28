import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import * as z from 'zod/v4';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

type PageRow = {
  id: number;
  page_id: string;
  title: string;
  depth: number;
  url: string;
  file: string;
  version: number | null;
  created_at: string | null;
  bytes_html: number | null;
  content: string;
};

type SearchResult = {
  pageId: string;
  title: string;
  depth: number;
  url: string;
  file: string;
  version: number | null;
  createdAt: string | null;
  bytesHtml: number | null;
  score?: number;
  snippet?: string;
};

const PORT = Number(process.env.PORT ?? '3000');
const HOST = process.env.HOST ?? '0.0.0.0';
const DB_PATH = process.env.DB_PATH ?? path.join(process.cwd(), 'data', 'db', 'docs.sqlite');
const HEALTH_PATH = '/health';
const MCP_PATH = '/mcp';
const AUTH_MODE = process.env.AUTH_MODE ?? 'none';
const BASE_URL = process.env.BASE_URL ?? '';
const ALLOWED_DOMAIN = process.env.ALLOWED_DOMAIN ?? '';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID ?? '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET ?? '';
const OAUTH_REDIRECT_URI = `${BASE_URL}/auth/google/callback`;

interface SessionData {
  email: string;
  name: string;
  picture?: string;
  expiresAt: number;
}

const sessions = new Map<string, SessionData>();

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

function generateSessionId(): string {
  return crypto.randomUUID();
}

function parseCookies(req: http.IncomingMessage): Record<string, string> {
  const header = req.headers.cookie;
  if (!header) return {};
  return Object.fromEntries(
    header.split(';').map((c) => {
      const idx = c.indexOf('=');
      if (idx === -1) return [c.trim(), ''];
      return [c.slice(0, idx).trim(), c.slice(idx + 1).trim()];
    })
  );
}

function setSessionCookie(res: http.ServerResponse, sessionId: string): void {
  res.setHeader('set-cookie', `sid=${sessionId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL_MS / 1000}`);
}

function clearSessionCookie(res: http.ServerResponse): void {
  res.setHeader('set-cookie', 'sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
}

function getSession(req: http.IncomingMessage): SessionData | null {
  if (AUTH_MODE !== 'oauth') return null;
  const cookies = parseCookies(req);
  const sid = cookies['sid'];
  if (!sid) return null;
  const session = sessions.get(sid);
  if (!session || session.expiresAt < Date.now()) {
    if (session) sessions.delete(sid);
    return null;
  }
  return session;
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT');
  const raw = parts[1];
  try {
    return JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
  } catch {
    return JSON.parse(Buffer.from(raw, 'base64').toString('utf8'));
  }
}

function httpsPostJson(url: string, body: Record<string, string>): Promise<Record<string, unknown>> {
  const u = new URL(url);
  const data = new URLSearchParams(body).toString();
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: u.hostname,
        port: 443,
        path: u.pathname,
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          'content-length': Buffer.byteLength(data),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk: string) => (raw += chunk));
        res.on('end', () => {
          try {
            resolve(JSON.parse(raw));
          } catch {
            reject(new Error(`Token response not JSON: ${raw.slice(0, 200)}`));
          }
        });
      }
    );
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function sendHtml(res: http.ServerResponse, statusCode: number, html: string) {
  const payload = Buffer.from(html, 'utf8');
  res.writeHead(statusCode, {
    'content-type': 'text/html; charset=utf-8',
    'content-length': payload.length,
  });
  res.end(payload);
}

function requireAuth(
  req: http.IncomingMessage,
  res: http.ServerResponse
): SessionData | null {
  if (AUTH_MODE !== 'oauth') return { email: '', name: '', expiresAt: 0 };
  const session = getSession(req);
  if (!session) {
    sendJson(res, 401, {
      error: 'unauthorized',
      authUrl: `${BASE_URL}/auth/google/login`,
    });
    return null;
  }
  return session;
}

function sendJson(res: http.ServerResponse, statusCode: number, body: unknown) {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload)
  });
  res.end(payload);
}

function sendText(res: http.ServerResponse, statusCode: number, body: string) {
  res.writeHead(statusCode, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': Buffer.byteLength(body)
  });
  res.end(body);
}

function normalize(value: string) {
  return value.trim().toLowerCase();
}

function quoteFtsTerm(term: string) {
  return `"${term.replace(/"/g, '""')}"`;
}

function buildFtsQuery(query: string) {
  const parts = query
    .trim()
    .split(/\s+/)
    .map((part) => part.trim())
    .filter(Boolean)
    .map(quoteFtsTerm);
  return parts.join(' AND ');
}

if (!existsSync(DB_PATH)) {
  throw new Error(`Missing SQLite database at ${DB_PATH}. Run npm run build:db first.`);
}

const db = new DatabaseSync(DB_PATH, { readOnly: true });

const exactLookup = db.prepare(`
  SELECT id, page_id, title, depth, url, file, version, created_at, bytes_html, content
  FROM pages
  WHERE page_id = ? OR lower(file) = ? OR lower(url) = ? OR lower(title) = ?
  LIMIT 1
`);

const searchLookup = db.prepare(`
  SELECT
    p.id,
    p.page_id,
    p.title,
    p.depth,
    p.url,
    p.file,
    p.version,
    p.created_at,
    p.bytes_html,
    snippet(pages_fts, 4, '…', '…', '…', 18) AS snippet,
    bm25(pages_fts) AS score
  FROM pages_fts
  JOIN pages p ON p.id = pages_fts.rowid
  WHERE pages_fts MATCH ?
  ORDER BY score ASC, p.depth ASC, p.title ASC
  LIMIT ?
`);

function toSearchResult(row: PageRow, extra?: { snippet?: string; score?: number }): SearchResult {
  return {
    pageId: row.page_id,
    title: row.title,
    depth: row.depth,
    url: row.url,
    file: row.file,
    version: row.version,
    createdAt: row.created_at,
    bytesHtml: row.bytes_html,
    ...(extra ?? {})
  };
}

function findExactPage(lookup: {
  pageId?: string;
  file?: string;
  url?: string;
  title?: string;
}) {
  const candidates = [
    lookup.pageId?.trim(),
    lookup.file?.trim(),
    lookup.url?.trim(),
    lookup.title?.trim()
  ].filter((value): value is string => Boolean(value));

  for (const candidate of candidates) {
    const row = exactLookup.get(
      candidate,
      normalize(candidate),
      normalize(candidate),
      normalize(candidate)
    ) as PageRow | undefined;
    if (row) {
      return row;
    }
  }

  return undefined;
}

function searchPages(query: string, limit = 10) {
  const normalized = query.trim();
  if (!normalized) {
    return [];
  }

  const results: SearchResult[] = [];
  const exact = findExactPage({ pageId: query, file: query, url: query, title: query });
  if (exact) {
    results.push(toSearchResult(exact));
  }

  const rows = searchLookup.all(buildFtsQuery(query), Math.max(1, Math.min(50, limit))) as Array<
    PageRow & { snippet?: string; score?: number }
  >;

  for (const row of rows) {
    if (results.some((item) => item.pageId === row.page_id)) {
      continue;
    }
    results.push(
      toSearchResult(row, {
        snippet: row.snippet,
        score: row.score
      })
    );
  }

  return results;
}

function buildServer() {
  const server = new McpServer({
    name: 'feed-moborg-docs-mcp',
    version: '1.0.0'
  });

  server.registerTool(
    'search_docs',
    {
      title: 'Search docs',
      description: 'Search the scraped markdown pages in docs.sqlite',
      inputSchema: {
        query: z.string().min(1).describe('Search query'),
        limit: z.number().int().min(1).max(50).default(10)
      }
    },
    async ({ query, limit }) => {
      const results = searchPages(query, limit);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                query,
                count: results.length,
                results
              },
              null,
              2
            )
          }
        ]
      };
    }
  );

  server.registerTool(
    'get_page',
    {
      title: 'Get page',
      description: 'Fetch a single page by pageId, file, url, title, or exact query',
      inputSchema: {
        pageId: z.string().optional(),
        file: z.string().optional(),
        url: z.string().optional(),
        title: z.string().optional(),
        query: z.string().optional()
      }
    },
    async ({ pageId, file, url, title, query }) => {
      const row = findExactPage({
        pageId,
        file,
        url,
        title
      });

      if (row) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  pageId: row.page_id,
                  title: row.title,
                  depth: row.depth,
                  url: row.url,
                  file: row.file,
                  version: row.version,
                  createdAt: row.created_at,
                  bytesHtml: row.bytes_html,
                  content: row.content
                },
                null,
                2
              )
            }
          ]
        };
      }

      if (query?.trim()) {
        const fallback = searchPages(query, 1)[0];
        if (fallback) {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    pageId: fallback.pageId,
                    title: fallback.title,
                    depth: fallback.depth,
                    url: fallback.url,
                    file: fallback.file,
                    version: fallback.version,
                    createdAt: fallback.createdAt,
                    bytesHtml: fallback.bytesHtml,
                    content: db
                      .prepare(
                        `
                          SELECT content
                          FROM pages
                          WHERE page_id = ?
                          LIMIT 1
                        `
                      )
                      .get(fallback.pageId)?.content
                  },
                  null,
                  2
                )
              }
            ]
          };
        }
      }

      return {
        isError: true,
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                error: 'Page not found',
                lookup: { pageId, file, url, title, query }
              },
              null,
              2
            )
          }
        ]
      };
    }
  );

  return server;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`);

  if (url.pathname === HEALTH_PATH) {
    sendJson(res, 200, { ok: true });
    return;
  }

  if (url.pathname === '/auth/google/login') {
    if (AUTH_MODE !== 'oauth') {
      sendJson(res, 400, { error: 'Auth not configured' });
      return;
    }
    const state = generateSessionId();
    const authUrl =
      `https://accounts.google.com/o/oauth2/v2/auth?` +
      `client_id=${encodeURIComponent(GOOGLE_CLIENT_ID)}` +
      `&redirect_uri=${encodeURIComponent(OAUTH_REDIRECT_URI)}` +
      `&response_type=code` +
      `&scope=${encodeURIComponent('openid email profile')}` +
      `&state=${state}` +
      `&access_type=offline`;
    setSessionCookie(res, state);
    res.writeHead(302, { location: authUrl });
    res.end();
    return;
  }

  if (url.pathname === '/auth/google/callback') {
    if (AUTH_MODE !== 'oauth') {
      sendJson(res, 400, { error: 'Auth not configured' });
      return;
    }
    const code = url.searchParams.get('code');
    const returnedState = url.searchParams.get('state');
    if (!code) {
      sendJson(res, 400, { error: 'Missing authorization code', query: url.search });
      return;
    }
    const cookies = parseCookies(req);
    const storedState = cookies['sid'];
    if (returnedState && storedState && returnedState !== storedState) {
      sendJson(res, 403, { error: 'Invalid state parameter' });
      return;
    }
    try {
      const tokenData = await httpsPostJson('https://oauth2.googleapis.com/token', {
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: OAUTH_REDIRECT_URI,
        grant_type: 'authorization_code',
      });
      const idToken = tokenData['id_token'] as string | undefined;
      if (!idToken) {
        sendJson(res, 500, { error: 'No id_token in response', data: tokenData });
        return;
      }
      const payload = decodeJwtPayload(idToken);
      const email = payload['email'] as string | undefined;
      const emailVerified = payload['email_verified'] as boolean | undefined;
      if (!email || !emailVerified) {
        sendHtml(
          res,
          403,
          '<h1>Email not verified</h1><p>Google did not return a verified email address.</p>'
        );
        return;
      }
      const domain = email.split('@')[1];
      if (ALLOWED_DOMAIN && domain !== ALLOWED_DOMAIN) {
        sendHtml(
          res,
          403,
          `<h1>Access Denied</h1><p>Only @${ALLOWED_DOMAIN} emails are allowed. Your email: ${email}</p>`
        );
        return;
      }
      const sessionId = generateSessionId();
      sessions.set(sessionId, {
        email,
        name: (payload['name'] as string) ?? email,
        picture: payload['picture'] as string | undefined,
        expiresAt: Date.now() + SESSION_TTL_MS,
      });
      setSessionCookie(res, sessionId);
      sendHtml(
        res,
        200,
        `<h1>Authenticated</h1><p>Logged in as ${email}</p><p>You can close this tab and return to your MCP client.</p>`
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      sendJson(res, 500, { error: 'Token exchange failed', message });
    }
    return;
  }

  if (url.pathname === '/auth/logout') {
    const cookies = parseCookies(req);
    const sid = cookies['sid'];
    if (sid) sessions.delete(sid);
    clearSessionCookie(res);
    sendJson(res, 200, { ok: true });
    return;
  }

  if (url.pathname === '/auth/status') {
    const session = getSession(req);
    if (!session) {
      sendJson(res, 401, { authenticated: false });
      return;
    }
    sendJson(res, 200, {
      authenticated: true,
      email: session.email,
      name: session.name,
    });
    return;
  }

  if (url.pathname === MCP_PATH) {
    if (!requireAuth(req, res)) return;
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    });
    const mcpServer = buildServer();

    try {
      await mcpServer.connect(transport);
      await transport.handleRequest(req, res);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!res.headersSent) {
        sendJson(res, 500, {
          jsonrpc: '2.0',
          error: { code: -32603, message },
          id: null
        });
      }
    } finally {
      await transport.close().catch(() => {});
      await mcpServer.close().catch(() => {});
    }
    return;
  }

  if (url.pathname === '/') {
    sendText(res, 200, 'feed-moborg-docs-mcp');
    return;
  }

  sendJson(res, 404, { error: 'Not found' });
});

server.listen(PORT, HOST, () => {
  console.log(`feed-moborg-docs-mcp listening on ${HOST}:${PORT}`);
  console.log(`Database: ${DB_PATH}`);
  console.log(`Health: http://${HOST}:${PORT}${HEALTH_PATH}`);
  console.log(`MCP: http://${HOST}:${PORT}${MCP_PATH}`);
});

process.on('SIGINT', () => {
  server.close(() => process.exit(0));
});

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
});
