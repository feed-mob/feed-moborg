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

// ---------------------------------------------------------------------------
// MCP OAuth 2.0 Authorization Server (server is its own AS; Google = upstream
// login only). Implements: discovery, dynamic client registration (RFC 7591),
// Authorization Code + PKCE, and Device Authorization Grant (RFC 8628).
// Tokens are stateless signed JWT (HS256). Stores below are in-memory; that is
// fine because DCR clients re-register automatically and codes are short-lived.
// ---------------------------------------------------------------------------
const TOKEN_SECRET = process.env.TOKEN_SECRET || crypto.randomBytes(32).toString('hex');
const ACCESS_TOKEN_TTL_MS = 8 * 60 * 60 * 1000;
const AUTH_CODE_TTL_MS = 5 * 60 * 1000;
const DEVICE_CODE_TTL_MS = 10 * 60 * 1000;
const DEVICE_POLL_INTERVAL = 5;

interface OAuthClient {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  token_endpoint_auth_method: string;
  client_name?: string;
  created_at: number;
}
interface AuthCode {
  clientId: string;
  redirectUri: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  scope: string;
  email: string;
  name: string;
  expiresAt: number;
}
interface PendingLogin {
  kind: 'browser' | 'authorize' | 'device';
  expiresAt: number;
  clientId?: string;
  redirectUri?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  clientState?: string;
  scope?: string;
  deviceCode?: string;
}
interface DeviceAuth {
  deviceCode: string;
  userCode: string;
  clientId: string;
  scope: string;
  status: 'pending' | 'approved' | 'denied';
  email?: string;
  name?: string;
  expiresAt: number;
}

const oauthClients = new Map<string, OAuthClient>();
const authCodes = new Map<string, AuthCode>();
const pendingLogins = new Map<string, PendingLogin>();
const deviceAuths = new Map<string, DeviceAuth>();
const userCodeIndex = new Map<string, string>();

function b64url(buf: Buffer): string {
  return buf.toString('base64url');
}
function sha256(input: string): Buffer {
  return crypto.createHash('sha256').update(input).digest();
}
function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

function signAccessToken(claims: Record<string, unknown>): string {
  const header = b64url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const now = Math.floor(Date.now() / 1000);
  const body = b64url(
    Buffer.from(
      JSON.stringify({
        iss: BASE_URL,
        aud: BASE_URL,
        iat: now,
        exp: now + Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
        ...claims,
      })
    )
  );
  const sig = b64url(crypto.createHmac('sha256', TOKEN_SECRET).update(`${header}.${body}`).digest());
  return `${header}.${body}.${sig}`;
}
function verifyAccessToken(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, b, s] = parts;
  const expected = b64url(crypto.createHmac('sha256', TOKEN_SECRET).update(`${h}.${b}`).digest());
  const sigBuf = Buffer.from(s);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  try {
    const payload = JSON.parse(Buffer.from(b, 'base64url').toString('utf8')) as Record<string, unknown>;
    if (typeof payload.exp === 'number' && payload.exp * 1000 < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function googleAuthUrl(state: string): string {
  return (
    `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${encodeURIComponent(GOOGLE_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(OAUTH_REDIRECT_URI)}` +
    `&response_type=code&scope=${encodeURIComponent('openid email profile')}` +
    `&state=${encodeURIComponent(state)}&access_type=online&prompt=select_account`
  );
}

function genUserCode(): string {
  const alphabet = 'BCDFGHJKLMNPQRSTVWXZ23456789';
  let out = '';
  for (let i = 0; i < 8; i++) out += alphabet[crypto.randomInt(alphabet.length)];
  return `${out.slice(0, 4)}-${out.slice(4)}`;
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (c: Buffer | string) => (raw += c));
    req.on('end', () => resolve(raw));
  });
}
function parseBody(raw: string, contentType: string): Record<string, any> {
  if (contentType.includes('application/json')) {
    try {
      return JSON.parse(raw) as Record<string, any>;
    } catch {
      return {};
    }
  }
  return Object.fromEntries(new URLSearchParams(raw)) as Record<string, any>;
}

function htmlShell(title: string, inner: string): string {
  return (
    `<!doctype html><html><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<title>${title}</title><style>` +
    `body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0b0e14;color:#e8edf6;` +
    `display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}` +
    `.card{background:#141925;border:1px solid #2a3342;border-radius:14px;padding:32px;max-width:420px;width:90%}` +
    `h1{font-size:20px;margin:0 0 12px}p{color:#9aa7bd;line-height:1.6}` +
    `a.btn,button{display:block;width:100%;box-sizing:border-box;margin:10px 0 0;padding:12px;border-radius:9px;` +
    `border:1px solid #2a3342;background:#1b2230;color:#e8edf6;font-size:15px;text-align:center;text-decoration:none;cursor:pointer}` +
    `a.btn.primary{background:#5b8cff;color:#06101f;border-color:#5b8cff;font-weight:700}` +
    `input{width:100%;box-sizing:border-box;padding:12px;border-radius:9px;border:1px solid #2a3342;` +
    `background:#0f1420;color:#e8edf6;font-size:18px;letter-spacing:2px;text-align:center;margin-top:8px}` +
    `code{font-family:ui-monospace,Menlo,monospace;color:#cfe0ff}` +
    `</style></head><body><div class="card">${inner}</div></body></html>`
  );
}
function loginChooserPage(): string {
  return htmlShell(
    'FeedMob Docs MCP · Login',
    `<h1>登录 FeedMob Docs MCP</h1><p>选择登录方式：</p>` +
      `<a class="btn primary" href="/auth/google/login">1 · 浏览器登录（本地 / IDE 有浏览器）</a>` +
      `<a class="btn" href="/device">2 · 设备码登录（无头服务器 / 远程）</a>` +
      `<p style="font-size:13px;margin-top:16px">仅限 @${ALLOWED_DOMAIN || 'feedmob.com'} 邮箱。</p>`
  );
}
function devicePage(prefill: string): string {
  return htmlShell(
    'Device Login',
    `<h1>设备码登录</h1><p>在你的终端/客户端里看到的配对码，输入到下面：</p>` +
      `<form method="POST" action="/device">` +
      `<input name="user_code" placeholder="XXXX-XXXX" value="${prefill.replace(/"/g, '')}" autocapitalize="characters" autofocus>` +
      `<button type="submit">继续，用 Google 登录</button></form>` +
      `<p style="font-size:13px;margin-top:16px">仅限 @${ALLOWED_DOMAIN || 'feedmob.com'} 邮箱。</p>`
  );
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

  // 1) Bearer access token (MCP clients via OAuth: VS Code, Codex, OpenCode…)
  const authz = req.headers['authorization'];
  if (typeof authz === 'string' && /^bearer\s+/i.test(authz)) {
    const token = authz.replace(/^bearer\s+/i, '').trim();
    const claims = verifyAccessToken(token);
    const email = claims && typeof claims.email === 'string' ? claims.email : '';
    const domainOk = !ALLOWED_DOMAIN || email.split('@')[1] === ALLOWED_DOMAIN;
    if (claims && domainOk) {
      return {
        email,
        name: typeof claims.name === 'string' ? claims.name : email,
        expiresAt: typeof claims.exp === 'number' ? claims.exp * 1000 : 0,
      };
    }
  }

  // 2) Browser cookie session (backward compatible)
  const session = getSession(req);
  if (session) return session;

  // 3) Unauthorized: advertise the resource-metadata so MCP clients can start
  //    the standard OAuth discovery + authorization flow.
  res.setHeader(
    'WWW-Authenticate',
    `Bearer resource_metadata="${BASE_URL}/.well-known/oauth-protected-resource"`
  );
  sendJson(res, 401, {
    error: 'unauthorized',
    authUrl: `${BASE_URL}/login`,
  });
  return null;
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

  if (url.pathname === '/login') {
    if (AUTH_MODE !== 'oauth') {
      sendJson(res, 400, { error: 'Auth not configured' });
      return;
    }
    sendHtml(res, 200, loginChooserPage());
    return;
  }

  if (url.pathname === '/auth/google/login') {
    if (AUTH_MODE !== 'oauth') {
      sendJson(res, 400, { error: 'Auth not configured' });
      return;
    }
    const state = generateSessionId();
    pendingLogins.set(state, { kind: 'browser', expiresAt: Date.now() + AUTH_CODE_TTL_MS });
    setSessionCookie(res, state);
    res.writeHead(302, { location: googleAuthUrl(state) });
    res.end();
    return;
  }

  if (url.pathname === '/auth/google/callback') {
    if (AUTH_MODE !== 'oauth') {
      sendJson(res, 400, { error: 'Auth not configured' });
      return;
    }
    const code = url.searchParams.get('code');
    const returnedState = url.searchParams.get('state') ?? '';
    if (!code) {
      sendJson(res, 400, { error: 'Missing authorization code', query: url.search });
      return;
    }
    let email: string;
    let name: string;
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
      const e = payload['email'] as string | undefined;
      const emailVerified = payload['email_verified'] as boolean | undefined;
      if (!e || !emailVerified) {
        sendHtml(res, 403, '<h1>Email not verified</h1><p>Google did not return a verified email address.</p>');
        return;
      }
      const domain = e.split('@')[1];
      if (ALLOWED_DOMAIN && domain !== ALLOWED_DOMAIN) {
        sendHtml(res, 403, `<h1>Access Denied</h1><p>Only @${ALLOWED_DOMAIN} emails are allowed. Your email: ${e}</p>`);
        return;
      }
      email = e;
      name = (payload['name'] as string) ?? e;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      sendJson(res, 500, { error: 'Token exchange failed', message });
      return;
    }

    const pending = pendingLogins.get(returnedState);
    pendingLogins.delete(returnedState);

    // (a) Authorization Code flow for an MCP client: mint our auth code and
    //     redirect back to the client's registered redirect_uri.
    if (pending?.kind === 'authorize' && pending.clientId && pending.redirectUri) {
      const newCode = randomToken(24);
      authCodes.set(newCode, {
        clientId: pending.clientId,
        redirectUri: pending.redirectUri,
        codeChallenge: pending.codeChallenge,
        codeChallengeMethod: pending.codeChallengeMethod,
        scope: pending.scope ?? 'mcp',
        email,
        name,
        expiresAt: Date.now() + AUTH_CODE_TTL_MS,
      });
      const redirect = new URL(pending.redirectUri);
      redirect.searchParams.set('code', newCode);
      if (pending.clientState) redirect.searchParams.set('state', pending.clientState);
      res.writeHead(302, { location: redirect.toString() });
      res.end();
      return;
    }

    // (b) Device Authorization Grant: approve the waiting device_code.
    if (pending?.kind === 'device' && pending.deviceCode) {
      const da = deviceAuths.get(pending.deviceCode);
      if (da && da.status === 'pending' && da.expiresAt > Date.now()) {
        da.status = 'approved';
        da.email = email;
        da.name = name;
        sendHtml(
          res,
          200,
          `<h1>设备已授权 ✓</h1><p>已登录为 ${email}。回到你的终端 / 客户端，它会自动连接。</p>`
        );
      } else {
        sendHtml(res, 400, '<h1>配对码已过期</h1><p>请在设备端重新发起登录。</p>');
      }
      return;
    }

    // (c) Default: browser session (backward-compatible cookie).
    const sessionId = generateSessionId();
    sessions.set(sessionId, {
      email,
      name,
      expiresAt: Date.now() + SESSION_TTL_MS,
    });
    setSessionCookie(res, sessionId);
    sendHtml(
      res,
      200,
      `<h1>Authenticated</h1><p>Logged in as ${email}</p><p>You can close this tab and return to your MCP client.</p>`
    );
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

  // ---- OAuth 2.0 discovery ----
  if (url.pathname === '/.well-known/oauth-authorization-server') {
    if (AUTH_MODE !== 'oauth') { sendJson(res, 404, { error: 'Not found' }); return; }
    sendJson(res, 200, {
      issuer: BASE_URL,
      authorization_endpoint: `${BASE_URL}/authorize`,
      token_endpoint: `${BASE_URL}/token`,
      registration_endpoint: `${BASE_URL}/register`,
      device_authorization_endpoint: `${BASE_URL}/device_authorization`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
      scopes_supported: ['openid', 'email', 'profile', 'mcp'],
    });
    return;
  }
  if (url.pathname.startsWith('/.well-known/oauth-protected-resource')) {
    if (AUTH_MODE !== 'oauth') { sendJson(res, 404, { error: 'Not found' }); return; }
    sendJson(res, 200, {
      resource: BASE_URL,
      authorization_servers: [BASE_URL],
      scopes_supported: ['mcp'],
    });
    return;
  }

  // ---- Dynamic Client Registration (RFC 7591) ----
  if (url.pathname === '/register' && req.method === 'POST') {
    if (AUTH_MODE !== 'oauth') { sendJson(res, 404, { error: 'Not found' }); return; }
    const body = parseBody(await readBody(req), String(req.headers['content-type'] ?? 'application/json'));
    const rawUris = body['redirect_uris'];
    const redirect_uris: string[] = Array.isArray(rawUris) ? rawUris : rawUris ? [String(rawUris)] : [];
    const method = typeof body['token_endpoint_auth_method'] === 'string' ? body['token_endpoint_auth_method'] : 'none';
    const client_id = randomToken(16);
    const client: OAuthClient = {
      client_id,
      redirect_uris,
      token_endpoint_auth_method: method,
      client_name: typeof body['client_name'] === 'string' ? body['client_name'] : undefined,
      created_at: Date.now(),
    };
    let client_secret: string | undefined;
    if (method !== 'none') {
      client_secret = randomToken(24);
      client.client_secret = client_secret;
    }
    oauthClients.set(client_id, client);
    sendJson(res, 201, {
      client_id,
      ...(client_secret ? { client_secret } : {}),
      client_id_issued_at: Math.floor(client.created_at / 1000),
      redirect_uris,
      token_endpoint_auth_method: method,
      grant_types: ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'],
      response_types: ['code'],
    });
    return;
  }

  // ---- Authorization endpoint (Authorization Code + PKCE) ----
  if (url.pathname === '/authorize') {
    if (AUTH_MODE !== 'oauth') { sendJson(res, 404, { error: 'Not found' }); return; }
    const responseType = url.searchParams.get('response_type');
    const clientId = url.searchParams.get('client_id') ?? '';
    const redirectUri = url.searchParams.get('redirect_uri') ?? '';
    if (responseType !== 'code') { sendJson(res, 400, { error: 'unsupported_response_type' }); return; }
    const client = oauthClients.get(clientId);
    if (!client) { sendJson(res, 400, { error: 'invalid_client' }); return; }
    if (client.redirect_uris.length && !client.redirect_uris.includes(redirectUri)) {
      sendJson(res, 400, { error: 'invalid_request', error_description: 'redirect_uri not registered' });
      return;
    }
    const state = generateSessionId();
    pendingLogins.set(state, {
      kind: 'authorize',
      clientId,
      redirectUri,
      codeChallenge: url.searchParams.get('code_challenge') ?? undefined,
      codeChallengeMethod: url.searchParams.get('code_challenge_method') ?? undefined,
      clientState: url.searchParams.get('state') ?? undefined,
      scope: url.searchParams.get('scope') ?? 'mcp',
      expiresAt: Date.now() + AUTH_CODE_TTL_MS,
    });
    res.writeHead(302, { location: googleAuthUrl(state) });
    res.end();
    return;
  }

  // ---- Device Authorization Grant (RFC 8628) ----
  if (url.pathname === '/device_authorization' && req.method === 'POST') {
    if (AUTH_MODE !== 'oauth') { sendJson(res, 404, { error: 'Not found' }); return; }
    const params = parseBody(await readBody(req), String(req.headers['content-type'] ?? ''));
    const clientId = typeof params['client_id'] === 'string' ? params['client_id'] : 'device';
    const scope = typeof params['scope'] === 'string' ? params['scope'] : 'mcp';
    const device_code = randomToken(32);
    let user_code = genUserCode();
    while (userCodeIndex.has(user_code)) user_code = genUserCode();
    deviceAuths.set(device_code, {
      deviceCode: device_code,
      userCode: user_code,
      clientId,
      scope,
      status: 'pending',
      expiresAt: Date.now() + DEVICE_CODE_TTL_MS,
    });
    userCodeIndex.set(user_code, device_code);
    sendJson(res, 200, {
      device_code,
      user_code,
      verification_uri: `${BASE_URL}/device`,
      verification_uri_complete: `${BASE_URL}/device?user_code=${encodeURIComponent(user_code)}`,
      expires_in: Math.floor(DEVICE_CODE_TTL_MS / 1000),
      interval: DEVICE_POLL_INTERVAL,
    });
    return;
  }
  if (url.pathname === '/device' && req.method === 'GET') {
    if (AUTH_MODE !== 'oauth') { sendJson(res, 404, { error: 'Not found' }); return; }
    sendHtml(res, 200, devicePage(url.searchParams.get('user_code') ?? ''));
    return;
  }
  if (url.pathname === '/device' && req.method === 'POST') {
    if (AUTH_MODE !== 'oauth') { sendJson(res, 404, { error: 'Not found' }); return; }
    const params = parseBody(await readBody(req), String(req.headers['content-type'] ?? ''));
    const userCode = String(params['user_code'] ?? '').toUpperCase().trim();
    const dc = userCodeIndex.get(userCode);
    const da = dc ? deviceAuths.get(dc) : undefined;
    if (!dc || !da || da.expiresAt < Date.now()) {
      sendHtml(res, 400, '<h1>配对码无效或已过期</h1><p>请回到设备端重新获取。</p>');
      return;
    }
    const state = generateSessionId();
    pendingLogins.set(state, { kind: 'device', deviceCode: dc, expiresAt: Date.now() + AUTH_CODE_TTL_MS });
    res.writeHead(302, { location: googleAuthUrl(state) });
    res.end();
    return;
  }

  // ---- Token endpoint (authorization_code + device_code) ----
  if (url.pathname === '/token' && req.method === 'POST') {
    if (AUTH_MODE !== 'oauth') { sendJson(res, 404, { error: 'Not found' }); return; }
    const params = parseBody(await readBody(req), String(req.headers['content-type'] ?? ''));
    const grant = params['grant_type'];

    if (grant === 'authorization_code') {
      const code = typeof params['code'] === 'string' ? params['code'] : '';
      const ac = code ? authCodes.get(code) : undefined;
      if (!ac || ac.expiresAt < Date.now()) { sendJson(res, 400, { error: 'invalid_grant' }); return; }
      authCodes.delete(code);
      if (params['redirect_uri'] && ac.redirectUri !== params['redirect_uri']) {
        sendJson(res, 400, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
        return;
      }
      if (ac.codeChallenge) {
        const verifier = typeof params['code_verifier'] === 'string' ? params['code_verifier'] : '';
        if (!verifier || b64url(sha256(verifier)) !== ac.codeChallenge) {
          sendJson(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
          return;
        }
      }
      const access_token = signAccessToken({ sub: ac.email, email: ac.email, name: ac.name, scope: ac.scope });
      sendJson(res, 200, {
        access_token,
        token_type: 'Bearer',
        expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
        scope: ac.scope,
      });
      return;
    }

    if (grant === 'urn:ietf:params:oauth:grant-type:device_code') {
      const dc = typeof params['device_code'] === 'string' ? params['device_code'] : '';
      const da = dc ? deviceAuths.get(dc) : undefined;
      if (!da || da.expiresAt < Date.now()) { sendJson(res, 400, { error: 'expired_token' }); return; }
      if (da.status === 'pending') { sendJson(res, 400, { error: 'authorization_pending' }); return; }
      if (da.status === 'denied') { sendJson(res, 400, { error: 'access_denied' }); return; }
      deviceAuths.delete(dc);
      userCodeIndex.delete(da.userCode);
      const access_token = signAccessToken({ sub: da.email, email: da.email, name: da.name, scope: da.scope });
      sendJson(res, 200, {
        access_token,
        token_type: 'Bearer',
        expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
        scope: da.scope,
      });
      return;
    }

    sendJson(res, 400, { error: 'unsupported_grant_type' });
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
