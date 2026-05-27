import crypto from 'crypto';

import { withDb } from './db.js';

const DEFAULT_SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const DEFAULT_CLEANUP_INTERVAL_MS = 15 * 60 * 1000;
const DEFAULT_TOUCH_THROTTLE_MS = 60 * 1000; // 1 minute default

let schemaReady = null;
let cleanupTimer = null;

// Bounded in-memory map to throttle last_seen_at updates (prevents MVCC bloat & lock storms)
const lastSeenThrottleMap = new Map();

function getSessionTtlMs() {
  const value = Number(process.env.ADMIN_SESSION_TTL_MS);
  return Number.isFinite(value) && value > 0 ? value : DEFAULT_SESSION_TTL_MS;
}

function getCleanupIntervalMs() {
  const value = Number(process.env.ADMIN_SESSION_CLEANUP_INTERVAL_MS);
  return Number.isFinite(value) && value > 0 ? value : DEFAULT_CLEANUP_INTERVAL_MS;
}

function getTouchThrottleMs() {
  const value = Number(process.env.ADMIN_SESSION_TOUCH_THROTTLE_MS);
  return Number.isFinite(value) && value >= 0 ? value : DEFAULT_TOUCH_THROTTLE_MS;
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

async function ensureSchema(client) {
  await client.query(`
    create table if not exists admin_sessions (
      token_hash text primary key,
      username text not null,
      metadata jsonb not null default '{}'::jsonb,
      created_at timestamptz not null default now(),
      last_seen_at timestamptz not null default now(),
      expires_at timestamptz not null,
      revoked_at timestamptz
    )
  `);

  await client.query('create index if not exists idx_admin_sessions_expires_at on admin_sessions (expires_at)');
  await client.query('create index if not exists idx_admin_sessions_revoked_at on admin_sessions (revoked_at)');
}

async function ensureReady() {
  if (!schemaReady) {
    schemaReady = withDb(async (client) => {
      await ensureSchema(client);
    });
  }

  return schemaReady;
}

export async function createAdminSession({ username, metadata = {} }) {
  await ensureReady();

  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(token);
  const ttlMs = getSessionTtlMs();
  const expiresAt = new Date(Date.now() + ttlMs);

  await withDb(async (client) => {
    await client.query(
      `insert into admin_sessions (token_hash, username, metadata, expires_at)
       values ($1, $2, $3, $4)
       on conflict (token_hash) do update set
         username = excluded.username,
         metadata = excluded.metadata,
         created_at = now(),
         last_seen_at = now(),
         expires_at = excluded.expires_at,
         revoked_at = null`,
      [tokenHash, username, metadata, expiresAt]
    );
  });

  return {
    token,
    username,
    expiresAt: expiresAt.toISOString(),
    ttlMs,
  };
}

export async function getAdminSession(token) {
  if (!token) return null;
  await ensureReady();

  const tokenHash = hashToken(token);
  return withDb(async (client) => {
    const { rows } = await client.query(
      `select token_hash, username, metadata, created_at, last_seen_at, expires_at
       from admin_sessions
       where token_hash = $1
         and revoked_at is null
         and expires_at > now()`,
      [tokenHash]
    );

    if (!rows.length) {
      lastSeenThrottleMap.delete(tokenHash);
      await client.query('delete from admin_sessions where token_hash = $1 and (expires_at <= now() or revoked_at is not null)', [tokenHash]);
      return null;
    }

    const row = rows[0];
    const nowMs = Date.now();
    const lastUpdate = lastSeenThrottleMap.get(tokenHash);
    const throttleMs = getTouchThrottleMs();

    if (!lastUpdate || nowMs - lastUpdate >= throttleMs) {
      lastSeenThrottleMap.set(tokenHash, nowMs);

      // Async non-blocking deferred persistence: execute outside the request query thread context
      withDb(async (dbClient) => {
        await dbClient.query('update admin_sessions set last_seen_at = now() where token_hash = $1', [tokenHash]);
      }).catch((error) => {
        console.error('Failed to update admin session last_seen_at asynchronously:', error);
      });
    }

    // Bounded memory defense: safeguard map from unbounded growth in extreme production environments
    if (lastSeenThrottleMap.size > 1000) {
      lastSeenThrottleMap.clear();
    }

    return {
      token: token,
      username: row.username,
      metadata: row.metadata || {},
      createdAt: row.created_at,
      lastSeenAt: row.last_seen_at,
      expiresAt: row.expires_at,
    };
  });
}

export async function revokeAdminSession(token) {
  if (!token) return false;
  await ensureReady();

  const tokenHash = hashToken(token);
  lastSeenThrottleMap.delete(tokenHash);

  return withDb(async (client) => {
    const { rowCount } = await client.query(
      'update admin_sessions set revoked_at = now() where token_hash = $1 and revoked_at is null',
      [tokenHash]
    );
    return rowCount > 0;
  });
}

export async function cleanupExpiredAdminSessions() {
  await ensureReady();
  lastSeenThrottleMap.clear(); // Prune all throttled session updates to free memory

  return withDb(async (client) => {
    const { rowCount } = await client.query(
      'delete from admin_sessions where expires_at <= now() or revoked_at is not null'
    );
    return rowCount;
  });
}

export function startAdminSessionCleanup() {
  if (cleanupTimer) return cleanupTimer;

  const intervalMs = getCleanupIntervalMs();
  cleanupTimer = setInterval(() => {
    cleanupExpiredAdminSessions().catch((error) => {
      console.error('Failed to clean up admin sessions', error);
    });
  }, intervalMs);

  cleanupTimer.unref?.();
  return cleanupTimer;
}