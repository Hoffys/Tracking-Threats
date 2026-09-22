import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import pg from 'pg'
import sqlite3 from 'sqlite3'
import { open } from 'sqlite'
import '../config/loadEnv.js'

const { Pool, types } = pg
const __dirname = path.dirname(fileURLToPath(import.meta.url))
const databaseUrl = String(process.env.DATABASE_URL ?? '').trim()
const databasePath = process.env.DATABASE_PATH
  ? path.resolve(process.env.DATABASE_PATH)
  : path.join(__dirname, '..', 'threattrack.sqlite')

export const databaseProvider = databaseUrl ? 'postgresql' : 'sqlite'

// PostgreSQL returns BIGINT values such as COUNT(*) as strings by default.
types.setTypeParser(20, (value) => Number(value))

const toPostgresQuery = (sql) => {
  let parameter = 0
  return sql
    .replace(/\?/g, () => `$${++parameter}`)
    .replace(/LIMIT\s+-1\s+OFFSET/gi, 'LIMIT ALL OFFSET')
}

const createPostgresAdapter = (queryable, pool = null) => ({
  provider: 'postgresql',
  async exec(sql) {
    await queryable.query(sql)
  },
  async run(sql, ...params) {
    const result = await queryable.query(toPostgresQuery(sql), params)
    return { changes: result.rowCount ?? 0 }
  },
  async get(sql, ...params) {
    const result = await queryable.query(toPostgresQuery(sql), params)
    return result.rows[0]
  },
  async all(sql, ...params) {
    const result = await queryable.query(toPostgresQuery(sql), params)
    return result.rows
  },
  async transaction(callback) {
    if (!pool) throw new Error('Nested PostgreSQL transactions are not supported')
    const client = await pool.connect()
    const transactionDb = createPostgresAdapter(client)
    try {
      await client.query('BEGIN')
      const result = await callback(transactionDb)
      await client.query('COMMIT')
      return result
    } catch (error) {
      await client.query('ROLLBACK')
      throw error
    } finally {
      client.release()
    }
  },
})

const openPostgresDatabase = async () => {
  const useTls = process.env.DATABASE_SSL === 'true'
  const poolSize = Number.parseInt(process.env.DATABASE_POOL_SIZE ?? '10', 10)
  const pool = new Pool({
    connectionString: databaseUrl,
    max: Number.isInteger(poolSize) && poolSize > 0 ? poolSize : 10,
    ssl: useTls
      ? { rejectUnauthorized: process.env.DATABASE_SSL_REJECT_UNAUTHORIZED !== 'false' }
      : undefined,
  })
  await pool.query('SELECT 1')
  return createPostgresAdapter(pool, pool)
}

const openSqliteDatabase = async () => {
  await fs.mkdir(path.dirname(databasePath), { recursive: true })
  const db = await open({ filename: databasePath, driver: sqlite3.Database })
  db.provider = 'sqlite'
  db.transaction = async (callback) => {
    await db.exec('BEGIN')
    try {
      const result = await callback(db)
      await db.exec('COMMIT')
      return result
    } catch (error) {
      await db.exec('ROLLBACK')
      throw error
    }
  }
  return db
}

const openDatabase = () => (databaseUrl ? openPostgresDatabase() : openSqliteDatabase())

export const dbPromise = openDatabase()

export async function initDatabase() {
  const db = await dbPromise
  await db.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      target TEXT NOT NULL,
      content TEXT,
      score INTEGER NOT NULL,
      status TEXT NOT NULL,
      risk TEXT NOT NULL,
      action TEXT NOT NULL,
      summary TEXT,
      warning_signs TEXT,
      recommendations TEXT,
      details TEXT,
      client_id TEXT,
      submission_id TEXT,
      processing_status TEXT NOT NULL DEFAULT 'completed',
      methodology_version TEXT NOT NULL DEFAULT '2026.09',
      content_retained INTEGER NOT NULL DEFAULT 0,
      expires_at TEXT,
      history_visible INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY,
      scan_id TEXT,
      title TEXT NOT NULL,
      source TEXT NOT NULL,
      severity TEXT NOT NULL,
      status TEXT NOT NULL,
      threat_type TEXT,
      risk_level TEXT,
      recommended_action TEXT,
      message TEXT,
      client_id TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS blocked_threats (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      type TEXT NOT NULL,
      target TEXT NOT NULL,
      content TEXT,
      score INTEGER NOT NULL,
      status TEXT NOT NULL,
      action TEXT NOT NULL,
      reason TEXT,
      recommended_action TEXT,
      review_status TEXT NOT NULL DEFAULT 'active',
      active_visible INTEGER NOT NULL DEFAULT 1,
      audit_visible INTEGER NOT NULL DEFAULT 1,
      reviewed_at TEXT,
      client_id TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS email_scans (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      sender TEXT NOT NULL,
      subject TEXT,
      body TEXT,
      score INTEGER NOT NULL,
      status TEXT NOT NULL,
      risk TEXT NOT NULL,
      summary TEXT,
      warning_signs TEXT,
      recommendations TEXT,
      client_id TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS message_scans (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      target TEXT NOT NULL,
      message TEXT,
      score INTEGER NOT NULL,
      status TEXT NOT NULL,
      risk TEXT NOT NULL,
      summary TEXT,
      warning_signs TEXT,
      recommendations TEXT,
      client_id TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS live_monitor_activity (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL UNIQUE,
      activity_type TEXT NOT NULL,
      source TEXT NOT NULL,
      target TEXT NOT NULL,
      domain TEXT,
      title TEXT NOT NULL,
      detail TEXT,
      score INTEGER NOT NULL,
      status TEXT NOT NULL,
      risk_status TEXT NOT NULL,
      warning_signs TEXT,
      client_id TEXT,
      history_visible INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS system_logs (
      id TEXT PRIMARY KEY,
      level TEXT NOT NULL,
      event TEXT NOT NULL,
      message TEXT,
      metadata TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notification_settings (
      id TEXT PRIMARY KEY,
      report_emails TEXT NOT NULL,
      email_scan_reports INTEGER NOT NULL DEFAULT 1,
      email_history_digest INTEGER NOT NULL DEFAULT 1,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scan_evidence (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      evidence_type TEXT NOT NULL,
      source TEXT NOT NULL,
      finding TEXT NOT NULL,
      matched INTEGER NOT NULL DEFAULT 0,
      score_impact INTEGER NOT NULL DEFAULT 0,
      details TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scan_submissions (
      id TEXT PRIMARY KEY,
      scan_id TEXT,
      client_id TEXT,
      scan_type TEXT NOT NULL,
      target_label TEXT NOT NULL,
      target_hash TEXT NOT NULL,
      source TEXT NOT NULL,
      processing_status TEXT NOT NULL DEFAULT 'queued',
      content_received INTEGER NOT NULL DEFAULT 0,
      error_message TEXT,
      submitted_at TEXT NOT NULL,
      started_at TEXT,
      completed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS privacy_consents (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL,
      client_id TEXT,
      notice_version TEXT NOT NULL,
      accepted INTEGER NOT NULL DEFAULT 0,
      processing_basis TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS client_credentials (
      client_id TEXT PRIMARY KEY,
      token_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS admin_actions (
      id TEXT PRIMARY KEY,
      action TEXT NOT NULL,
      client_ref TEXT NOT NULL,
      deleted_scans INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );
  `)

  await ensureColumn(db, 'blocked_threats', 'review_status', "TEXT NOT NULL DEFAULT 'active'")
  await ensureColumn(db, 'blocked_threats', 'active_visible', 'INTEGER NOT NULL DEFAULT 1')
  await ensureColumn(db, 'blocked_threats', 'audit_visible', 'INTEGER NOT NULL DEFAULT 1')
  await ensureColumn(db, 'blocked_threats', 'reviewed_at', 'TEXT')
  await ensureColumn(db, 'scans', 'history_visible', 'INTEGER NOT NULL DEFAULT 1')
  await ensureColumn(db, 'scans', 'client_id', 'TEXT')
  await ensureColumn(db, 'scans', 'submission_id', 'TEXT')
  await ensureColumn(db, 'scans', 'processing_status', "TEXT NOT NULL DEFAULT 'completed'")
  await ensureColumn(db, 'scans', 'methodology_version', "TEXT NOT NULL DEFAULT '2026.09'")
  await ensureColumn(db, 'scans', 'content_retained', 'INTEGER NOT NULL DEFAULT 0')
  await ensureColumn(db, 'scans', 'expires_at', 'TEXT')
  await ensureColumn(db, 'alerts', 'client_id', 'TEXT')
  await ensureColumn(db, 'blocked_threats', 'client_id', 'TEXT')
  await ensureColumn(db, 'email_scans', 'client_id', 'TEXT')
  await ensureColumn(db, 'message_scans', 'client_id', 'TEXT')
  await ensureColumn(db, 'live_monitor_activity', 'history_visible', 'INTEGER NOT NULL DEFAULT 1')
  await ensureColumn(db, 'live_monitor_activity', 'client_id', 'TEXT')
  await db.exec(`
    CREATE INDEX IF NOT EXISTS idx_scans_client_id ON scans(client_id);
    CREATE INDEX IF NOT EXISTS idx_scans_expires_at ON scans(expires_at);
    CREATE INDEX IF NOT EXISTS idx_scan_evidence_scan_id ON scan_evidence(scan_id);
    CREATE INDEX IF NOT EXISTS idx_privacy_consents_scan_id ON privacy_consents(scan_id);
    CREATE INDEX IF NOT EXISTS idx_scan_submissions_client_id ON scan_submissions(client_id);
    CREATE INDEX IF NOT EXISTS idx_scan_submissions_status ON scan_submissions(processing_status);
    CREATE INDEX IF NOT EXISTS idx_admin_actions_created_at ON admin_actions(created_at);
  `)
  await db.run(
    `INSERT INTO notification_settings
      (id, report_emails, email_scan_reports, email_history_digest, updated_at)
      VALUES ('default', '[]', 1, 1, ?)
      ON CONFLICT(id) DO NOTHING`,
    new Date().toISOString(),
  )
}

async function ensureColumn(db, table, column, definition) {
  if (db.provider === 'postgresql') {
    await db.exec(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${column} ${definition}`)
    return
  }

  const columns = await db.all(`PRAGMA table_info(${table})`)
  if (!columns.some((item) => item.name === column)) {
    await db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`)
  }
}

export const toJson = (value) => JSON.stringify(value ?? [])

export const fromJson = (value, fallback = []) => {
  if (!value) return fallback
  try {
    return JSON.parse(value)
  } catch {
    return fallback
  }
}
