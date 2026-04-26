import path from 'node:path'
import { fileURLToPath } from 'node:url'
import sqlite3 from 'sqlite3'
import { open } from 'sqlite'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const databasePath = path.join(__dirname, '..', 'threattrack.sqlite')

export const dbPromise = open({
  filename: databasePath,
  driver: sqlite3.Database,
})

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
  `)
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
