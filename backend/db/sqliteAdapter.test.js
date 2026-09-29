import assert from 'node:assert/strict'
import test from 'node:test'
import sqlite3 from 'sqlite3'
import { open } from 'sqlite'
import { createSqliteAdapter } from './sqliteAdapter.js'

async function database(t) {
  const connection = await open({ filename: ':memory:', driver: sqlite3.Database })
  const db = createSqliteAdapter(connection)
  t.after(() => db.close())
  await db.exec('CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)')
  return db
}

test('concurrent SQLite transactions both commit', async (t) => {
  const db = await database(t)
  const results = await Promise.all([1, 2].map((id) => db.transaction(async (tx) => {
    await tx.run('INSERT INTO records (id, value) VALUES (?, ?)', id, `record ${id}`)
    return (await tx.get('SELECT COUNT(*) AS count FROM records')).count
  })))
  assert.deepEqual(results, [1, 2])
  assert.equal((await db.get('SELECT COUNT(*) AS count FROM records')).count, 2)
})

test('a rollback cannot discard another request\'s write and the queue recovers', async (t) => {
  const db = await database(t)
  const entered = Promise.withResolvers()
  const release = Promise.withResolvers()
  const failing = db.transaction(async (tx) => {
    await tx.run('INSERT INTO records (id, value) VALUES (1, ?)', 'rolled back')
    entered.resolve()
    await release.promise
    throw new Error('intentional failure')
  })
  const rejected = assert.rejects(failing, /intentional failure/)
  await entered.promise

  const outsideWrite = db.run('INSERT INTO records (id, value) VALUES (2, ?)', 'outside transaction')
  const outsideRead = db.all('SELECT id FROM records ORDER BY id')
  const nextTransaction = db.transaction((tx) =>
    tx.run('INSERT INTO records (id, value) VALUES (3, ?)', 'next transaction'))
  release.resolve()

  await rejected
  await outsideWrite
  assert.deepEqual(await outsideRead, [{ id: 2 }])
  await nextTransaction
  assert.deepEqual(await db.all('SELECT id FROM records ORDER BY id'), [{ id: 2 }, { id: 3 }])
})

test('SQLite rejects nested transactions and remains usable', async (t) => {
  const db = await database(t)
  await assert.rejects(db.transaction((tx) => tx.transaction(() => {})), /Nested SQLite/)
  await db.run('INSERT INTO records (id) VALUES (1)')
  assert.equal((await db.get('SELECT COUNT(*) AS count FROM records')).count, 1)
})
