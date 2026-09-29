// Keep every connection operation outside another request's transaction.
export function createSqliteAdapter(connection) {
  let pending = Promise.resolve()
  const enqueue = (operation) => {
    const result = pending.then(operation)
    pending = result.catch(() => {})
    return result
  }

  const direct = {
    provider: 'sqlite',
    exec: (...args) => connection.exec(...args),
    run: (...args) => connection.run(...args),
    get: (...args) => connection.get(...args),
    all: (...args) => connection.all(...args),
    async transaction() {
      throw new Error('Nested SQLite transactions are not supported')
    },
  }

  return {
    provider: 'sqlite',
    exec: (...args) => enqueue(() => direct.exec(...args)),
    run: (...args) => enqueue(() => direct.run(...args)),
    get: (...args) => enqueue(() => direct.get(...args)),
    all: (...args) => enqueue(() => direct.all(...args)),
    close: () => enqueue(() => connection.close()),
    transaction: (callback) => enqueue(async () => {
      await direct.exec('BEGIN')
      try {
        const result = await callback(direct)
        await direct.exec('COMMIT')
        return result
      } catch (error) {
        await direct.exec('ROLLBACK')
        throw error
      }
    }),
  }
}
