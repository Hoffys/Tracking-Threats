globalThis.createEmailBatchEngine = function createEmailBatchEngine({
  providerId = 'unknown',
  getViewId,
  getRows,
  extractRow,
  isEligible,
  submit,
  getLevel,
  onResult = () => {},
  onState = () => {},
  isEnabled = () => true,
  batchSizes = [10, 20, 30, 40, 50],
  initialBatchSize = 10,
  maxConcurrency = 4,
}) {
  const allowedBatchSizes = new Set(batchSizes)
  const concurrency = Math.max(1, Math.min(4, Math.trunc(maxConcurrency) || 4))
  let batchSize = allowedBatchSizes.has(initialBatchSize) ? initialBatchSize : batchSizes[0]
  let viewId = readViewId()
  let batchNumber = 1
  let batchStart = 0
  let batchLimit = batchSize
  let attempts = 0
  let pending = 0
  let inFlight = 0
  let paused = false
  let waitingForRows = false
  let generation = 0
  let queue = []
  const messages = new Map()
  const results = []
  const stats = {
    checked: 0,
    safe: 0,
    incomplete: 0,
    caution: 0,
    dangerous: 0,
    content: 0,
    failed: 0,
  }

  function readViewId() {
    try {
      const value = getViewId()
      return typeof value === 'string' && value.trim() ? value.trim() : null
    } catch {
      return null
    }
  }

  function getState() {
    return {
      providerId,
      viewId,
      supported: Boolean(viewId),
      batchNumber,
      batchStart,
      batchSize,
      batchLimit,
      attempts,
      pending,
      paused,
      waitingForRows,
      queued: queue.length,
      stats: { ...stats },
      results: results.map((result) => ({ ...result })),
    }
  }

  function emit() {
    onState(getState())
  }

  function resetForView(nextViewId) {
    generation += 1
    viewId = nextViewId
    batchNumber = 1
    batchStart = 0
    batchLimit = batchSize
    attempts = 0
    pending = 0
    paused = false
    waitingForRows = false
    queue = []
    messages.clear()
    results.length = 0
    Object.keys(stats).forEach((key) => { stats[key] = 0 })
    emit()
  }

  function syncView() {
    const nextViewId = readViewId()
    if (nextViewId === viewId) return false
    resetForView(nextViewId)
    return true
  }

  function removeLatestStats(record) {
    const previousStatus = record.previousStatus ?? record.status
    if (previousStatus === 'success') {
      stats.checked = Math.max(0, stats.checked - 1)
      stats[record.level] = Math.max(0, stats[record.level] - 1)
    } else if (previousStatus === 'failed') {
      stats.failed = Math.max(0, stats.failed - 1)
    } else if (previousStatus === 'pending') {
      pending = Math.max(0, pending - 1)
    }
    delete record.previousStatus
  }

  function collectRows(retryIds = null) {
    let rows
    try {
      rows = getRows()
    } catch {
      rows = []
    }
    if (!Array.isArray(rows)) return

    for (const row of rows) {
      if (attempts + queue.length >= batchLimit) break
      let extracted
      try {
        extracted = extractRow(row)
      } catch {
        continue
      }
      const id = typeof extracted?.id === 'string' ? extracted.id.trim() : ''
      const email = extracted?.email
      if (!id || !email || typeof email !== 'object' || !isEligible(email)) continue
      if (retryIds && !retryIds.has(id)) continue

      const existing = messages.get(id)
      if (existing && (!retryIds || existing.status !== 'failed')) continue
      if (!existing && retryIds) continue

      const record = existing ?? { id, status: 'new', level: '', email, row }
      record.email = email
      record.row = row
      if (existing) record.previousStatus = existing.status
      record.status = 'queued'
      record.generation = generation
      messages.set(id, record)
      queue.push(record)
    }
  }

  function setWaitingOrPaused() {
    if (pending > 0 || queue.length > 0) {
      waitingForRows = false
      return
    }
    if (attempts - batchStart >= batchSize) {
      paused = true
      waitingForRows = false
      return
    }
    waitingForRows = true
  }

  function drain() {
    while (isEnabled() && queue.length > 0 && inFlight < concurrency && attempts < batchLimit) {
      if (readViewId() !== viewId) {
        syncView()
        return
      }
      const record = queue.shift()
      if (record.generation !== generation) continue
      attempts += 1
      pending += 1
      inFlight += 1
      waitingForRows = false
      paused = false
      removeLatestStats(record)
      record.status = 'pending'
      record.level = ''
      const result = {
        batch: batchNumber,
        sender: record.email.sender ?? '',
        subject: record.email.subject ?? '',
        pending: true,
      }
      results.push(result)
      const requestGeneration = generation
      const requestViewId = viewId
      let settled = false

      const settle = (error, scan) => {
        if (settled) return
        settled = true
        inFlight = Math.max(0, inFlight - 1)
        if (requestGeneration !== generation) {
          if (isEnabled()) drain()
          return
        }
        if (readViewId() !== requestViewId) {
          syncView()
          if (isEnabled()) drain()
          return
        }
        pending = Math.max(0, pending - 1)
        result.pending = false
        if (error || !scan) {
          result.failed = true
          record.status = 'failed'
          stats.failed += 1
        } else {
          const level = getLevel(scan)
          const classification = scan.threatClassification ?? scan.details?.threatClassification ?? {}
          result.status = scan.status
          result.score = scan.score
          result.coverage = scan.coverage
          result.categories = scan.categories
          result.categoryWarnings = scan.categoryWarnings
          for (const field of [
            'threatName', 'threatType', 'confidence', 'whyDetected', 'evidenceSources',
            'warningSigns', 'summary', 'recommendations',
          ]) {
            const value = scan[field] ?? classification[field]
            if (value !== undefined) result[field] = value
          }
          result.level = level
          record.status = 'success'
          record.level = level
          stats.checked += 1
          stats[level] = (stats[level] ?? 0) + 1
          onResult({ row: record.row, email: record.email, scan, result: { ...result } })
        }
        setWaitingOrPaused()
        emit()
        drain()
        setWaitingOrPaused()
        emit()
      }

      try {
        submit(record.email, (error, scan) => settle(error, scan))
      } catch (error) {
        settle(error, null)
      }
    }
  }

  function scan(retryIds = null) {
    if (!isEnabled() || !viewId || syncView() || paused) {
      if (!viewId) emit()
      return
    }
    collectRows(retryIds)
    drain()
    setWaitingOrPaused()
    emit()
  }

  function setBatchSize(value) {
    const nextSize = Number(value)
    if (!allowedBatchSizes.has(nextSize)) return batchSize
    batchSize = nextSize
    if (paused || attempts === batchStart) batchLimit = batchStart + batchSize
    emit()
    return batchSize
  }

  function continueBatch() {
    if (!isEnabled() || !paused || !viewId) return false
    if (syncView()) return false
    batchNumber += 1
    batchStart = attempts
    batchLimit = batchStart + batchSize
    paused = false
    waitingForRows = false
    scan()
    return true
  }

  function retryFailed() {
    if (!isEnabled() || !viewId) return false
    if (syncView()) return false
    const retryIds = new Set([...messages.values()]
      .filter((record) => record.status === 'failed')
      .map((record) => record.id))
    if (retryIds.size === 0) return false
    batchNumber += 1
    batchStart = attempts
    batchLimit = batchStart + batchSize
    paused = false
    waitingForRows = false
    scan(retryIds)
    return true
  }

  function cancel() {
    resetForView(readViewId())
  }

  return {
    scan,
    setBatchSize,
    continueBatch,
    retryFailed,
    handleViewChange: syncView,
    cancel,
    getState,
  }
}
