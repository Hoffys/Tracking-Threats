globalThis.createOutlookCloudBatchAdapter = function createOutlookCloudBatchAdapter({
  documentRef = document,
  windowRef = window,
  getFolderId,
  extractMessage,
  submit,
  getLevel,
  isEnabled,
  onState = () => {},
  onConversation = () => {},
  isEligible = (email) => Boolean(email?.sender && email?.subject && email?.body),
  canScanMessage = () => true,
  maxWaitMs = 6000,
}) {
  const stagedMessages = []
  const seenConversationIds = new Set()
  const seenMessageIds = new Set()
  let generation = 0
  let active = false
  let folderId = null
  let currentConversation = null
  let conversationsInspected = 0
  let conversationsIncomplete = 0
  let conversationsSkipped = 0
  let folderTraversalLimited = true
  let listWaitCleanup = null
  const setIntervalFn = windowRef.setInterval?.bind(windowRef) ?? globalThis.setInterval
  const clearIntervalFn = windowRef.clearInterval?.bind(windowRef) ?? globalThis.clearInterval

  function emitState(state = engine.getState()) {
    onState({ ...state, adapter: getStatus() })
  }

  const engine = globalThis.createEmailBatchEngine({
    providerId: 'outlook-cloud',
    getViewId: getFolderId,
    getRows: () => stagedMessages,
    extractRow: (record) => record,
    isEligible,
    submit,
    getLevel,
    isEnabled,
    onState: (state) => emitState(state),
    initialBatchSize: 10,
    maxConcurrency: 4,
  })

  function getMessageList() {
    return Array.from(documentRef.querySelectorAll('[role="listbox"]'))
      .find((list) => /^Message list\b/i.test(list.getAttribute('aria-label') ?? '')) ?? null
  }

  function getConversationRows(list = getMessageList()) {
    if (!list) return []
    return Array.from(list.querySelectorAll('[role="option"][data-convid]'))
      .filter((row) => {
        if (!row.getAttribute('data-convid')?.trim() || row.getAttribute('aria-hidden') === 'true') return false
        const rect = row.getBoundingClientRect?.()
        return !rect || (rect.width > 0 && rect.height > 0)
      })
  }

  function waitForRenderedConversation(list, runGeneration) {
    return new Promise((resolve) => {
      let settled = false
      let interval = null
      let observer = null
      const finish = (hasRows) => {
        if (settled) return
        settled = true
        observer?.disconnect()
        list?.removeEventListener('scroll', check)
        if (interval !== null) clearIntervalFn(interval)
        listWaitCleanup = null
        resolve(hasRows)
      }
      const check = () => {
        if (runGeneration !== generation || !active || getFolderId() !== folderId) {
          finish(false)
          return
        }
        if (findNextConversationRow(list)) finish(true)
      }
      observer = typeof MutationObserver === 'function' ? new MutationObserver(check) : null
      observer?.observe(list, { childList: true, subtree: true })
      list?.addEventListener('scroll', check, { passive: true })
      interval = setIntervalFn(check, 250)
      listWaitCleanup = () => finish(false)
      check()
    })
  }

  function getConversationId(row) {
    const value = row?.getAttribute?.('data-convid')?.trim() ?? ''
    return value && value.length <= 256 && !/[\u0000-\u001f\u007f]/.test(value) ? value : ''
  }

  function getReadingPane() {
    return Array.from(documentRef.querySelectorAll('[aria-label="Reading Pane"]')).at(-1) ?? null
  }

  function getMessageElements() {
    const pane = getReadingPane()
    return pane ? Array.from(pane.querySelectorAll('[aria-label="Email message"]')) : []
  }

  function getItempartId(messageElement) {
    let current = messageElement
    for (let depth = 0; current && depth <= 5; depth += 1, current = current.parentElement) {
      const value = current.getAttribute?.('data-itempart-id')?.trim() ?? ''
      if (value) {
        return value.length <= 256 && !/[\u0000-\u001f\u007f]/.test(value) ? value : ''
      }
    }
    return ''
  }

  function getMessageSignature(elements) {
    return elements.map((element) => {
      const id = getItempartId(element)
      const body = element.querySelector('[data-test-id="mailMessageBodyContainer"], [aria-label="Message body"]')?.textContent ?? ''
      return `${id}:${body.trim().slice(0, 120)}`
    }).join('|')
  }

  function delay(ms, runGeneration) {
    return new Promise((resolve) => {
      windowRef.setTimeout(() => resolve(runGeneration === generation), ms)
    })
  }

  async function waitForOpenedConversation(previousSignature, runGeneration) {
    const startedAt = Date.now()
    let priorSignature = ''
    let stableFor = 0
    while (Date.now() - startedAt < maxWaitMs) {
      if (runGeneration !== generation || getFolderId() !== folderId) return []
      const list = getMessageList()
      const elements = getMessageElements()
      const signature = getMessageSignature(elements)
      if (!list) return []
      if (elements.length && signature && signature !== previousSignature) {
        stableFor = signature === priorSignature ? stableFor + 100 : 0
        if (stableFor >= 400) return elements
      } else {
        stableFor = 0
      }
      priorSignature = signature
      if (!await delay(100, runGeneration)) return []
    }
    return []
  }

  async function waitForEngineIdle(runGeneration) {
    while (runGeneration === generation) {
      if (getFolderId() !== folderId) return false
      const state = engine.getState()
      if (state.pending === 0) return true
      if (!await delay(40, runGeneration)) return false
    }
    return false
  }

  function collectCurrentMessages(conversationId, elements) {
    const records = []
    let incomplete = false
    const localIds = new Set()
    for (const element of elements) {
      const itempartId = getItempartId(element)
      if (!itempartId || localIds.has(itempartId) || seenMessageIds.has(itempartId)) {
        incomplete = true
        continue
      }
      localIds.add(itempartId)
      const email = extractMessage(element)
      if (!email?.sender || !email?.subject || !email?.body?.trim() || email.body.trim().length < 12) {
        incomplete = true
        continue
      }
      const record = { id: itempartId, email }
      if (!isEligible(email) || !canScanMessage(itempartId, email)) {
        incomplete = true
        continue
      }
      seenMessageIds.add(itempartId)
      records.push(record)
    }
    // The observed DOM does not expose a verified count for collapsed or unloaded replies.
    return { records, incomplete: true }
  }

  function findNextConversationRow(list) {
    return getConversationRows(list).find((row) => {
      const id = getConversationId(row)
      return id && !seenConversationIds.has(id)
    }) ?? null
  }

  async function run(runGeneration) {
    while (active && runGeneration === generation && isEnabled()) {
      if (getFolderId() !== folderId) {
        cancel()
        return
      }
      if (currentConversation?.records) {
        while (currentConversation.index < currentConversation.records.length) {
          if (engine.getState().paused) return
          const record = currentConversation.records[currentConversation.index]
          currentConversation.index += 1
          stagedMessages.push(record)
          engine.scan()
          if (!await waitForEngineIdle(runGeneration)) return
          if (engine.getState().paused) return
        }
        conversationsInspected += 1
        onConversation({ id: currentConversation.id, status: 'incomplete' })
        if (currentConversation.incomplete) conversationsIncomplete += 1
        emitState()
        currentConversation = null
      }

      const list = getMessageList()
      if (!list) {
        conversationsSkipped += 1
        onConversation({ id: '', status: 'skipped', reason: 'Message list is unavailable.' })
        emitState()
        active = false
        break
      }
      let row = findNextConversationRow(list)
      if (!row) {
        folderTraversalLimited = true
        emitState()
        if (!await waitForRenderedConversation(list, runGeneration)) return
        continue
      }

      const conversationId = getConversationId(row)
      const previousSignature = getMessageSignature(getMessageElements())
      seenConversationIds.add(conversationId)
      row.click()
      const messageElements = await waitForOpenedConversation(previousSignature, runGeneration)
      if (runGeneration !== generation || getFolderId() !== folderId) return
      const { records, incomplete } = collectCurrentMessages(conversationId, messageElements)
      currentConversation = { id: conversationId, records, index: 0, incomplete: true }
      if (!records.length) {
        conversationsSkipped += 1
        conversationsIncomplete += 1
        onConversation({ id: conversationId, status: 'skipped', reason: 'No complete, uniquely identified individual messages were available.' })
        emitState()
        currentConversation = null
      }
    }
    if (runGeneration === generation && !engine.getState().paused) {
      active = false
      onState({ ...engine.getState(), adapter: getStatus() })
    }
  }

  function getStatus() {
    return {
      active,
      folderId,
      conversationsInspected,
      conversationsIncomplete,
      conversationsSkipped,
      seenConversations: seenConversationIds.size,
      folderTraversalLimited,
    }
  }

  function start() {
    if (!isEnabled()) return false
    const selectedFolder = getFolderId()
    if (!selectedFolder || !getMessageList()) return false
    cancel()
    generation += 1
    folderId = selectedFolder
    active = true
    conversationsInspected = 0
    conversationsIncomplete = 0
    conversationsSkipped = 0
    folderTraversalLimited = true
    seenConversationIds.clear()
    seenMessageIds.clear()
    stagedMessages.length = 0
    currentConversation = null
    engine.handleViewChange()
    engine.scan()
    onState({ ...engine.getState(), adapter: getStatus() })
    run(generation).catch(() => {
      if (active) {
        active = false
        emitState({ ...engine.getState(), error: true })
      }
    })
    return true
  }

  function continueBatch() {
    if (!active || !engine.continueBatch()) return false
    const runGeneration = generation
    run(runGeneration).catch(() => {
      if (active) active = false
    })
    return true
  }

  function retryFailed() {
    if (!isEnabled()) return false
    const resumePausedRunner = active && engine.getState().paused
    const retried = engine.retryFailed()
    if (retried && resumePausedRunner) {
      const runGeneration = generation
      run(runGeneration).catch(() => {
        if (active) active = false
      })
    }
    return retried
  }

  function cancel() {
    generation += 1
    active = false
    listWaitCleanup?.()
    listWaitCleanup = null
    currentConversation = null
    stagedMessages.length = 0
    folderId = null
    engine.cancel()
    onState({ ...engine.getState(), adapter: getStatus() })
  }

  function syncFolder() {
    const currentFolder = getFolderId()
    if (active && currentFolder !== folderId) cancel()
    else {
      engine.handleViewChange()
      if (!active) folderId = currentFolder
    }
    return Boolean(currentFolder && currentFolder === folderId)
  }

  return {
    engine,
    start,
    continueBatch,
    retryFailed,
    cancel,
    syncFolder,
    getState: () => ({ ...engine.getState(), adapter: getStatus() }),
    hasMessageId: (id) => seenMessageIds.has(id),
    getConversationRows,
    getConversationId,
    getItempartId,
  }
}
