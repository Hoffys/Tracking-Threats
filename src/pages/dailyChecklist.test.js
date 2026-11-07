import assert from 'node:assert/strict'
import test from 'node:test'
import {
  DAILY_CHECKLIST_SIZE,
  DAILY_CHECKLIST_STORAGE_KEY,
  DAILY_CHECKLIST_TASKS,
  getDailyChecklist,
  getLocalDateKey,
  readDailyChecklistState,
  writeDailyChecklistState,
} from './dailyChecklist.js'

function createStorage(initial = null) {
  let value = initial
  return {
    getItem: () => value,
    setItem: (_key, nextValue) => { value = nextValue },
    getValue: () => value,
  }
}

test('daily checklist has five stable tasks for each local date and rotates each day', () => {
  const date = new Date(2026, 10, 8)
  const dateKey = getLocalDateKey(date)
  const today = getDailyChecklist(dateKey)
  const tomorrow = new Date(date)
  tomorrow.setDate(tomorrow.getDate() + 1)

  assert.equal(today.length, DAILY_CHECKLIST_SIZE)
  assert.equal(new Set(today).size, DAILY_CHECKLIST_SIZE)
  assert.deepEqual(getDailyChecklist(dateKey), today)
  assert.notDeepEqual(getDailyChecklist(getLocalDateKey(tomorrow)), today)
  assert.equal(new Set(Array.from({ length: 15 }, (_, offset) => {
    const nextDate = new Date(date)
    nextDate.setDate(nextDate.getDate() + offset)
    return getDailyChecklist(getLocalDateKey(nextDate)).join('|')
  })).size, 15)
  assert.equal(DAILY_CHECKLIST_TASKS.length, 15)
})

test('checked tasks persist for the same day and reset when the local date changes', () => {
  const dateKey = '2026-11-08'
  const tasks = getDailyChecklist(dateKey)
  const storage = createStorage()
  const state = { date: dateKey, checkedItems: [tasks[0], 'not a checklist task'] }

  writeDailyChecklistState(storage, state)
  assert.equal(JSON.parse(storage.getValue()).date, dateKey)
  assert.deepEqual(readDailyChecklistState(storage, dateKey), {
    date: dateKey,
    checkedItems: [tasks[0]],
  })
  assert.deepEqual(readDailyChecklistState(storage, '2026-11-09'), {
    date: '2026-11-09',
    checkedItems: [],
  })
  assert.equal(DAILY_CHECKLIST_STORAGE_KEY, 'tracking-threats:learn:daily-checklist:v1')
})

test('missing, malformed, and unavailable storage safely starts with unchecked tasks', () => {
  assert.deepEqual(readDailyChecklistState(null, '2026-11-08'), {
    date: '2026-11-08',
    checkedItems: [],
  })
  const malformed = createStorage('{invalid json')
  assert.deepEqual(readDailyChecklistState(malformed, '2026-11-08'), {
    date: '2026-11-08',
    checkedItems: [],
  })
  const throwingStorage = {
    getItem() { throw new Error('storage unavailable') },
    setItem() { throw new Error('storage unavailable') },
  }
  assert.deepEqual(readDailyChecklistState(throwingStorage, '2026-11-08'), {
    date: '2026-11-08',
    checkedItems: [],
  })
  assert.doesNotThrow(() => writeDailyChecklistState(throwingStorage, {
    date: '2026-11-08', checkedItems: [],
  }))
})
