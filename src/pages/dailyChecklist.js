export const DAILY_CHECKLIST_STORAGE_KEY = 'tracking-threats:learn:daily-checklist:v1'
export const DAILY_CHECKLIST_SIZE = 5

export const DAILY_CHECKLIST_TASKS = [
  'Check the sender address and domain before trusting a message.',
  'Hover or preview links before opening them.',
  'Never share one-time codes, passwords, or recovery links.',
  'Scan files before opening downloads or email attachments.',
  'Report suspicious activity quickly so it can be blocked.',
  'Open an organization’s website from a trusted bookmark.',
  'Compare the visible link text with the actual destination.',
  'Verify unexpected payment requests through a separate channel.',
  'Be cautious when a message pressures you to act immediately.',
  'Check for misspelled or lookalike domain names.',
  'Do not enable macros in unexpected document attachments.',
  'Confirm unusual password-reset requests directly with the service.',
  'Use multi-factor authentication without approving unexpected prompts.',
  'Avoid entering personal details after following an unsolicited link.',
  'Report suspicious messages using your organization’s trusted process.',
]

export function getChecklistStorage() {
  try {
    return globalThis.localStorage
  } catch {
    return null
  }
}

export function getLocalDateKey(date = new Date()) {
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')
  return `${year}-${month}-${day}`
}

export function getDailyChecklist(dateKey) {
  const dayNumber = Math.floor(Date.parse(`${dateKey}T00:00:00Z`) / 86_400_000)
  const normalizedDay = Number.isFinite(dayNumber) ? dayNumber : 0
  const start = ((normalizedDay * 7) % DAILY_CHECKLIST_TASKS.length + DAILY_CHECKLIST_TASKS.length) % DAILY_CHECKLIST_TASKS.length
  return Array.from({ length: DAILY_CHECKLIST_SIZE }, (_, index) => (
    DAILY_CHECKLIST_TASKS[(start + index) % DAILY_CHECKLIST_TASKS.length]
  ))
}

export function readDailyChecklistState(storage, dateKey) {
  const todaysTasks = getDailyChecklist(dateKey)
  try {
    const stored = JSON.parse(storage?.getItem(DAILY_CHECKLIST_STORAGE_KEY) ?? 'null')
    if (stored?.date !== dateKey || !Array.isArray(stored.checkedItems)) {
      return { date: dateKey, checkedItems: [] }
    }
    return {
      date: dateKey,
      checkedItems: stored.checkedItems.filter((item) => todaysTasks.includes(item)),
    }
  } catch {
    return { date: dateKey, checkedItems: [] }
  }
}

export function writeDailyChecklistState(storage, state) {
  try {
    storage?.setItem(DAILY_CHECKLIST_STORAGE_KEY, JSON.stringify(state))
  } catch {
    // The checklist remains usable for the current session if storage is unavailable.
  }
}
