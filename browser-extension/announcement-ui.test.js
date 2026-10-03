import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const html = readFileSync(new URL('./popup.html', import.meta.url), 'utf8')
const script = readFileSync(new URL('./popup.js', import.meta.url), 'utf8')

test('extension popup exposes a safe announcement panel and official update action', () => {
  assert.match(html, /id="announcementButton"/)
  assert.match(html, /id="announcementBadge"/)
  assert.match(html, /id="announcementPanel"/)
  assert.match(script, /\/api\/public\/announcements\?version=/)
  assert.match(script, /\/api\/public\/extension\/download/)
  assert.match(script, /chrome\.runtime\.getManifest\(\)\.version/)
  assert.match(script, /trackingThreatsReadAnnouncements/)
  assert.doesNotMatch(script, /innerHTML/)
})
