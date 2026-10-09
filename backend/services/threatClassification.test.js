import assert from 'node:assert/strict'
import test from 'node:test'

import { buildThreatClassification } from './threatClassification.js'

test('classifies local phishing evidence as suspected rather than confirmed', () => {
  const classification = buildThreatClassification('URL', {
    status: 'Dangerous', summary: 'Found warning signs.',
    warningSigns: ['Possible paypal impersonation on an unrelated registrable domain'],
    details: { categories: ['phishing-indicators'], findings: [{ code: 'brand-impersonation', deduction: 40 }] },
  })

  assert.equal(classification.threatName, 'Suspected credential phishing page')
  assert.equal(classification.threatType, 'Phishing / credential theft')
  assert.equal(classification.confidence, 'Medium')
  assert.deepEqual(classification.evidenceSources, ['URL and page rules'])
})

test('uses verified provider evidence for high-confidence threat names', () => {
  const classification = buildThreatClassification('URL', {
    status: 'Dangerous', warningSigns: ['PhishTank verified this URL as an active phishing page'],
    details: { threatIntel: [{ provider: 'PhishTank', checked: true, found: true, warning: 'PhishTank verified this URL as an active phishing page' }] },
  })

  assert.equal(classification.threatName, 'Verified phishing page')
  assert.equal(classification.confidence, 'High')
  assert.deepEqual(classification.evidenceSources, ['PhishTank'])
})

test('keeps piracy classification separate from a malware verdict', () => {
  const classification = buildThreatClassification('URL', {
    status: 'Safe', summary: 'No strong phishing indicators.', warningSigns: [],
    details: { categories: ['piracy-content'], categoryWarnings: [{ category: 'piracy-content', label: 'Contains piracy-related references; this is not a phishing determination.' }] },
  })

  assert.equal(classification.threatName, 'Piracy-related content warning')
  assert.equal(classification.threatType, 'Content and download risk')
  assert.equal(classification.confidence, 'Informational')
  assert.match(classification.whyDetected[0], /not a phishing determination/i)
})

test('does not invent an exact malware family from VirusTotal counts', () => {
  const classification = buildThreatClassification('File', {
    status: 'Dangerous', warningSigns: ['VirusTotal reports 4 malicious engine detections for this file hash'],
    details: { categories: ['file-risk'], threatIntel: [{ provider: 'VirusTotal File', checked: true, found: true, stats: { malicious: 4 }, warning: 'VirusTotal reports 4 malicious engine detections for this file hash' }] },
  })

  assert.equal(classification.threatName, 'Malicious file hash')
  assert.equal(classification.threatType, 'Malware / file reputation')
  assert.equal(classification.confidence, 'High')
})

test('treats a MalwareBazaar match as known malware without asserting its family', () => {
  const classification = buildThreatClassification('File', {
    status: 'Dangerous', warningSigns: ['MalwareBazaar lists this file hash as Example RAT'],
    details: { categories: ['file-risk'], threatIntel: [{ provider: 'MalwareBazaar', checked: true, found: true, signature: 'Example RAT', warning: 'MalwareBazaar lists this file hash as Example RAT' }] },
  })

  assert.equal(classification.threatName, 'Known malware file hash')
  assert.equal(classification.threatType, 'Malware / file reputation')
  assert.equal(classification.confidence, 'High')
  assert.deepEqual(classification.evidenceSources, ['MalwareBazaar'])
})

test('uses MetaDefender detection counts without inventing a malware family', () => {
  const classification = buildThreatClassification('File', {
    status: 'Dangerous', warningSigns: ['MetaDefender reports 7 of 25 anti-malware engines detected this file hash'],
    details: { categories: ['file-risk'], threatIntel: [{ provider: 'MetaDefender Cloud', checked: true, found: true, resultCode: 1, detectedEngines: 7, totalEngines: 25, warning: 'MetaDefender reports 7 of 25 anti-malware engines detected this file hash' }] },
  })

  assert.equal(classification.threatName, 'Malicious file reputation')
  assert.equal(classification.threatType, 'Malware / file reputation')
  assert.equal(classification.confidence, 'High')
  assert.deepEqual(classification.evidenceSources, ['MetaDefender Cloud'])
})

test('returns a qualified no-threat result for a safe scan', () => {
  const classification = buildThreatClassification('Message', {
    status: 'Safe', summary: 'No strong local message phishing indicators were found.', warningSigns: [],
    details: { categories: [], threatIntel: [] },
  })

  assert.equal(classification.threatName, 'No threat identified')
  assert.equal(classification.threatType, 'None detected')
  assert.equal(classification.confidence, 'No threat detected')
})
