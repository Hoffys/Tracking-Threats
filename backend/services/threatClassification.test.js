import assert from 'node:assert/strict'
import test from 'node:test'

import { buildThreatClassification } from './threatClassification.js'
import { combineUrlReputation, parseUrlhausHostResponse } from './threatIntel.js'
import { scanUrl } from './urlScanner.js'

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

test('historical example.com URLhaus evidence is informational and does not change the verdict', () => {
  const hostEvidence = parseUrlhausHostResponse('example.com', {
    query_status: 'ok', url_count: '4',
    urls: [{ url: 'http://example.com/old-payload.exe', url_status: 'offline' }],
  })
  const scan = combineUrlReputation(scanUrl('https://example.com/'), [hostEvidence])
  const classification = buildThreatClassification('URL', scan)

  assert.equal(scan.status, 'Safe')
  assert.equal(scan.score, 100)
  assert.deepEqual(scan.warningSigns, [])
  assert.equal(classification.threatName, 'No threat identified')
  assert.ok(scan.details.threatIntel.some((provider) =>
    provider.evidenceType === 'historical-host-association' && /historical host evidence.*exact URL was not confirmed/i.test(provider.warning)))
})

test('active host-level URLhaus evidence retains contextual risk scoring and wording', () => {
  const hostEvidence = parseUrlhausHostResponse('example.com', {
    query_status: 'ok', url_count: '1',
    urls: [{ url: 'https://example.com/other-path.exe', url_status: 'online' }],
  })
  const scan = combineUrlReputation(scanUrl('https://example.com/'), [hostEvidence])
  const classification = buildThreatClassification('URL', scan)

  assert.equal(scan.status, 'Suspicious')
  assert.equal(scan.score, 75)
  assert.equal(scan.warningSigns.length, 1)
  assert.equal(classification.threatName, 'URLhaus host association; exact URL not confirmed.')
  assert.equal(classification.confidence, 'Low')
})

test('keeps a confirmed exact URLhaus URL match high-confidence and dangerous', () => {
  const exactMatch = {
    provider: 'URLhaus URL', checked: true, found: true,
    threat: 'malware distribution', warning: 'URLhaus lists this URL for malware distribution', deduction: 65,
  }
  const scan = combineUrlReputation(scanUrl('https://example.com/payload.exe'), [exactMatch])
  const classification = buildThreatClassification('URL', scan)

  assert.equal(scan.status, 'Dangerous')
  assert.equal(scan.action, 'Blocked')
  assert.equal(classification.threatName, 'URLhaus-listed malware source')
  assert.equal(classification.confidence, 'High')
})

test('historical URLhaus evidence does not alter independent phishing score or classification', () => {
  const hostEvidence = parseUrlhausHostResponse('example.com', {
    query_status: 'ok', url_count: '1',
    urls: [{ url: 'https://example.com/old.exe', url_status: 'offline' }],
  })
  const phishingEvidence = {
    provider: 'PhishTank', checked: true, found: true,
    warning: 'PhishTank verified this URL as an active phishing page', deduction: 60,
  }
  const scan = combineUrlReputation(scanUrl('https://example.com/'), [hostEvidence, phishingEvidence])
  const classification = buildThreatClassification('URL', scan)

  assert.equal(scan.status, 'Dangerous')
  assert.equal(scan.score, 40)
  assert.deepEqual(scan.warningSigns, [phishingEvidence.warning])
  assert.equal(classification.threatName, 'Verified phishing page')
  assert.equal(classification.confidence, 'High')
  assert.ok(scan.details.threatIntel.some((provider) => provider.provider === 'URLhaus Host' && provider.riskAffecting === false))
  assert.ok(classification.evidenceSources.includes('PhishTank'))
})
