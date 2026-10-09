import assert from 'node:assert/strict'
import test from 'node:test'
import { scanFile } from './fileScanner.js'

const sha256 = 'a'.repeat(64)

const restoreEnvironment = (name, previous) => {
  if (previous === undefined) delete process.env[name]
  else process.env[name] = previous
}

test('MalwareBazaar hash matches produce bounded high-confidence file evidence', async () => {
  const previousFetch = globalThis.fetch
  const previousMalwareBazaarKey = process.env.MALWAREBAZAAR_AUTH_KEY
  const previousMetaDefenderKey = process.env.METADEFENDER_API_KEY
  const previousVirusTotalKey = process.env.VIRUSTOTAL_API_KEY
  const previousReputationEnabled = process.env.REPUTATION_ENABLED
  process.env.MALWAREBAZAAR_AUTH_KEY = 'test-malwarebazaar-key'
  delete process.env.METADEFENDER_API_KEY
  delete process.env.VIRUSTOTAL_API_KEY
  process.env.REPUTATION_ENABLED = 'true'

  globalThis.fetch = async (url, options = {}) => {
    assert.equal(url, 'https://mb-api.abuse.ch/api/v1/')
    assert.equal(options.method, 'POST')
    assert.equal(options.headers['Auth-Key'], 'test-malwarebazaar-key')
    assert.equal(String(options.body), `query=get_info&hash=${sha256}`)
    return new Response(JSON.stringify({
      query_status: 'ok',
      data: [{
        signature: `Example RAT ${'x'.repeat(200)}`,
        tags: ['exe', 'rat'],
        file_type: 'exe',
        first_seen: '2026-10-10 00:00:00',
      }],
    }), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }

  try {
    const result = await scanFile({ fileName: 'sample.bin', size: 10, sha256 })
    const provider = result.details.threatIntel.find((item) => item.provider === 'MalwareBazaar')
    assert.equal(provider.checked, true)
    assert.equal(provider.found, true)
    assert.equal(provider.signature.length, 120)
    assert.match(provider.warning, /^MalwareBazaar lists this file hash as Example RAT/)
    assert.equal(result.status, 'Dangerous')
  } finally {
    globalThis.fetch = previousFetch
    restoreEnvironment('MALWAREBAZAAR_AUTH_KEY', previousMalwareBazaarKey)
    restoreEnvironment('METADEFENDER_API_KEY', previousMetaDefenderKey)
    restoreEnvironment('VIRUSTOTAL_API_KEY', previousVirusTotalKey)
    restoreEnvironment('REPUTATION_ENABLED', previousReputationEnabled)
  }
})

test('an unknown MalwareBazaar hash remains incomplete instead of being called safe proof', async () => {
  const previousFetch = globalThis.fetch
  const previousMalwareBazaarKey = process.env.MALWAREBAZAAR_AUTH_KEY
  const previousMetaDefenderKey = process.env.METADEFENDER_API_KEY
  const previousVirusTotalKey = process.env.VIRUSTOTAL_API_KEY
  const previousReputationEnabled = process.env.REPUTATION_ENABLED
  process.env.MALWAREBAZAAR_AUTH_KEY = 'test-malwarebazaar-key'
  delete process.env.METADEFENDER_API_KEY
  delete process.env.VIRUSTOTAL_API_KEY
  process.env.REPUTATION_ENABLED = 'true'

  globalThis.fetch = async () => new Response(
    JSON.stringify({ query_status: 'hash_not_found' }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  )

  try {
    const result = await scanFile({ fileName: 'notes.txt', size: 10, sha256 })
    const provider = result.details.threatIntel.find((item) => item.provider === 'MalwareBazaar')
    assert.equal(provider.checked, false)
    assert.equal(provider.found, false)
    assert.match(provider.skipped, /not in the provider database/i)
    assert.equal(result.details.coverage.status, 'unavailable')
    assert.match(result.details.coverage.limitations.join(' '), /not proof of safety/i)
  } finally {
    globalThis.fetch = previousFetch
    restoreEnvironment('MALWAREBAZAAR_AUTH_KEY', previousMalwareBazaarKey)
    restoreEnvironment('METADEFENDER_API_KEY', previousMetaDefenderKey)
    restoreEnvironment('VIRUSTOTAL_API_KEY', previousVirusTotalKey)
    restoreEnvironment('REPUTATION_ENABLED', previousReputationEnabled)
  }
})

test('MetaDefender multi-engine detections produce dangerous file evidence', async () => {
  const previousFetch = globalThis.fetch
  const previousMalwareBazaarKey = process.env.MALWAREBAZAAR_AUTH_KEY
  const previousMetaDefenderKey = process.env.METADEFENDER_API_KEY
  const previousVirusTotalKey = process.env.VIRUSTOTAL_API_KEY
  const previousReputationEnabled = process.env.REPUTATION_ENABLED
  delete process.env.MALWAREBAZAAR_AUTH_KEY
  process.env.METADEFENDER_API_KEY = 'test-metadefender-key'
  delete process.env.VIRUSTOTAL_API_KEY
  process.env.REPUTATION_ENABLED = 'true'

  globalThis.fetch = async (url, options = {}) => {
    assert.equal(url, `https://api.metadefender.com/v4/hash/${sha256}`)
    assert.equal(options.headers.apikey, 'test-metadefender-key')
    return new Response(JSON.stringify({
      scan_results: {
        scan_all_result_i: 1,
        total_detected_avs: 7,
        total_avs: 25,
      },
    }), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }

  try {
    const result = await scanFile({ fileName: 'sample.bin', size: 10, sha256 })
    const provider = result.details.threatIntel.find((item) => item.provider === 'MetaDefender Cloud')
    assert.equal(provider.checked, true)
    assert.equal(provider.found, true)
    assert.equal(provider.detectedEngines, 7)
    assert.equal(provider.totalEngines, 25)
    assert.match(provider.warning, /7 of 25 anti-malware engines detected/i)
    assert.equal(result.status, 'Dangerous')
  } finally {
    globalThis.fetch = previousFetch
    restoreEnvironment('MALWAREBAZAAR_AUTH_KEY', previousMalwareBazaarKey)
    restoreEnvironment('METADEFENDER_API_KEY', previousMetaDefenderKey)
    restoreEnvironment('VIRUSTOTAL_API_KEY', previousVirusTotalKey)
    restoreEnvironment('REPUTATION_ENABLED', previousReputationEnabled)
  }
})

test('an unknown MetaDefender hash remains incomplete instead of being called clean', async () => {
  const previousFetch = globalThis.fetch
  const previousMalwareBazaarKey = process.env.MALWAREBAZAAR_AUTH_KEY
  const previousMetaDefenderKey = process.env.METADEFENDER_API_KEY
  const previousVirusTotalKey = process.env.VIRUSTOTAL_API_KEY
  const previousReputationEnabled = process.env.REPUTATION_ENABLED
  delete process.env.MALWAREBAZAAR_AUTH_KEY
  process.env.METADEFENDER_API_KEY = 'test-metadefender-key'
  delete process.env.VIRUSTOTAL_API_KEY
  process.env.REPUTATION_ENABLED = 'true'

  globalThis.fetch = async () => new Response(null, { status: 404 })

  try {
    const result = await scanFile({ fileName: 'notes.txt', size: 10, sha256 })
    const provider = result.details.threatIntel.find((item) => item.provider === 'MetaDefender Cloud')
    assert.equal(provider.checked, false)
    assert.equal(provider.found, false)
    assert.match(provider.skipped, /not in the provider database/i)
    assert.equal(result.details.coverage.status, 'unavailable')
  } finally {
    globalThis.fetch = previousFetch
    restoreEnvironment('MALWAREBAZAAR_AUTH_KEY', previousMalwareBazaarKey)
    restoreEnvironment('METADEFENDER_API_KEY', previousMetaDefenderKey)
    restoreEnvironment('VIRUSTOTAL_API_KEY', previousVirusTotalKey)
    restoreEnvironment('REPUTATION_ENABLED', previousReputationEnabled)
  }
})
