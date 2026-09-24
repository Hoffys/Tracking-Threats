import assert from 'node:assert/strict'
import test from 'node:test'
import { inflateRawSync } from 'node:zlib'
import { getExtensionPackage } from './extensionPackage.js'

test('download ZIP contains runnable extension assets and excludes private files', async () => {
  const archive = await getExtensionPackage()
  const entries = new Map()
  let offset = 0
  while (archive.readUInt32LE(offset) === 0x04034b50) {
    const size = archive.readUInt32LE(offset + 18)
    const length = archive.readUInt16LE(offset + 26)
    const name = archive.subarray(offset + 30, offset + 30 + length).toString()
    const data = inflateRawSync(archive.subarray(offset + 30 + length, offset + 30 + length + size))
    assert.equal(data.length, archive.readUInt32LE(offset + 22))
    entries.set(name.replace('tracking-threats-extension/', ''), data)
    offset += 30 + length + size
  }
  const manifest = JSON.parse(entries.get('manifest.json'))
  const needed = [manifest.background.service_worker, manifest.action.default_popup,
    ...Object.values(manifest.icons), ...manifest.content_scripts.flatMap((script) => script.js),
    ...manifest.web_accessible_resources.flatMap((resource) => resource.resources),
    ...manifest.declarative_net_request.rule_resources.map((rule) => rule.path), 'popup.js', 'INSTALL.txt']
  needed.forEach((file) => assert.ok(entries.has(file), `Missing ${file}`))
  assert.equal(manifest.version, '1.0.26')
  assert.ok(manifest.permissions.includes('alarms'))
  assert.ok([...entries.keys()].every((name) => !/\.env|_metadata|\.test\.|sqlite/.test(name)))
  assert.match(entries.get('config.js').toString(), /tracking-threats-production.up.railway.app/)
  assert.equal(archive.readUInt32LE(archive.length - 22), 0x06054b50)
  assert.equal(archive.readUInt16LE(archive.length - 12), entries.size)
})
