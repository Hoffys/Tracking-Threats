import { readFile } from 'node:fs/promises'
import { deflateRawSync } from 'node:zlib'

// Explicit release files: never package local metadata, credentials, or test fixtures.
const files = [
  'manifest.json', 'config.js', 'background.js', 'app-bridge.js',
  'google-results.js', 'email-monitor.js', 'popup.html', 'popup.js',
  'blocked.html', 'blocked.js', 'INSTALL.txt',
  'icons/icon-16.png', 'icons/icon-32.png', 'icons/icon-48.png', 'icons/icon-128.png',
  'rules/adblock-rules.json',
]

const crc32 = (data) => {
  let crc = 0xffffffff
  for (const byte of data) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0)
  }
  return (crc ^ 0xffffffff) >>> 0
}

let packagePromise
export function getExtensionPackage() {
  if (!packagePromise) packagePromise = (async () => {
    const localParts = []
    const directory = []
    let offset = 0
    for (const file of files) {
      const data = await readFile(new URL(`../../browser-extension/${file}`, import.meta.url))
      const compressed = deflateRawSync(data)
      const name = Buffer.from(`tracking-threats-extension/${file}`)
      const checksum = crc32(data)
      const header = Buffer.alloc(30)
      header.writeUInt32LE(0x04034b50, 0)
      header.writeUInt16LE(20, 4)
      header.writeUInt16LE(8, 8)
      header.writeUInt16LE(0x5c21, 12) // January 1, 2026
      header.writeUInt32LE(checksum, 14)
      header.writeUInt32LE(compressed.length, 18)
      header.writeUInt32LE(data.length, 22)
      header.writeUInt16LE(name.length, 26)
      localParts.push(header, name, compressed)
      const central = Buffer.alloc(46)
      central.writeUInt32LE(0x02014b50, 0)
      central.writeUInt16LE(20, 4)
      header.copy(central, 6, 4, 30)
      central.writeUInt32LE(offset, 42)
      directory.push(central, name)
      offset += header.length + name.length + compressed.length
    }
    const centralData = Buffer.concat(directory)
    const end = Buffer.alloc(22)
    end.writeUInt32LE(0x06054b50, 0)
    end.writeUInt16LE(files.length, 8)
    end.writeUInt16LE(files.length, 10)
    end.writeUInt32LE(centralData.length, 12)
    end.writeUInt32LE(offset, 16)
    return Buffer.concat([...localParts, centralData, end])
  })().catch((error) => { packagePromise = null; throw error })
  return packagePromise
}
