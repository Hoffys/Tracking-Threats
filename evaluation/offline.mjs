// Install before dynamically importing scanners. Prevent accidental network/provider
// usage, subprocesses and workers. This is an evaluation guard, not a hostile-code sandbox.
import http from 'node:http'
import https from 'node:https'
import http2 from 'node:http2'
import net from 'node:net'
import tls from 'node:tls'
import dns from 'node:dns'
import dgram from 'node:dgram'
import childProcess from 'node:child_process'
import workers from 'node:worker_threads'
import { syncBuiltinESMExports } from 'node:module'
import { EvaluationError } from './dataset.mjs'

export function disableNetwork() {
  function denied() { throw new EvaluationError('Offline evaluation forbids network, subprocess and worker access') }
  for (const [module, names] of [
    [http, ['request', 'get', 'createServer']], [https, ['request', 'get', 'createServer']],
    [http2, ['connect', 'createServer', 'createSecureServer']],
    [net, ['connect', 'createConnection', 'createServer']], [tls, ['connect', 'createServer']],
    [dgram, ['createSocket']],
    [childProcess, ['exec', 'execSync', 'execFile', 'execFileSync', 'fork', 'spawn', 'spawnSync']],
    [workers, ['Worker']],
  ]) for (const name of names) module[name] = denied
  net.Socket.prototype.connect = denied
  net.Server.prototype.listen = denied
  for (const module of [dns, dns.promises]) {
    for (const name of Object.keys(module)) if (/^(lookup|resolve|reverse)/.test(name) && typeof module[name] === 'function') module[name] = denied
    for (const name of Object.getOwnPropertyNames(module.Resolver.prototype)) if (/^(resolve|reverse)/.test(name)) module.Resolver.prototype[name] = denied
  }
  globalThis.fetch = denied
  globalThis.WebSocket = denied
  globalThis.EventSource = denied
  syncBuiltinESMExports()
}
