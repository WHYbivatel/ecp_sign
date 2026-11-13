// Runs native-host/tegin_token_host.py as a child process and exposes it with the runtime.Port shape the extension's
// TokenClient expects, using the Native Messaging framing (32-bit little-endian length, then UTF-8 JSON).
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';

export function spawnTokenHost(env) {
  const child = spawn(process.platform === 'win32' ? 'python' : 'python3', [resolve('native-host/tegin_token_host.py')], { env, stdio: ['pipe', 'pipe', 'pipe'] });
  const listeners = { message: [], disconnect: [] }, frames = [];
  let buffer = Buffer.alloc(0), log = '';
  child.stdout.on('data', chunk => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length >= 4 && buffer.length >= 4 + buffer.readUInt32LE(0)) {
      const message = JSON.parse(buffer.subarray(4, 4 + buffer.readUInt32LE(0)).toString('utf8'));
      buffer = buffer.subarray(4 + buffer.readUInt32LE(0));
      frames.push(message); listeners.message.forEach(fn => fn(message));
    }
  });
  child.stderr.on('data', chunk => { log += chunk; });
  child.on('exit', () => listeners.disconnect.forEach(fn => fn()));
  const sent = [];
  return {
    frames, sent, log: () => log,
    postMessage(message) { sent.push(JSON.stringify(message)); const body = Buffer.from(JSON.stringify(message)); const header = Buffer.alloc(4); header.writeUInt32LE(body.length); child.stdin.write(Buffer.concat([header, body])); },
    onMessage: { addListener: fn => listeners.message.push(fn) },
    onDisconnect: { addListener: fn => listeners.disconnect.push(fn) },
    disconnect() { child.stdin.end(); },
    exited: new Promise(done => child.on('exit', done))
  };
}
