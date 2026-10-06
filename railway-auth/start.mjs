import { spawn } from 'node:child_process';
import net from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { readConfig, createGateway } from './gateway.mjs';

const config = readConfig();
if (!process.env.APP_ID || !process.env.APP_SECRET) throw new Error('Lark credentials are required');
if (process.env.USER_ACCESS_TOKEN) throw new Error('Remove USER_ACCESS_TOKEN: this deployment uses the application identity');
let isReady = false;
const server = createGateway(config, { ready: () => isReady });
server.listen(config.port, '0.0.0.0', () => console.log('Protected Lark MCP gateway listening'));
const child = spawn('lark-mcp', ['mcp', '-m', 'streamable', '--host', '127.0.0.1', '-p', String(config.upstreamPort),
  '--token-mode', 'tenant_access_token'], { env: process.env, stdio: ['ignore', 'inherit', 'inherit'] });
let stopping = false;
function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  isReady = false;
  child.kill('SIGTERM');
  server.close(() => process.exit(code));
  setTimeout(() => process.exit(code), 5000).unref();
}
child.on('error', () => stop(1));
child.on('exit', code => stop(code || 1));
server.on('error', () => stop(1));
process.on('SIGTERM', () => stop());
process.on('SIGINT', () => stop());
for (let attempt = 0; attempt < 120 && !stopping; attempt++) {
  isReady = await new Promise(resolve => {
    const socket = net.connect(config.upstreamPort, '127.0.0.1');
    socket.setTimeout(500);
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', () => resolve(false));
    socket.once('timeout', () => { socket.destroy(); resolve(false); });
  });
  if (isReady) break;
  await delay(500);
}
if (!isReady && !stopping) stop(1);
