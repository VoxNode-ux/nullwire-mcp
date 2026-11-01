#!/usr/bin/env node
'use strict';

// Thin launcher for the NullWire-MCP binary. It has no dependencies and no
// install script: on first run it downloads the binary for this platform from
// the project's GitHub release, checks it against the release's SHA256SUMS.txt
// (and refuses to run it if the check fails), keeps it in a cache folder, and
// then starts it with the same arguments and the same stdin/stdout, so it works
// as an MCP stdio server.
//
//   npx -y nullwire-mcp                         run the server
//   npx -y nullwire-mcp install --client all    register it with your MCP clients
//   npx -y nullwire-mcp --nullwire-prefetch     only download the binary
//
// Environment: NULLWIRE_VERSION (release tag), NULLWIRE_BASE_URL (mirror),
// NULLWIRE_CACHE_DIR (where the binary is kept).

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { spawn } = require('child_process');

const pkg = require('../package.json');
const REPO = 'VoxNode-ux/nullwire-mcp';
const RELEASE = process.env.NULLWIRE_VERSION || pkg.nullwireRelease || `v${pkg.version}`;
const BASE_URL = (process.env.NULLWIRE_BASE_URL ||
  `https://github.com/${REPO}/releases/download/${RELEASE}`).replace(/\/+$/, '');

function log(msg) {
  process.stderr.write(`nullwire-mcp: ${msg}\n`); // never stdout: that is the MCP channel
}

function fail(msg) {
  log(msg);
  process.exit(1);
}

function assetName() {
  const platform = process.platform === 'android' ? 'linux' : process.platform; // Termux
  const osName = { linux: 'linux', darwin: 'darwin', win32: 'windows' }[platform];
  let cpu = { x64: 'amd64', arm64: 'arm64' }[process.arch];
  if (osName === 'windows') cpu = 'amd64'; // Windows on ARM runs the x64 build
  if (!osName || !cpu) {
    fail(`no prebuilt binary for ${process.platform}/${process.arch}. Build from source: https://github.com/${REPO}`);
  }
  return `nullwire-${osName}-${cpu}${osName === 'windows' ? '.exe' : ''}`;
}

function cacheDir() {
  if (process.env.NULLWIRE_CACHE_DIR) return process.env.NULLWIRE_CACHE_DIR;
  let base;
  if (process.platform === 'win32') {
    base = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
  } else if (process.platform === 'darwin') {
    base = path.join(os.homedir(), 'Library', 'Caches');
  } else {
    base = process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
  }
  return path.join(base, 'nullwire-mcp', RELEASE.replace(/[^\w.-]/g, '_'));
}

function get(url, redirects) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error('too many redirects'));
    const lib = url.startsWith('https:') ? https : url.startsWith('http:') ? http : null;
    if (!lib) return reject(new Error(`unsupported URL: ${url}`));
    const req = lib.get(url, { headers: { 'User-Agent': 'nullwire-mcp-npm' } }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        return resolve(get(new URL(res.headers.location, url).toString(), redirects + 1));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`${url} answered HTTP ${res.statusCode}`));
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.setTimeout(60000, () => req.destroy(new Error(`timed out fetching ${url}`)));
    req.on('error', reject);
  });
}

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function expectedHash(sums, asset) {
  for (const line of sums.split(/\r?\n/)) {
    const m = /^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$/.exec(line);
    if (m && m[2] === asset) return m[1].toLowerCase();
  }
  return null;
}

async function ensureBinary() {
  const asset = assetName();
  const dir = cacheDir();
  const bin = path.join(dir, asset);
  const sidecar = `${bin}.sha256`;

  // A cached copy is used only if it still matches the hash recorded when it was verified.
  try {
    const want = fs.readFileSync(sidecar, 'utf8').trim();
    if (sha256(fs.readFileSync(bin)) === want) return bin;
    log('the cached binary does not match its recorded checksum; downloading it again');
  } catch (_) { /* not cached yet */ }

  log(`downloading ${asset} (${RELEASE})`);
  let data;
  let sums;
  try {
    [data, sums] = await Promise.all([get(`${BASE_URL}/${asset}`, 0), get(`${BASE_URL}/SHA256SUMS.txt`, 0)]);
  } catch (err) {
    fail(`download failed: ${err.message}`);
  }
  const want = expectedHash(sums.toString('utf8'), asset);
  if (!want) fail(`SHA256SUMS.txt has no entry for ${asset}`);
  const got = sha256(data);
  if (got !== want) fail(`checksum mismatch for ${asset} (expected ${want}, got ${got}); not running it`);

  fs.mkdirSync(dir, { recursive: true });
  const tmp = `${bin}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, data, { mode: 0o755 });
  fs.renameSync(tmp, bin);
  fs.writeFileSync(sidecar, `${got}\n`);
  log('checksum OK');
  return bin;
}

async function main() {
  const args = process.argv.slice(2);
  const bin = await ensureBinary();
  if (args[0] === '--nullwire-prefetch') {
    log(`ready: ${bin}`);
    return;
  }
  const child = spawn(bin, args, {
    stdio: 'inherit',
    windowsHide: true,
    env: Object.assign({}, process.env, { NULLWIRE_VIA_NPM: '1' }),
  });
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(sig, () => { try { child.kill(sig); } catch (_) { /* already gone */ } });
  }
  child.on('error', (err) => fail(`could not start ${bin}: ${err.message}`));
  child.on('exit', (code, signal) => {
    if (signal) process.kill(process.pid, signal);
    else process.exit(code === null ? 1 : code);
  });
}

main().catch((err) => fail(err && err.message ? err.message : String(err)));
