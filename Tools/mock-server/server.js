#!/usr/bin/env node
/**
 * 设备指纹 SDK 的本地联调服务（零依赖，仅用 Node 内置模块）。
 *
 * 用途：在没有真实后端时，完整模拟 `/fingerprint/init` 与 `/fingerprint/generate`，
 * 并真正执行服务端侧的校验：HMAC-SHA256 验签、RSA-OAEP-SHA256 解出 AES 密钥、
 * AES-256-GCM 解密 rawData、时间戳窗口检查、nonce 一次性防重放。
 *
 * 启动：
 *   node Tools/mock-server/server.js
 *   APP_ID=your-app-id PORT=8080 node Tools/mock-server/server.js
 *
 * SDK 配置：
 *   模拟器：FingerprintSDK.configure(appId: "demo-app-id", baseURL: "http://127.0.0.1:8080")
 *   真机：  baseURL 换成 Mac 的局域网地址，如 "http://192.168.1.10:8080"，
 *          并在宿主 App 的 Info.plist 加 ATS 例外（仅调试用）。
 *
 * 注意：仅供本地调试，切勿用于生产（会话只存在内存、无鉴权、日志会打印解密字段）。
 */

const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 8080);
const APP_ID = process.env.APP_ID || 'demo-app-id';
const SESSION_TTL_MS = 5 * 60 * 1000;
const CLOCK_SKEW_MS = 5 * 60 * 1000;

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

/** tempId -> { nonce, sessionToken, expiresAt, used } */
const sessions = new Map();
/** 指纹键 -> deviceId，保证同一设备多次上报得到同一 ID */
const devices = new Map();

const log = (...args) => console.log(`[${new Date().toISOString()}]`, ...args);

function sendJSON(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body)
  });
  res.end(body);
}

function readJSON(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 1024 * 1024) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch (error) {
        reject(new Error('invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function timingSafeEqualHex(expectedHex, actualHex) {
  const expected = Buffer.from(expectedHex, 'utf8');
  const actual = Buffer.from(String(actualHex || '').toLowerCase(), 'utf8');
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function stringToSign({ timestamp, tempId, nonce, encryptedAesKey, encryptedData }) {
  return `${timestamp}|${tempId}|${nonce}|${encryptedAesKey}|${encryptedData}`;
}

function decryptRawData(encryptedAesKey, encryptedData) {
  const aesKey = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    Buffer.from(encryptedAesKey, 'base64')
  );

  const combined = Buffer.from(encryptedData, 'base64');
  if (combined.length <= 12 + 16) {
    throw new Error('encryptedData too short');
  }

  const iv = combined.subarray(0, 12);
  const ciphertext = combined.subarray(12, combined.length - 16);
  const tag = combined.subarray(combined.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// ---------------------------------------------------------------------------
// Step 1: POST /fingerprint/init
// ---------------------------------------------------------------------------
function handleInit(req, res, body) {
  if (body.appId !== APP_ID) {
    log(`init rejected: appId mismatch (got ${JSON.stringify(body.appId)})`);
    return sendJSON(res, 403, { error: 'unknown appId' });
  }
  if (!body.tempId || !body.bundleId) {
    return sendJSON(res, 400, { error: 'tempId and bundleId are required' });
  }

  const nonce = crypto.randomBytes(16).toString('hex');
  const sessionToken = crypto.randomBytes(32).toString('hex');

  sessions.set(body.tempId, {
    nonce,
    sessionToken,
    expiresAt: Date.now() + SESSION_TTL_MS,
    used: false
  });

  log(`init ok: bundleId=${body.bundleId} tempId=${body.tempId} nonce=${nonce.slice(0, 8)}…`);

  sendJSON(res, 200, {
    nonce,
    sessionToken,
    rsaPublicKey: publicKey,
    serverTimestamp: Date.now()
  });
}

// ---------------------------------------------------------------------------
// Step 4: POST /fingerprint/generate
// ---------------------------------------------------------------------------
function handleGenerate(req, res, body) {
  const session = sessions.get(body.tempId);
  if (!session) {
    return sendJSON(res, 404, { error: 'unknown or expired session' });
  }
  if (session.used) {
    log(`generate rejected: replay detected for tempId=${body.tempId}`);
    return sendJSON(res, 409, { error: 'session already used' });
  }
  if (Date.now() > session.expiresAt) {
    sessions.delete(body.tempId);
    return sendJSON(res, 410, { error: 'session expired' });
  }
  if (body.nonce !== session.nonce) {
    return sendJSON(res, 400, { error: 'nonce mismatch' });
  }
  if (Math.abs(Number(body.timestamp) - Date.now()) > CLOCK_SKEW_MS) {
    return sendJSON(res, 400, { error: 'timestamp out of allowed window' });
  }

  const message = stringToSign(body);
  const expectedSignature = crypto
    .createHmac('sha256', Buffer.from(session.sessionToken, 'utf8'))
    .update(Buffer.from(message, 'utf8'))
    .digest('hex');

  if (!timingSafeEqualHex(expectedSignature, body.signature)) {
    log('generate rejected: bad signature');
    return sendJSON(res, 401, { error: 'invalid signature' });
  }

  let raw;
  try {
    raw = JSON.parse(decryptRawData(body.encryptedAesKey, body.encryptedData).toString('utf8'));
  } catch (error) {
    log(`generate rejected: decryption failed (${error.message})`);
    return sendJSON(res, 400, { error: 'decrypt failed' });
  }

  session.used = true;

  const fingerprintKey = `${raw.clientAnchorId || ''}|${raw.idfv || ''}`;
  let deviceId = devices.get(fingerprintKey);
  if (!deviceId) {
    deviceId = 'dev_' + crypto.createHash('sha256').update(fingerprintKey).digest('hex').slice(0, 24);
    devices.set(fingerprintKey, deviceId);
  }

  log(`generate ok: signature verified, deviceId=${deviceId}`);
  log('  decrypted rawData:', JSON.stringify(raw));

  sendJSON(res, 200, { deviceId, success: true });
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);

    if (req.method === 'GET' && url.pathname === '/health') {
      return sendJSON(res, 200, { ok: true, appId: APP_ID, now: Date.now() });
    }

    if (req.method !== 'POST') {
      return sendJSON(res, 404, { error: 'not found' });
    }

    const body = await readJSON(req);

    if (url.pathname === '/fingerprint/init') {
      return handleInit(req, res, body);
    }
    if (url.pathname === '/fingerprint/generate') {
      return handleGenerate(req, res, body);
    }
    return sendJSON(res, 404, { error: 'not found' });
  } catch (error) {
    log('request failed:', error.message);
    if (!res.headersSent) {
      sendJSON(res, 400, { error: error.message });
    }
  }
});

server.listen(PORT, '0.0.0.0', () => {
  log(`mock fingerprint server listening on http://0.0.0.0:${PORT}`);
  log(`appId = ${APP_ID}（SDK configure 时需保持一致）`);
  log('endpoints: POST /fingerprint/init, POST /fingerprint/generate, GET /health');
});
