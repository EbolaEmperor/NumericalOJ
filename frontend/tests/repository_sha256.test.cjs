'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const repositorySha256 = require('../public/static/app/repository/sha256.js');

function expectedDigest(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

test('repository SHA-256 fallback matches Node for representative payloads', () => {
  const payloads = [
    Buffer.alloc(0),
    Buffer.from('abc'),
    Buffer.from('中文文件名与 Windows 换行\r\n', 'utf8'),
    ...[55, 56, 63, 64, 65].map((length) =>
      Buffer.from(Array.from({ length }, (_value, index) => (index * 29) % 256))
    ),
    Buffer.from(Array.from({ length: 257 }, (_value, index) => index % 256)),
    Buffer.alloc(1024 * 1024, 0x61),
  ];

  for (const payload of payloads) {
    assert.equal(repositorySha256.digestHex(payload), expectedDigest(payload));
  }
});

test('repository SHA-256 fallback respects typed-array offsets', () => {
  const storage = Buffer.from('prefix:payload:suffix');
  const payload = storage.subarray(7, 14);

  assert.equal(repositorySha256.digestHex(payload), expectedDigest(payload));
});
