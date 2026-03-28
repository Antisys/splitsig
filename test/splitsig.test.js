import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { deriveKey, derivePublicKey, verify, generateNonce } from '../dist/index.js';

const SIG = '3045022100a3f3c5e7b2d8f1a9c4e6b0d7f2a8e5c1b3d9f0a7c2e4d6b8a0f1c3e5d7a9b2022054e8c1a3f5d7b9e0c2a4f6d8b0e3c5a7f9d1b3e5c7a9f0d2b4e6c8a0f2d4e6b8';
const NONCE = 'deadbeef01020304050607080910111213141516171819202122232425262728';
const EXPECTED_PRIVKEY = '41373b36f9b4620864580f290b2fa1da0f0fa7293d34feff5047969051196bf7';

describe('deriveKey', () => {
  it('derives the correct private key from test vectors', () => {
    const key = deriveKey(SIG, NONCE);
    assert.equal(key.privateKey, EXPECTED_PRIVKEY);
  });

  it('returns 32-byte x-only pubkey', () => {
    const key = deriveKey(SIG, NONCE);
    assert.equal(key.publicKeyXOnly.length, 64); // 32 bytes hex
  });

  it('returns 33-byte compressed pubkey', () => {
    const key = deriveKey(SIG, NONCE);
    assert.equal(key.publicKey.length, 66); // 33 bytes hex
    assert.ok(key.publicKey.startsWith('02') || key.publicKey.startsWith('03'));
  });

  it('is deterministic', () => {
    const a = deriveKey(SIG, NONCE);
    const b = deriveKey(SIG, NONCE);
    assert.equal(a.privateKey, b.privateKey);
    assert.equal(a.publicKeyXOnly, b.publicKeyXOnly);
  });
});

describe('split knowledge', () => {
  it('signature alone produces a different key', () => {
    const withNonce = deriveKey(SIG, NONCE);
    const zeroNonce = deriveKey(SIG, '0000000000000000000000000000000000000000000000000000000000000000');
    assert.notEqual(withNonce.privateKey, zeroNonce.privateKey);
  });

  it('different nonce produces a different key', () => {
    const a = deriveKey(SIG, NONCE);
    const b = deriveKey(SIG, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    assert.notEqual(a.privateKey, b.privateKey);
  });

  it('different signature produces a different key', () => {
    const a = deriveKey(SIG, NONCE);
    const b = deriveKey('3045022100' + 'ff'.repeat(32) + '0220' + 'ee'.repeat(32), NONCE);
    assert.notEqual(a.privateKey, b.privateKey);
  });
});

describe('verify', () => {
  it('returns true for matching inputs', () => {
    const key = deriveKey(SIG, NONCE);
    assert.ok(verify(SIG, NONCE, key.publicKeyXOnly));
  });

  it('returns false for wrong nonce', () => {
    const key = deriveKey(SIG, NONCE);
    assert.ok(!verify(SIG, 'ff'.repeat(32), key.publicKeyXOnly));
  });
});

describe('derivePublicKey', () => {
  it('matches deriveKey().publicKeyXOnly', () => {
    const pub = derivePublicKey(SIG, NONCE);
    const key = deriveKey(SIG, NONCE);
    assert.equal(pub, key.publicKeyXOnly);
  });
});

describe('generateNonce', () => {
  it('returns 64-char hex string (32 bytes)', () => {
    const nonce = generateNonce();
    assert.equal(nonce.length, 64);
    assert.match(nonce, /^[0-9a-f]{64}$/);
  });

  it('produces unique values', () => {
    const a = generateNonce();
    const b = generateNonce();
    assert.notEqual(a, b);
  });
});
