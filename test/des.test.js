'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { DesUtil, encrypt, decrypt } = require('../src/utils/des');

const KEY = Buffer.from('0123456789ABCDEF', 'hex');
const IV = Buffer.from('1234567890ABCDEF', 'hex');

test('matches the classic DES ECB test vector', () => {
  const key = Buffer.from('133457799BBCDFF1', 'hex');
  const ciphertext = DesUtil.encrypt(Buffer.from('0123456789ABCDEF', 'hex'), key, {
    mode: 'ecb',
    padding: 'none',
    outputEncoding: 'hex',
  });
  assert.equal(ciphertext, '85e813540f0ab405');
});

test('matches an independently generated DES CBC vector', () => {
  const plaintext = 'The quick brown fox jumps over the lazy dog';
  const ciphertext = encrypt(plaintext, KEY, { iv: IV, outputEncoding: 'hex' });

  assert.equal(
    ciphertext,
    '33d21ca3eebde709ec40331bc453d5f8b193481acff2385f563fd2050dad667c' +
      '2495d7db6418790deb72a308dd0096e5',
  );
  assert.equal(decrypt(ciphertext, KEY, { iv: IV, inputEncoding: 'hex' }), plaintext);
});

test('round-trips UTF-8 text and matches the reference Base64 value', () => {
  const key = '12345678';
  const iv = '87654321';
  const plaintext = '你好，DES 加密工具类！';

  assert.equal(encrypt(plaintext, key, { iv }), 'uWwdcCpHqfDCCLe2kx28ik3ib9BMj4FSGg69Ae2d3jE=');
  assert.equal(decrypt('uWwdcCpHqfDCCLe2kx28ik3ib9BMj4FSGg69Ae2d3jE=', key, { iv }), plaintext);
});

test('handles empty plaintext', () => {
  assert.equal(encrypt('', '12345678', { iv: '87654321' }), 'zazGg9qwr7w=');
  assert.equal(decrypt('zazGg9qwr7w=', '12345678', { iv: '87654321' }), '');
});

test('supports ECB mode and Base64 output by default', () => {
  const ciphertext = encrypt('hello DES', '12345678', { mode: 'ecb' });
  assert.equal(ciphertext, 'gClLwyF2IXAAcrmFd3hwiA==');
  assert.equal(decrypt(ciphertext, '12345678', { mode: 'ecb' }), 'hello DES');
});

test('supports hex output and Buffer input', () => {
  const ciphertext = encrypt(Buffer.from('hex output'), '12345678', {
    mode: 'ecb',
    outputEncoding: 'hex',
  });
  assert.match(ciphertext, /^[0-9a-f]{32}$/);
  assert.equal(decrypt(ciphertext, '12345678', { mode: 'ecb', inputEncoding: 'hex' }), 'hex output');
});

test('CBC is the default mode', () => {
  const implicit = encrypt('default mode', '12345678', { iv: '87654321' });
  const explicit = encrypt('default mode', '12345678', { mode: 'cbc', iv: '87654321' });
  assert.equal(implicit, explicit);
});

test('rejects keys and IVs that are not 8 bytes', () => {
  assert.throws(() => encrypt('data', 'short', { iv: '87654321' }), RangeError);
  assert.throws(() => encrypt('data', '123456789', { iv: '87654321' }), RangeError);
  assert.throws(() => encrypt('data', '12345678', { iv: 'short' }), RangeError);
  assert.throws(() => encrypt('data', 12345678, { iv: '87654321' }), TypeError);
});

test('requires an IV in CBC mode', () => {
  assert.throws(() => encrypt('data', '12345678'), /iv is required/);
});

test('rejects unsupported options', () => {
  assert.throws(() => encrypt('data', '12345678', { iv: '87654321', mode: 'ctr' }), RangeError);
  assert.throws(() => encrypt('data', '12345678', { iv: '87654321', padding: 'zero' }), RangeError);
  assert.throws(
    () => encrypt('data', '12345678', { mode: 'ecb', outputEncoding: 'utf8' }),
    RangeError,
  );
});

test('rejects plaintext that is not block-aligned without padding', () => {
  assert.throws(
    () => encrypt('abc', '12345678', { mode: 'ecb', padding: 'none' }),
    RangeError,
  );
});

test('rejects malformed ciphertext', () => {
  assert.throws(() => decrypt('not base64!', '12345678', { iv: '87654321' }), RangeError);
  assert.throws(() => decrypt('abc', '12345678', { iv: '87654321' }), RangeError);
  assert.throws(
    () => decrypt('0011', '12345678', { iv: '87654321', inputEncoding: 'hex' }),
    RangeError,
  );
});

test('rejects invalid PKCS#7 padding on decrypt', () => {
  const ciphertext = encrypt(Buffer.alloc(8), '12345678', {
    iv: '87654321',
    padding: 'none',
  });
  assert.throws(() => decrypt(ciphertext, '12345678', { iv: '87654321' }), /decryption failed/);
});
