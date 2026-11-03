'use strict';

const crypto = require('node:crypto');

const BLOCK_SIZE = 8;
const DES_MODES = ['cbc', 'ecb'];
const PADDINGS = ['pkcs7', 'none'];
const ENCODINGS = ['base64', 'hex'];

/**
 * DES encryption utility.
 *
 * DES is a legacy cipher with a 56-bit key and must not be used for new
 * designs; prefer AES. This helper exists for interoperability with systems
 * that still require DES.
 */
class DesUtil {
  /**
   * Encrypt a UTF-8 string or Buffer with DES.
   *
   * @param {string|Buffer} plaintext
   * @param {string|Buffer} key 8-byte DES key (UTF-8 string or Buffer)
   * @param {object} [options]
   * @param {'cbc'|'ecb'} [options.mode='cbc']
   * @param {string|Buffer} [options.iv] 8-byte IV, required in CBC mode
   * @param {'pkcs7'|'none'} [options.padding='pkcs7']
   * @param {'base64'|'hex'} [options.outputEncoding='base64']
   * @returns {string}
   */
  static encrypt(plaintext, key, options = {}) {
    const opts = normalizeOptions(options);
    const keyBuffer = normalizeKey(key);
    const ivBuffer = opts.mode === 'cbc' ? normalizeIv(opts.iv) : null;
    const data = normalizePlaintext(plaintext);

    if (opts.padding === 'none' && data.length % BLOCK_SIZE !== 0) {
      throw new RangeError(
        `plaintext length must be a multiple of ${BLOCK_SIZE} bytes when padding is "none"`,
      );
    }

    const cipher = createCipher(opts.mode, keyBuffer, ivBuffer);
    if (opts.padding === 'none') {
      cipher.setAutoPadding(false);
    }

    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    return encrypted.toString(opts.outputEncoding);
  }

  /**
   * Decrypt a DES ciphertext back to a UTF-8 string.
   *
   * @param {string|Buffer} ciphertext Base64 or hex text, or a Buffer
   * @param {string|Buffer} key 8-byte DES key (UTF-8 string or Buffer)
   * @param {object} [options]
   * @param {'cbc'|'ecb'} [options.mode='cbc']
   * @param {string|Buffer} [options.iv] 8-byte IV, required in CBC mode
   * @param {'pkcs7'|'none'} [options.padding='pkcs7']
   * @param {'base64'|'hex'} [options.inputEncoding='base64']
   * @returns {string}
   */
  static decrypt(ciphertext, key, options = {}) {
    const opts = normalizeOptions(options);
    const keyBuffer = normalizeKey(key);
    const ivBuffer = opts.mode === 'cbc' ? normalizeIv(opts.iv) : null;
    const data = normalizeCiphertext(ciphertext, opts.inputEncoding);

    if (data.length === 0 || data.length % BLOCK_SIZE !== 0) {
      throw new RangeError(
        `ciphertext length must be a positive multiple of ${BLOCK_SIZE} bytes`,
      );
    }

    const decipher = createDecipher(opts.mode, keyBuffer, ivBuffer);
    if (opts.padding === 'none') {
      decipher.setAutoPadding(false);
    }

    let decrypted;
    try {
      decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
    } catch (error) {
      throw new Error('DES decryption failed: wrong key, IV, or corrupted ciphertext', {
        cause: error,
      });
    }
    return decrypted.toString('utf8');
  }
}

/**
 * OpenSSL 3 builds (including the ones bundled with Node.js) may not provide
 * single DES ciphers. Triple DES with three identical 8-byte keys is
 * mathematically equivalent to single DES, because EDE becomes
 * E_K(D_K(E_K(P))) === E_K(P), so DES is performed through the widely
 * available des-ede3-* algorithms.
 */
function toTripleDesKey(key) {
  return Buffer.concat([key, key, key]);
}

function createCipher(mode, key, iv) {
  const algorithm = mode === 'ecb' ? 'des-ede3-ecb' : 'des-ede3-cbc';
  return crypto.createCipheriv(algorithm, toTripleDesKey(key), mode === 'ecb' ? null : iv);
}

function createDecipher(mode, key, iv) {
  const algorithm = mode === 'ecb' ? 'des-ede3-ecb' : 'des-ede3-cbc';
  return crypto.createDecipheriv(algorithm, toTripleDesKey(key), mode === 'ecb' ? null : iv);
}

function normalizeOptions(options) {
  if (options === undefined || options === null) {
    options = {};
  }
  if (typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('options must be an object');
  }
  return {
    mode: normalizeChoice(options.mode, 'cbc', 'mode', DES_MODES),
    padding: normalizeChoice(options.padding, 'pkcs7', 'padding', PADDINGS),
    outputEncoding: normalizeChoice(options.outputEncoding, 'base64', 'outputEncoding', ENCODINGS),
    inputEncoding: normalizeChoice(options.inputEncoding, 'base64', 'inputEncoding', ENCODINGS),
    iv: options.iv,
  };
}

function normalizeChoice(value, fallback, name, supported) {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== 'string') {
    throw new TypeError(`options.${name} must be a string`);
  }
  const normalized = value.toLowerCase();
  if (!supported.includes(normalized)) {
    throw new RangeError(
      `options.${name} must be one of: ${supported.join(', ')} (got "${value}")`,
    );
  }
  return normalized;
}

function normalizeKey(key) {
  return toBlockSizedBuffer(key, 'key');
}

function normalizeIv(iv) {
  if (iv === undefined || iv === null) {
    throw new TypeError('options.iv is required in CBC mode');
  }
  return toBlockSizedBuffer(iv, 'iv');
}

function toBlockSizedBuffer(value, name) {
  let buffer;
  if (Buffer.isBuffer(value)) {
    buffer = Buffer.from(value);
  } else if (typeof value === 'string') {
    buffer = Buffer.from(value, 'utf8');
  } else {
    throw new TypeError(`${name} must be a string or Buffer`);
  }
  if (buffer.length !== BLOCK_SIZE) {
    throw new RangeError(`${name} must be exactly ${BLOCK_SIZE} bytes (got ${buffer.length})`);
  }
  return buffer;
}

function normalizePlaintext(plaintext) {
  if (Buffer.isBuffer(plaintext)) {
    return plaintext;
  }
  if (typeof plaintext === 'string') {
    return Buffer.from(plaintext, 'utf8');
  }
  throw new TypeError('plaintext must be a string or Buffer');
}

function normalizeCiphertext(ciphertext, encoding) {
  if (Buffer.isBuffer(ciphertext)) {
    return Buffer.from(ciphertext);
  }
  if (typeof ciphertext !== 'string') {
    throw new TypeError('ciphertext must be a string or Buffer');
  }
  if (ciphertext.length === 0) {
    return Buffer.alloc(0);
  }
  if (encoding === 'base64') {
    const validBase64 =
      ciphertext.length % 4 === 0 &&
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(ciphertext);
    if (!validBase64) {
      throw new RangeError('ciphertext is not a valid base64 string');
    }
  } else if (!/^(?:[0-9a-fA-F]{2})+$/.test(ciphertext)) {
    throw new RangeError('ciphertext is not a valid hex string');
  }
  return Buffer.from(ciphertext, encoding);
}

function encrypt(plaintext, key, options) {
  return DesUtil.encrypt(plaintext, key, options);
}

function decrypt(ciphertext, key, options) {
  return DesUtil.decrypt(ciphertext, key, options);
}

module.exports = { DesUtil, encrypt, decrypt };
