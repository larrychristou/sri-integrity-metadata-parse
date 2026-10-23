/**
 * Core parsing logic for Subresource Integrity metadata.
 *
 * The SRI integrity attribute format is defined by the SRI specification:
 *   <algorithm>-<base64-hash>[ <algorithm>-<base64-hash> ...]
 *
 * This module deliberately validates only the structural contract — that each
 * entry splits into a recognised algorithm and a base64 value whose decoded
 * byte length matches the algorithm's known digest length. We do NOT
 * re-compute a digest; that is the browser's job at fetch time. The value of
 * parsing here is catching malformed metadata early (wrong algorithm name,
 * truncated hash) before it is written into HTML.
 *
 * Base64 decoding uses a hand-rolled decoder rather than Node's Buffer or
 * atob. atob is only available in Node ≥16 globally and is not part of the
 * ECMAScript standard, so relying on it would make the library host-dependent.
 * Buffer is Node-specific and would break ESM consumers running under a
 * standards-only runtime. A from-scratch decoder keeps the library pure ESM
 * with zero host assumptions beyond the language itself.
 */

/**
 * Known SRI algorithms and their digest byte lengths.
 *
 * Only sha256, sha384, and sha512 are permitted by the SRI spec. We list them
 * explicitly rather than accepting any string so that a typo like "sha356"
 * produces a clear error rather than a silent unknownAlgorithm result.
 */
export const ALGORITHMS = Object.freeze({
  sha256: 32,
  sha384: 48,
  sha512: 64,
});

/**
 * Parse a single integrity-metadata option: "algorithm-base64hash".
 *
 * @param {string} option - The option string (no surrounding whitespace).
 * @returns {{algorithm: string, hash: string}}
 * @throws {SyntaxError} If the option lacks a dash or the algorithm is unknown
 *   or the hash contains characters outside the base64 alphabet or its
 *   decoded byte length does not match the algorithm's digest length.
 */
function parseOption(option) {
  const dashIndex = option.indexOf('-');
  if (dashIndex <= 0) {
    throw new SyntaxError(`Integrity option missing algorithm/hash separator: "${option}"`);
  }
  const algorithm = option.slice(0, dashIndex);
  const hash = option.slice(dashIndex + 1);
  if (!Object.prototype.hasOwnProperty.call(ALGORITHMS, algorithm)) {
    throw new SyntaxError(`Unknown or unsupported integrity algorithm: "${algorithm}"`);
  }
  const expectedBytes = ALGORITHMS[algorithm];
  const decoded = base64DecodeToBytes(hash);
  if (decoded.length !== expectedBytes) {
    throw new SyntaxError(
      `Hash for "${algorithm}" has ${decoded.length} byte(s) after base64 decode; expected ${expectedBytes}.`,
    );
  }
  return { algorithm, hash };
}

/**
 * RFC 4648 base64 alphabet. We accept '+' and '/' (standard base64) only;
 * the URL-safe '-' and '_' variant is not part of the SRI format and would
 * collide visually with the '-' separator, so rejecting it avoids ambiguity.
 */
const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const CHAR_TO_SIX = new Uint8Array(128);
for (let i = 0; i < 128; i++) CHAR_TO_SIX[i] = 255;
for (let i = 0; i < BASE64_CHARS.length; i++) CHAR_TO_SIX[BASE64_CHARS.charCodeAt(i)] = i;

/**
 * Decode a standard base64 string into a byte array.
 *
 * Throws on characters outside the base64 alphabet or '=' padding that does
 * not appear in the canonical trailing positions or at the canonical length.
 * We implement strict validation because a wrong-length hash is exactly the
 * class of error this library is built to surface, and lenient decoding would
 * silently accept truncated or padded-but-garbage input.
 *
 * @param {string} input
 * @returns {Uint8Array}
 * @throws {SyntaxError}
 */
function base64DecodeToBytes(input) {
  if (input.length === 0) {
    return new Uint8Array(0);
  }
  const equalsCount = countTrailingEquals(input);
  const coreLen = input.length - equalsCount;
  if (equalsCount > 2) {
    throw new SyntaxError(`Invalid base64: too many '=' paddings in "${input}"`);
  }
  if ((coreLen + equalsCount) % 4 !== 0) {
    throw new SyntaxError(`Invalid base64 length: "${input}"`);
  }
  const outLen = Math.floor(coreLen * 6 / 8);
  const out = new Uint8Array(outLen);
  let bits = 0;
  let bitsHeld = 0;
  let outIndex = 0;
  for (let i = 0; i < coreLen; i++) {
    const code = input.charCodeAt(i);
    if (code >= 128) {
      throw new SyntaxError(`Invalid base64 character in "${input}"`);
    }
    const six = CHAR_TO_SIX[code];
    if (six === 255) {
      throw new SyntaxError(`Invalid base64 character in "${input}"`);
    }
    bits = (bits << 6) | six;
    bitsHeld += 6;
    if (bitsHeld >= 8) {
      bitsHeld -= 8;
      out[outIndex++] = (bits >>> bitsHeld) & 0xff;
    }
  }
  return out;
}

/**
 * Count '=' characters at the end of `input`, verifying they form the only
 * run of padding and that none sit in the middle (which would be malformed).
 */
function countTrailingEquals(input) {
  let count = 0;
  for (let i = input.length - 1; i >= 0; i--) {
    if (input[i] === '=') count++;
    else break;
  }
  if (count > 0) {
    for (let i = 0; i < input.length - count; i++) {
      if (input[i] === '=') {
        throw new SyntaxError(`Invalid base64: '=' appears before end in "${input}"`);
      }
    }
  }
  return count;
}

/**
 * Parse a full integrity attribute value into an array of option objects.
 *
 * Surrounding whitespace is trimmed and options are split on any run of
 * ASCII whitespace (spaces, tabs, newlines), matching how browsers tokenize
 * the attribute. An empty string yields an empty array — an SRI attribute
 * with no options is structurally valid (if useless) so we do not throw.
 *
 * @param {string} integrity - The raw integrity attribute value.
 * @returns {Array<{algorithm: string, hash: string}>}
 * @throws {SyntaxError} If any option fails to parse.
 */
export function parseIntegrityMetadata(integrity) {
  if (typeof integrity !== 'string') {
    throw new TypeError('integrity must be a string');
  }
  const trimmed = integrity.trim();
  if (trimmed === '') {
    return [];
  }
  const options = trimmed.split(/\s+/);
  const results = [];
  for (const option of options) {
    if (option === '') continue;
    results.push(parseOption(option));
  }
  return results;
}
