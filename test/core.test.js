import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseIntegrityMetadata, ALGORITHMS } from '../src/index.js';

test('parses a single well-formed sha256 entry', () => {
  const hash = '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=';
  const result = parseIntegrityMetadata(`sha256-${hash}`);
  assert.deepEqual(result, [{ algorithm: 'sha256', hash }]);
});

test('parses sha384 and sha512 entries', () => {
  const sha384Hash = 'rT9MdzZ5NVaj0oVxJlaipBWQTmUxVUcvRyP0j4rCsO4X7vJmBnXG2KQ9eQw7x+Q8';
  const sha512Hash = 'XxKzM62vqVwmvKqX0lJqaP3elKu/r3ylIt0nV6vI8KVRls2V/muJ6HfgNk5u5w8FQ4r1+fH5Q5J5X7zZ8vKqVw==';
  const result = parseIntegrityMetadata(`sha384-${sha384Hash} sha512-${sha512Hash}`);
  assert.deepEqual(result, [
    { algorithm: 'sha384', hash: sha384Hash },
    { algorithm: 'sha512', hash: sha512Hash },
  ]);
});

test('ALGORITHMS exports the three spec algorithms with their byte lengths', () => {
  assert.deepEqual({ ...ALGORITHMS }, { sha256: 32, sha384: 48, sha512: 64 });
});

test('returns empty array for empty string', () => {
  assert.deepEqual(parseIntegrityMetadata(''), []);
});

test('returns empty array for whitespace-only string', () => {
  assert.deepEqual(parseIntegrityMetadata('   \t\n  '), []);
});

test('trims surrounding whitespace before parsing', () => {
  const hash = '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=';
  const result = parseIntegrityMetadata(`  sha256-${hash}  `);
  assert.deepEqual(result, [{ algorithm: 'sha256', hash }]);
});

test('splits options on runs of mixed whitespace', () => {
  const a = '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=';
  const b = 'lWKdH7RkTFaPDYcIs7FddoXx4Ul1uU+IC3B4SIraUJZg9qWX8rxgUpf6QHQ7zB1W';
  const result = parseIntegrityMetadata(`sha256-${a}\t sha384-${b}`);
  assert.deepEqual(result, [
    { algorithm: 'sha256', hash: a },
    { algorithm: 'sha384', hash: b },
  ]);
});

test('throws SyntaxError for unknown algorithm', () => {
  assert.throws(
    () => parseIntegrityMetadata('md5-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='),
    { name: 'SyntaxError' },
  );
});

test('throws SyntaxError for option missing separator', () => {
  assert.throws(
    () => parseIntegrityMetadata('sha256'),
    { name: 'SyntaxError' },
  );
});

test('throws SyntaxError for hash with wrong byte length', () => {
  // sha256 expects 32 bytes (44 base64 chars), here we give a 12-byte hash.
  assert.throws(
    () => parseIntegrityMetadata('sha256-dGVzdBo='),
    { name: 'SyntaxError' },
  );
});

test('throws SyntaxError for invalid base64 character', () => {
  // 44 chars so length is fine, but '!' is not base64.
  assert.throws(
    () => parseIntegrityMetadata('sha256-!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'),
    { name: 'SyntaxError' },
  );
});

test('throws TypeError when given a non-string', () => {
  assert.throws(
    // eslint-disable-next-line no-undefined
    () => parseIntegrityMetadata(undefined),
    { name: 'TypeError' },
  );
});
