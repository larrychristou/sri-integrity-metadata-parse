# sri-integrity-metadata-parse

Parses Subresource Integrity attribute values, splitting algorithm-hash pairs and validating that each hash's decoded byte length matches its declared algorithm.

```js
import { parseIntegrityMetadata } from 'sri-integrity-metadata-parse';

const options = parseIntegrityMetadata(
  'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU= sha384-rT9MdzZ5NVaj0oVxJlaipBWQTmUxVUcvRyP0j4rCsO4X7vJmBnXG2KQ9eQw7x+Q8',
);
// => [{ algorithm: 'sha256', hash: '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' },
//     { algorithm: 'sha384', hash: 'rT9MdzZ5NVaj0oVxJlaipBWQTmUxVUcvRyP0j4rCsO4X7vJmBnXG2KQ9eQw7x+Q8' }]
```

Exported names: `parseIntegrityMetadata(integrity: string): Array<{algorithm: string, hash: string}>` and `ALGORITHMS` (a frozen map of `{ sha256: 32, sha384: 48, sha512: 64 }`).

## Why this exists

The browser only acts on an integrity attribute at fetch time, which is too late to catch a typo in your build output. This library does an early structural check: it confirms each entry is `algorithm-base64hash`, that the algorithm is one the SRI spec permits (`sha256`, `sha384`, `sha512`), and that the base64 value decodes to the exact digest byte length for that algorithm (32, 48, or 64 bytes). It does not recompute any digest — that is deliberately left to the runtime that owns the bytes.

## Decisions and edges

- Options are split on any run of ASCII whitespace (spaces, tabs, newlines), matching how the HTML tokenizer treats the attribute. Surrounding whitespace is trimmed.
- Only standard base64 (`+` and `/`) is accepted. The URL-safe variant (`-` and `_`) is rejected because `-` is the algorithm separator and accepting it would introduce ambiguity.
- An empty or whitespace-only attribute yields an empty array rather than throwing. A useless attribute is not a malformed one.
- Unknown algorithms (including `sha1`, which the spec dropped) throw `SyntaxError`, as do hashes whose decoded length does not match the algorithm. This is the main reason to reach for this library: a `sha256` entry whose hash is one character short is the exact bug that silently disables SRI in browsers.
