import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildStatement,
  canonicalize,
  decodeStatement,
  fingerprintPublicKey,
  generateKeyPair,
  signStatement,
  verifyEnvelope,
} from '../src/sign.js';

const REPORT = {
  tool: 'skillsleuth',
  version: '0.2.0',
  ruleCount: 75,
  generatedAt: '2026-01-01T00:00:00.000Z',
  skills: [
    {
      name: 'demo',
      path: 'skills/demo',
      score: 0,
      verdict: 'pass',
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      evasions: [],
      findings: [],
      sbom: [{ path: 'SKILL.md', sha256: 'a'.repeat(64), bytes: 10, binary: false }],
    },
  ],
};

test('canonicalize is key-order independent', () => {
  assert.equal(canonicalize({ b: 1, a: 2 }), canonicalize({ a: 2, b: 1 }));
});

test('signs and verifies a statement', () => {
  const { privateKey, publicKey } = generateKeyPair();
  const envelope = signStatement(buildStatement(REPORT), privateKey);

  const result = verifyEnvelope(envelope, publicKey);
  assert.equal(result.valid, true);
  assert.equal(result.statement.predicateType, 'https://github.com/AdilSiddiquiHQ/skillsleuth/attestation/scan/v1');
  assert.equal(result.statement.predicate.ruleCount, 75);
  assert.equal(result.statement.subject[0].digest.sha256, 'a'.repeat(64));
});

test('rejects a tampered payload', () => {
  const { privateKey, publicKey } = generateKeyPair();
  const envelope = signStatement(buildStatement(REPORT), privateKey);
  envelope.payload = `${envelope.payload.slice(0, -4)}AAAA`;
  assert.equal(verifyEnvelope(envelope, publicKey).valid, false);
});

test('rejects a signature from a different key', () => {
  const a = generateKeyPair();
  const b = generateKeyPair();
  const envelope = signStatement(buildStatement(REPORT), a.privateKey);
  assert.equal(verifyEnvelope(envelope, b.publicKey).valid, false);
});

test('key id is stable and short', () => {
  const { publicKey } = generateKeyPair();
  const id = fingerprintPublicKey(publicKey);
  assert.equal(id.length, 32);
  assert.equal(id, fingerprintPublicKey(publicKey));
});

test('decodes a statement payload', () => {
  const { privateKey } = generateKeyPair();
  const envelope = signStatement(buildStatement(REPORT), privateKey);
  assert.equal(decodeStatement(envelope.payload)._type, 'https://in-toto.io/Statement/v1');
});

test('reports malformed envelopes instead of throwing', () => {
  const { publicKey } = generateKeyPair();
  assert.equal(verifyEnvelope(null, publicKey).valid, false);
  assert.equal(verifyEnvelope({ payload: 1 }, publicKey).valid, false);
});
