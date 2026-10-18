/**
 * Integrity and provenance.
 *
 * Scanning tells you what a skill *looks like* now. Signing tells you that the
 * bytes you scanned are the bytes you install — the missing half of every
 * "verified" badge. SkillSleuth emits in-toto style statements wrapped in a
 * DSSE envelope, signed with Ed25519 and no external dependencies, so a
 * publisher can sign a skill and a consumer can verify it offline.
 */

import { createHash, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, createPrivateKey, createPublicKey } from 'node:crypto';

export const PREDICATE_TYPE = 'https://github.com/AdilSiddiquiHQ/skillsleuth/attestation/scan/v1';
export const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
export const DSSE_PAYLOAD_TYPE = 'application/vnd.in-toto+json';

/** Deterministic JSON: object keys sorted so signatures are reproducible. */
export function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
}

export function generateKeyPair(passphrase = null) {
  const options = { format: 'pem', type: 'pkcs8' };
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: passphrase ? { ...options, cipher: 'aes-256-cbc', passphrase } : options,
    publicKeyEncoding: { format: 'pem', type: 'spki' },
  });
  return { privateKey, publicKey };
}

export function fingerprintPublicKey(publicKeyPem) {
  const der = createPublicKey(publicKeyPem).export({ format: 'der', type: 'spki' });
  return createHash('sha256').update(der).digest('hex').slice(0, 32);
}

/**
 * Build an in-toto statement describing a scan result: the subject is the
 * exact bytes on disk (by hash), the predicate is what the scanner observed.
 */
export function buildStatement(report, skill) {
  const subject = (skill ? [skill] : report.skills).flatMap((s) =>
    (s.sbom || []).map((entry) => ({
      name: `${s.path}/${entry.path}`.replace(/\/\.\//g, '/'),
      digest: { sha256: entry.sha256 },
    }))
  );

  return {
    _type: STATEMENT_TYPE,
    subject,
    predicateType: PREDICATE_TYPE,
    predicate: {
      scanner: report.tool,
      version: report.version,
      ruleCount: report.ruleCount,
      generatedAt: report.generatedAt,
      skills: (skill ? [skill] : report.skills).map((s) => ({
        name: s.name,
        path: s.path,
        score: s.score,
        verdict: s.verdict,
        counts: s.counts,
        evasions: s.evasions || [],
        findings: s.findings.length,
      })),
    },
  };
}

/** Wrap and sign a statement as a DSSE envelope. */
export function signStatement(statement, privateKeyPem) {
  const payload = Buffer.from(canonicalize(statement), 'utf8').toString('base64');
  const pae = preAuthenticationEncoding(DSSE_PAYLOAD_TYPE, payload);
  const key = createPrivateKey(privateKeyPem);
  const sig = cryptoSign(null, Buffer.from(pae), key).toString('base64');

  let keyid = null;
  try {
    keyid = fingerprintPublicKey(createPublicKey(key).export({ format: 'pem', type: 'spki' }));
  } catch {
    keyid = null;
  }

  return {
    payloadType: DSSE_PAYLOAD_TYPE,
    payload,
    signatures: [{ keyid, sig }],
  };
}

/** Verify a DSSE envelope against a public key. Returns a small result object. */
export function verifyEnvelope(envelope, publicKeyPem) {
  try {
    if (!envelope || typeof envelope.payload !== 'string' || !Array.isArray(envelope.signatures)) {
      return { valid: false, reason: 'malformed envelope' };
    }
    const pae = preAuthenticationEncoding(envelope.payloadType || DSSE_PAYLOAD_TYPE, envelope.payload);
    const pub = createPublicKey(publicKeyPem);
    for (const entry of envelope.signatures) {
      if (typeof entry.sig !== 'string') continue;
      const ok = cryptoVerify(null, Buffer.from(pae), pub, Buffer.from(entry.sig, 'base64'));
      if (ok) {
        return { valid: true, statement: decodeStatement(envelope.payload) };
      }
    }
    return { valid: false, reason: 'no signature verified' };
  } catch (err) {
    return { valid: false, reason: err.message };
  }
}

export function decodeStatement(payloadBase64) {
  try {
    return JSON.parse(Buffer.from(payloadBase64, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

/** DSSE pre-authentication encoding. */
export function preAuthenticationEncoding(payloadType, payload) {
  const type = Buffer.from(payloadType, 'utf8');
  const body = Buffer.from(payload, 'utf8');
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, 'utf8'),
    type,
    Buffer.from(` ${body.length} `, 'utf8'),
    body,
  ]);
}
