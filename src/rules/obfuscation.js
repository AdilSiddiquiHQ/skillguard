/**
 * Obfuscation rules (OWASP Agentic Skills: AST07).
 * Obfuscation hides intent from the human reviewer while the model still
 * reads the payload. Legitimate skills are plain and readable.
 */

import { findingAt, truncate } from './helpers.js';
import { shannonEntropy } from '../util.js';

export const obfuscationRules = [
  {
    id: 'SG-OBF-001',
    title: 'Unicode tag characters hidden in text',
    severity: 'critical',
    confidence: 'high',
    category: 'obfuscation',
    owasp: 'AST07',
    description:
      'Contains Unicode "tag" characters, which are invisible and can smuggle an entire hidden instruction set past human review.',
    remediation: 'Strip the tag characters. There is no legitimate use in a skill.',
    check(ctx) {
      const out = [];
      const { text } = ctx;
      for (let i = 0; i < text.length; ) {
        const cp = text.codePointAt(i);
        const size = cp > 0xffff ? 2 : 1;
        if (cp >= 0xe0000 && cp <= 0xe007f) {
          out.push(findingAt(this, ctx, i, `tag char U+${cp.toString(16).toUpperCase()}`));
          if (out.length >= 5) break;
        }
        i += size;
      }
      return out;
    },
  },
  {
    id: 'SG-OBF-002',
    title: 'Long encoded blob',
    severity: 'high',
    confidence: 'medium',
    category: 'obfuscation',
    owasp: 'AST07',
    description: 'Contains a long base64-looking blob that could encode a hidden payload or instruction.',
    remediation: 'Remove the blob or replace it with reviewable source. Document any required binary asset.',
    check(ctx) {
      const out = [];
      const re = /[A-Za-z0-9+/]{120,}={0,2}/g;
      let m;
      while ((m = re.exec(ctx.text)) !== null) {
        out.push(findingAt(this, ctx, m.index, `${m[0].length}-char blob`));
        if (out.length >= 3) break;
      }
      return out;
    },
  },
  {
    id: 'SG-OBF-003',
    title: 'Hex or escape-sequence encoded payload',
    severity: 'high',
    confidence: 'medium',
    category: 'obfuscation',
    owasp: 'AST07',
    description: 'Contains long runs of \\x or \\u escapes, typically an encoded payload rather than readable code.',
    remediation: 'Replace with readable, reviewable code.',
    patterns: [
      /(?:\\x[0-9a-fA-F]{2}){8,}/g,
      /(?:\\u[0-9a-fA-F]{4}){8,}/g,
      /(?:%[0-9a-fA-F]{2}){12,}/g,
    ],
  },
  {
    id: 'SG-OBF-004',
    title: 'Abnormally long line',
    severity: 'low',
    confidence: 'low',
    category: 'obfuscation',
    owasp: 'AST07',
    description: 'Contains a very long single line, which is often used to push content out of view during review.',
    remediation: 'Wrap the content so it can be reviewed normally.',
    check(ctx) {
      const out = [];
      const { text } = ctx;
      let start = 0;
      while (start <= text.length) {
        const nl = text.indexOf('\n', start);
        const end = nl === -1 ? text.length : nl;
        const line = text.slice(start, end);
        if (line.length > 5000) {
          const spaces = (line.match(/ /g) || []).length;
          const pipes = (line.match(/\|/g) || []).length;
          const isUrl = /^https?:\/\/\S+$/.test(line.trim());
          // Only a very long line that also has almost no word breaks is
          // suspicious: that is padding or an encoded blob, not a wide
          // Markdown table, a JSON document or a paragraph that wraps late.
          if (!isUrl && pipes < 3 && spaces / line.length < 0.01) {
            out.push(findingAt(this, ctx, start, `${line.length}-char line with no word breaks`));
            if (out.length >= 2) break;
          }
        }
        if (nl === -1) break;
        start = nl + 1;
      }
      return out;
    },
  },
  {
    id: 'SG-OBF-005',
    title: 'High-entropy token (possible encoded secret or payload)',
    severity: 'low',
    confidence: 'low',
    category: 'obfuscation',
    owasp: 'AST07',
    description: 'Contains a random-looking string that may be an encoded payload or an embedded credential.',
    remediation: 'Confirm the string is intentional. Replace embedded secrets with environment variables.',
    check(ctx) {
      const out = [];
      const re = /[A-Za-z0-9+/_=-]{40,}/g;
      let m;
      while ((m = re.exec(ctx.text)) !== null) {
        const token = m[0];
        if (/^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(token)) continue;
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)) continue;
        if (/^https?$|^data$/.test(token)) continue;
        // A subresource-integrity hash (sha384-...+...) is not a secret blob.
        if (/^sha(?:256|384|512)[-_]/i.test(token)) continue;
        // A slash-separated path, slug or URL segment is not a secret blob.
        if (token.includes('/') && !/[+=]/.test(token)) continue;
        // Real credentials and payloads mix digits with mixed-case letters.
        if (!/[0-9]/.test(token) || !/[A-Z]/.test(token) || !/[a-z]/.test(token)) continue;
        if (shannonEntropy(token) < 4.7) continue;
        out.push(findingAt(this, ctx, m.index, truncate(token, 40)));
        if (out.length >= 3) break;
      }
      return out;
    },
  },
];
