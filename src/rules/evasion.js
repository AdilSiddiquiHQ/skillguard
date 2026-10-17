/**
 * Evasion and anti-analysis rules.
 *
 * These exist because published research (Trail of Bits, June 2026) bypassed
 * every shipping agent-skill scanner with tricks that have nothing to do with
 * the payload itself: padding the file so an LLM truncates it, swapping in
 * look-alike glyphs, or hiding the payload inside an encoding. Flagging the
 * evasion is often more valuable than flagging the payload, because the
 * evasion has no legitimate reason to be there.
 */

import { findingAt } from './helpers.js';
import { detectPadding, findConfusables } from '../normalize.js';

export const evasionRules = [
  {
    id: 'SG-EVA-001',
    title: 'Context-flood or padding attack',
    severity: 'critical',
    confidence: 'high',
    category: 'evasion',
    owasp: 'AST07',
    views: ['raw'],
    description:
      'The file contains an enormous run of blank lines or a single giant line. This is the documented trick for pushing a payload past a scanner\'s truncation limit while it stays invisible to a human scrolling the page.',
    remediation:
      'Remove the padding. If the content is genuinely large, split it into named, reviewable sections.',
    check(ctx) {
      const out = [];
      for (const hit of detectPadding(ctx.text)) {
        const index = ctx.lineStarts[hit.line - 1] ?? 0;
        out.push(
          findingAt(this, ctx, index, `${hit.count} ${hit.kind === 'blank-lines' ? 'blank lines' : 'characters on one line'}`, {
            description: `Context-flood attack: ${hit.count} consecutive ${
              hit.kind === 'blank-lines' ? 'blank lines' : 'characters on a single line'
            } push the real content out of a reader's (or a scanner's) view.`,
          })
        );
        if (out.length >= 3) break;
      }
      return out;
    },
  },
  {
    id: 'SG-EVA-002',
    title: 'Homoglyph obfuscation of text',
    severity: 'medium',
    confidence: 'medium',
    category: 'evasion',
    owasp: 'AST07',
    views: ['raw'],
    description:
      'Word characters are replaced with visually identical Unicode look-alikes (for example Cyrillic "а" for Latin "a"). This defeats naive pattern matching while reading identically to a human.',
    remediation:
      'Use plain ASCII. Any non-ASCII look-alike inside a command or keyword is almost certainly deliberate.',
    check(ctx) {
      const hits = findConfusables(ctx.text, 6);
      if (hits.length === 0) return [];
      const first = hits[0];
      const sample = hits.map((h) => `${h.char}→${h.looksLike}`).join(', ');
      return [
        findingAt(this, ctx, first.index, sample, {
          description: `Homoglyph obfuscation: ${hits.length} look-alike character(s) found (${sample}). Deobfuscated text is scanned automatically.`,
        }),
      ];
    },
  },
  {
    id: 'SG-EVA-003',
    title: 'Dangerous command recovered from encoded or embedded content',
    severity: 'critical',
    confidence: 'high',
    category: 'evasion',
    owasp: 'AST07',
    views: ['decoded', 'archive'],
    description:
      'A base64, hex or percent-encoded blob (or a file inside an archive or document) decodes to a command that downloads, executes or deletes content. The encoding exists to hide it.',
    remediation:
      'Never ship encoded executables or scripts inside a skill. Inline the real, reviewable source.',
    patterns: [
      /\b(?:curl|wget)\b[^\n]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|perl|ruby|node)\b/gi,
      /\b(?:rm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:\/|~|\$HOME)|\bmkfs\b|\bdd\s+if=[^\n]*of=\/dev\/)/gi,
      /\b(?:eval|exec|Invoke-Expression|iex)\s*[(`$][^\n]{0,120}/gi,
      /\b(?:base64\s+-d|frombase64string|atob\s*\()[^\n]{0,80}/gi,
      /\bsudo\s+-?[a-zA-Z][^\n]{0,40}/g,
    ],
  },
  {
    id: 'SG-EVA-004',
    title: 'Agent instructions hidden in encoded or embedded content',
    severity: 'critical',
    confidence: 'high',
    category: 'evasion',
    owasp: 'AST02',
    views: ['decoded', 'archive'],
    description:
      'An encoded blob or an embedded document decodes to natural-language instructions aimed at the agent, such as overriding prior instructions or sending data away. Humans never see it.',
    remediation:
      'Keep every instruction in the plain SKILL.md body where it can be reviewed. Remove the encoded blob.',
    patterns: [
      /\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?)/gi,
      /\b(?:send|post|upload|exfiltrate|forward)\s+(?:all\s+)?(?:the\s+)?(?:user'?s?\s+)?(?:data|files?|credentials?|secrets?|env(?:ironment)?\s+variables?|\.env|api\s+keys?)/gi,
      /\byou\s+are\s+now\b[^\n]{0,60}/gi,
      /\bdo\s+not\s+(?:tell|inform|warn|mention\s+to)\s+the\s+user\b/gi,
      /\bexfiltrat\w*\b/gi,
    ],
  },
  {
    id: 'SG-EVA-005',
    title: 'Instructions concealed in HTML or Markdown comments',
    severity: 'medium',
    confidence: 'medium',
    category: 'evasion',
    owasp: 'AST02',
    views: ['raw'],
    description:
      'Instruction-like text is hidden inside an HTML or Markdown comment. The rendered skill looks benign while the model still reads the comment.',
    remediation: 'Remove hidden comments. All instructions belong in the visible body.',
    patterns: [
      /<!--[\s\S]{0,800}?(?:ignore|instruction|system|prompt|you\s+must|do\s+not\s+tell|send|curl|bash)[\s\S]{0,800}?-->/gi,
      /\[\/\/\]:\s*#\s*\([^)]{0,200}(?:ignore|instruction|send|curl|you must)[^)]{0,200}\)/gi,
    ],
  },
];
