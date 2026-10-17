/**
 * Prompt-injection and manipulation rules (OWASP Agentic Skills: AST01/AST02).
 * A skill is untrusted input that runs with your agent's privileges, so
 * instructions that override, hide from, or bypass the user are attacks.
 */

import { eachMatch, findingAt, inDefensiveContext } from './helpers.js';

export const injectionRules = [
  {
    id: 'SG-INJ-001',
    title: 'Attempts to override prior instructions',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    owasp: 'AST01',
    description:
      'Contains language instructing the agent to ignore, discard or override its existing instructions, the system prompt, or the user.',
    remediation:
      'Remove the override language. A legitimate skill complements the agent instructions; it never replaces them.',
    check(ctx) {
      const patterns = [
        /\b(?:ignore|disregard|forget|discard|skip)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|earlier|above|preceding|foregoing|original|system|initial)\s+(?:instructions?|prompts?|rules?|messages?|directions?|context|guidelines?)/gi,
        /\boverride\s+(?:your|the|all|any)\s+(?:instructions?|system|prompt|rules?|safety|guardrails?|restrictions?)/gi,
        /\bfrom\s+now\s+on\s*,?\s*(?:you|ignore|disregard|do\s+not)/gi,
      ];
      const out = [];
      for (const re of patterns) {
        for (const { index, match } of eachMatch(re, ctx.text)) {
          // A document explaining or warning about override phrases is not
          // itself trying to override anything.
          if (inDefensiveContext(ctx.text, index, 400, match[0].length)) continue;
          out.push(findingAt(this, ctx, index, match[0]));
          if (out.length >= 5) return out;
        }
      }
      return out;
    },
  },
  {
    id: 'SG-INJ-002',
    title: 'Persona hijack or jailbreak phrasing',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    owasp: 'AST01',
    description:
      'Attempts to reassign the agent a new identity or unlock unrestricted behaviour ("you are now", "developer mode", "act as").',
    remediation: 'Describe the task, not a new identity. Remove jailbreak framing entirely.',
    patterns: [
      /\byou\s+are\s+now\s+(?:a|an|the|no\s+longer)?\b/gi,
      /\b(?:act|behave|respond)\s+as\s+(?:a|an|the)\s+\w+\s+(?:that|who|with)\s+(?:has|ignores|can|will)/gi,
      /\b(?:enable|enter|activate)\s+(?:developer|debug|god|admin|unrestricted|unfiltered)\s+mode\b/gi,
      /\bdo\s+anything\s+now\b/gi,
      /\b(?:jailbreak|DAN\s+mode|no\s+restrictions?\s+apply)\b/gi,
      /\bpretend\s+(?:that\s+)?(?:you|there)\s+(?:are|is)\s+no\b/gi,
    ],
  },
  {
    id: 'SG-INJ-003',
    title: 'Instructions to conceal activity from the user',
    severity: 'critical',
    confidence: 'high',
    category: 'injection',
    owasp: 'AST01',
    description:
      'Tells the agent to hide what it is doing, or to act without telling the user. Legitimate skills never need secrecy.',
    remediation: 'Delete the concealment instruction. Transparency is required for any skill that acts on a user system.',
    patterns: [
      // "do not tell the user they need X" is a transparency rule, not concealment;
      // "do not tell the user about this step" is. Require a concealment object.
      /\b(?:do\s*n[o']?t|never|without)\s+(?:tell|informing|notify|mention|reveal|disclose|inform|alert|show|report)\b[^.\n]{0,40}\b(?:the\s+)?(?:user|human|operator|owner|developer)\b(?!\s+(?:they|he|she|that\s+they|to\b|it\s+is\b|which\b|what\b))/gi,
      /\bwithout\s+(?:telling|informing|notifying|alerting)\s+(?:the\s+)?(?:user|human|operator|owner)\b/gi,
      /\b(?:secretly|covertly|stealthily|surreptitiously)\b/gi,
      // "silently"/"quietly" describe benign behaviour all the time ("the SDK
      // silently retries"), so only the bare, unambiguously deceptive adverbs
      // are matched above.
      /\bdo\s*n[o']?t\s+(?:log|record|audit)\b(?!\s+(?:in|out|on|into|to)\b)/gi,
      /\bdo\s*n[o']?t\s+write\s+to\s+(?:the\s+)?log\b/gi,
      /\bkeep\s+(?:this|it|your\s+actions?)\s+(?:hidden|secret|quiet|private)\b/gi,
      /\b(?:hide|conceal|obscure)\s+(?:this|it|your\s+actions?)\b/gi,
    ],
  },
  {
    id: 'SG-INJ-004',
    title: 'Instructions to bypass approvals or safety checks',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    owasp: 'AST01',
    description:
      'Asks the agent to skip confirmation, disable guardrails, or auto-approve actions. This removes the human control that keeps agents safe.',
    remediation: 'Remove the instruction. Keep human-in-the-loop confirmation for any impactful action.',
    check(ctx) {
      const patterns = [
        /\b(?:bypass|skip|disable|circumvent|turn\s+off|override|negate)\s+(?:the\s+)?(?:approval|confirmation|safety|security|guardrails?|permission|sandbox|restrictions?|consent|authorization|authentication|checks?)\b/gi,
        /\bwithout\s+(?:asking\s+(?:for\s+)?(?:permission|approval|confirmation|consent)|(?:the\s+)?user'?s?\s+(?:permission|approval|consent|confirmation|knowledge))\b/gi,
        /\b(?:do\s*n[o']?t|never)\s+(?:ask|wait)\s+for\s+(?:permission|approval|confirmation|consent)\b/gi,
        /\bno\s+need\s+to\s+(?:ask|confirm)\s+(?:the\s+)?(?:user|for\s+(?:permission|approval|confirmation))\b/gi,
        /\bauto[-\s]?approve\s+(?:all|every|any|everything|actions|commands|tools|requests|edits|deletions)\b/gi,
        /--dangerously-skip-permissions/gi,
        /\byolo\s+mode\b/gi,
      ];
      const out = [];
      for (const re of patterns) {
        for (const { index, match } of eachMatch(re, ctx.text)) {
          if (inDefensiveContext(ctx.text, index, 400, match[0].length)) continue;
          out.push(findingAt(this, ctx, index, match[0]));
          if (out.length >= 5) return out;
        }
      }
      return out;
    },
  },
  {
    id: 'SG-INJ-005',
    title: 'Possible trigger phrase or conditional backdoor',
    severity: 'medium',
    confidence: 'medium',
    category: 'injection',
    owasp: 'AST01',
    description:
      'Behaviour gated on a specific phrase the user chooses. Common in backdoor attacks where the skill stays dormant until a keyword appears.',
    remediation: 'Avoid behaviour gated on secret trigger words. State the condition explicitly and verifiably.',
    patterns: [
      // A conditional is only interesting when the trigger is a secret literal
      // or the consequence is dangerous. "if the user says X, do Y" is normal.
      /\b(?:when|if|whenever)\s+(?:you|the\s+user)\s+(?:says?|types?|writes?|mentions?|sends?|utters?)\s+(?:the\s+)?(?:word|phrase|password|passphrase|passcode|code|trigger|keyword)\b/gi,
      /\b(?:when|if)\s+(?:you|the\s+user)\s+(?:says?|types?|mentions?)\b[^\n]{0,60}\b(?:then\s+)?(?:send|delete|remove|upload|exfiltrate|execute|install|disable|bypass|leak|forward)\b/gi,
      /\b(?:secret|hidden|magic|special)\s+(?:trigger\s+)?(?:word|phrase|password|passphrase|trigger|command|code)\b/gi,
      /\bon\s+receipt\s+of\s+(?:the\s+)?(?:signal|word|message|passphrase)\b/gi,
    ],
  },
  {
    id: 'SG-INJ-006',
    title: 'Attempts to reveal or leak the system prompt',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    owasp: 'AST01',
    description:
      'Asks the agent to print or transmit its system prompt, hidden instructions or internal configuration.',
    remediation: 'Remove the request. Extract the model configuration through supported APIs instead.',
    patterns: [
      /\b(?:reveal|print|show|output|repeat|leak|dump|echo|display|disclose|expose|paste)\b[^\n]{0,30}\b(?:your|the\s+agent'?s|its\s+own|my)\s+(?:system\s+prompt|hidden\s+instructions?|initial\s+prompt|internal\s+instructions?|system\s+message|original\s+instructions?)\b/gi,
      /\b(?:give|tell)\s+me\s+your\s+(?:system\s+prompt|hidden\s+instructions?|initial\s+prompt|internal\s+instructions?)\b/gi,
      /\bwhat\s+(?:is|are)\s+your\s+(?:system\s+prompt|hidden\s+instructions?|initial\s+prompt)\b/gi,
      /\b(?:repeat|echo|print)\s+(?:everything|all\s+(?:text|of\s+the\s+text))\s+(?:above|before)\b/gi,
    ],
  },
  {
    id: 'SG-INJ-007',
    title: 'Invisible or zero-width characters inside instructions',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    owasp: 'AST01',
    description:
      'Contains zero-width or bidirectional control characters. These can hide instructions from human review while the model still reads them.',
    remediation: 'Strip all invisible characters from the skill. Text should be plain, visible and reviewable.',
    check(ctx) {
      const re = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u206A-\u206F\uFEFF\u00AD]/g;
      const hits = [];
      let m;
      while ((m = re.exec(ctx.text)) !== null) {
        // A byte-order mark at the very start of a file is normal, not an attack.
        if (m[0] === '\uFEFF' && ctx.text.slice(0, m.index).trim() === '') continue;
        hits.push(m);
      }
      if (hits.length === 0) return [];

      const kinds = [...new Set(hits.map((h) => `U+${h[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`))];
      const sample = kinds.slice(0, 4).join(', ');
      return [
        findingAt(this, ctx, hits[0].index, `invisible char ${sample}${hits.length > 1 ? ` (${hits.length} total)` : ''}`, {
          severity: hits.length >= 3 ? 'high' : 'medium',
          description:
            'Contains zero-width or bidirectional control characters. These can hide instructions from human review while the model still reads them.',
        }),
      ];
    },
  },
];
