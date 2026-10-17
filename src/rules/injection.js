/**
 * Prompt-injection and manipulation rules (OWASP Agentic Skills: AST01/AST02).
 * A skill is untrusted input that runs with your agent's privileges, so
 * instructions that override, hide from, or bypass the user are attacks.
 */

import { findingAt } from './helpers.js';

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
    patterns: [
      /\b(?:ignore|disregard|forget|discard|skip)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|earlier|above|preceding|foregoing|original|system|initial)\s+(?:instructions?|prompts?|rules?|messages?|directions?|context|guidelines?)/gi,
      /\boverride\s+(?:your|the|all|any)\s+(?:instructions?|system|prompt|rules?|safety|guardrails?|restrictions?)/gi,
      /\bfrom\s+now\s+on\s*,?\s*(?:you|ignore|disregard|do\s+not)/gi,
    ],
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
      /\b(?:do\s*n[o']?t|never|without)\s+(?:tell|informing|notify|mention|reveal|disclose|inform|alert|show|report)\b[^.\n]{0,40}\b(?:the\s+)?(?:user|human|operator|owner|developer)\b/gi,
      /\b(?:secretly|covertly|silently|quietly|without\s+(?:telling|informing|notifying|alerting))\b/gi,
      /\bdo\s*n[o']?t\s+(?:log|record|audit|write\s+to\s+(?:the\s+)?log)/gi,
      /\bkeep\s+(?:this|it|your\s+actions?)\s+(?:hidden|secret|quiet|private)\b/gi,
      /\b(?:hide|conceal|obscure)\s+(?:this|it|your)\b/gi,
    ],
  },
  {
    id: 'SG-INJ-004',
    title: 'Instructions to bypass approvals or safety checks',
    severity: 'critical',
    confidence: 'high',
    category: 'injection',
    owasp: 'AST01',
    description:
      'Asks the agent to skip confirmation, disable guardrails, or auto-approve actions. This removes the human control that keeps agents safe.',
    remediation: 'Remove the instruction. Keep human-in-the-loop confirmation for any impactful action.',
    patterns: [
      /\b(?:bypass|skip|disable|circumvent|turn\s+off|ignore)\s+(?:the\s+)?(?:approval|confirmation|safety|security|guardrail|permission|sandbox|restriction|consent|check)/gi,
      /\bwithout\s+(?:asking|confirmation|approval|permission|consent|checking)/gi,
      /\bauto[-\s]?approve\b/gi,
      /\bno\s+need\s+to\s+(?:ask|confirm|check)\b/gi,
      /--dangerously-skip-permissions/gi,
      /\byolo\s+mode\b/gi,
    ],
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
      /\b(?:when|if|whenever)\s+(?:you|the\s+user)\s+(?:says?|types?|writes?|mentions?|sends?|utters?)\b[^\n]{0,60}\b(?:then|,|:|,?\s+(?:start|run|execute|do))/gi,
      /\btrigger\s+(?:word|phrase|command)\b/gi,
      /\bon\s+receipt\s+of\s+(?:the\s+)?(?:signal|word|message)\b/gi,
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
      /\b(?:reveal|print|show|output|repeat|leak|dump|echo|display)\b[^\n]{0,40}\b(?:your\s+)?(?:system\s+prompt|hidden\s+instructions?|initial\s+prompt|internal\s+instructions?|configuration)\b/gi,
      /\bwhat\s+(?:is|are)\s+your\s+(?:system\s+prompt|hidden|initial)\s+(?:prompt|instructions?)\b/gi,
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
      const out = [];
      const re = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u206A-\u206F\uFEFF\u00AD]/g;
      let m;
      while ((m = re.exec(ctx.text)) !== null) {
        const code = m[0].codePointAt(0).toString(16).padStart(4, '0');
        out.push(
          findingAt(this, ctx, m.index, `invisible char U+${code.toUpperCase()}`)
        );
      }
      return out;
    },
  },
];
