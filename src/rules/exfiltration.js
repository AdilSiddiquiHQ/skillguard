/**
 * Exfiltration rules (OWASP Agentic Skills: AST04).
 * Detection focuses on the combination of (a) secret-bearing data and
 * (b) an outbound network sink.
 */

import { findingAt } from './helpers.js';

export const exfiltrationRules = [
  {
    id: 'SG-EXFIL-001',
    title: 'Uploads data to a remote endpoint',
    severity: 'high',
    confidence: 'medium',
    category: 'exfiltration',
    owasp: 'AST04',
    description: 'Sends a request body or uploads a file to a remote host. Combined with credential access this is data theft.',
    remediation: 'State exactly what is sent and to which host. Prefer hosts the user configured themselves.',
    patterns: [
      /\b(?:curl|wget)\b[^\n]{0,200}(?:--data(?:-raw|-binary|-urlencode)?\b|--upload-file\b|--post-data\b|--post-file\b|\s-d\s|\s-F\s|\s-T\s)/gi,
      /\b(?:requests|httpx)\.(?:post|put|patch)\s*\(/g,
      /\bfetch\s*\([^)]*method\s*:\s*['"](?:POST|PUT|PATCH)['"]/gi,
      /\bInvoke-(?:RestMethod|WebRequest)\b[^\n]{0,120}-Method\s+(?:Post|Put|Patch)/gi,
      /\bhttp\.client\b|\bnet\/http\b[^\n]{0,40}NewRequest/gi,
    ],
  },
  {
    id: 'SG-EXFIL-002',
    title: 'Posts to a known exfiltration sink',
    severity: 'critical',
    confidence: 'high',
    category: 'exfiltration',
    owasp: 'AST04',
    description: 'References a service commonly used to receive stolen data (webhooks, request bins, tunnelling and collaborator domains).',
    remediation: 'Remove the sink. If telemetry is intended, use a first-party endpoint the user can see and disable.',
    patterns: [
      /discord(?:app)?\.com\/api\/webhooks/gi,
      /hooks\.slack\.com|slack\.com\/api\/chat\.post/gi,
      /api\.telegram\.org\/bot/gi,
      /webhook\.site|requestbin|pipedream\.net|hookbin|beeceptor|requestcatcher/gi,
      /burpcollaborator\.net|interact\.sh|oast\.(?:fun|pro|me|live|online)|dnslog\.cn/gi,
      /(?:ngrok|serveo|localhost\.run|localtunnel)\.(?:io|me|net)/gi,
      /pastebin\.com|paste\.ee|ghostbin|termbin\.com|0x0\.st|transfer\.sh/gi,
    ],
  },
  {
    id: 'SG-EXFIL-003',
    title: 'Encodes data before sending it',
    severity: 'high',
    confidence: 'medium',
    category: 'exfiltration',
    owasp: 'AST04',
    description: 'Base64-encodes or compresses content next to a network call — a common way to smuggle secrets past review.',
    remediation: 'Never encode data for transmission. Send plain, reviewable payloads to documented endpoints.',
    check(ctx) {
      const out = [];
      const encodeRe = /\b(?:base64|b64encode|toBase64String|xxd\s+-p|gzip|tar\s+-cz|openssl\s+enc)\b/gi;
      const netRe = /\b(?:curl|wget|nc|ncat|requests\.(?:post|put)|fetch\s*\(|Invoke-RestMethod|http\.client)\b/gi;
      const encodeHits = [...ctx.text.matchAll(encodeRe)].map((m) => m.index);
      const netHits = [...ctx.text.matchAll(netRe)].map((m) => m.index);
      for (const e of encodeHits) {
        if (netHits.some((n) => Math.abs(n - e) < 400)) {
          out.push(findingAt(this, ctx, e, ctx.text.slice(e, e + 60)));
        }
      }
      return out;
    },
  },
  {
    id: 'SG-EXFIL-004',
    title: 'Pipes secrets straight into the network',
    severity: 'critical',
    confidence: 'high',
    category: 'exfiltration',
    owasp: 'AST04',
    description: 'Pipes environment variables or .env contents into a network client. There is no legitimate reason to do this.',
    remediation: 'Remove entirely.',
    patterns: [
      /\b(?:env|printenv|cat\s+[^\n|]*\.env[^\n|]*|set)\b[^\n]{0,80}\|\s*(?:curl|wget|nc|ncat|base64|openssl|dig|nslookup|mail)\b/gi,
      /\.env[^\n|]{0,40}\|\s*(?:curl|wget|nc|ncat)\b/gi,
    ],
  },
  {
    id: 'SG-EXFIL-005',
    title: 'Raw socket or reverse-shell style connection',
    severity: 'critical',
    confidence: 'high',
    category: 'exfiltration',
    owasp: 'AST04',
    description: 'Uses netcat, /dev/tcp, or a similar raw socket to open an outbound connection or shell.',
    remediation: 'Remove. Use documented HTTP APIs with explicit consent.',
    patterns: [
      /\bnc\s+(?:-[a-z]*e[a-z]*|-[a-z]*l[a-z]*|-v\b|\d+\.\d+\.\d+\.\d+)/gi,
      /\bncat\b/gi,
      /\/dev\/tcp\/|\/dev\/udp\//gi,
      /bash\s+-i\s*>&\s*\/dev\/tcp/gi,
      /\bsocat\b[^\n]{0,60}(?:exec|tcp)/gi,
      /\bpython3?\s+-c\s*['"][^'"]*socket\.socket/gi,
    ],
  },
  {
    id: 'SG-EXFIL-006',
    title: 'DNS-based exfiltration pattern',
    severity: 'high',
    confidence: 'medium',
    category: 'exfiltration',
    owasp: 'AST04',
    description: 'Builds a DNS lookup from computed data, a classic low-and-slow exfiltration channel.',
    remediation: 'Remove dynamic DNS lookups that embed data.',
    patterns: [
      /\b(?:dig|nslookup|host|Resolve-DnsName)\b[^\n]{0,100}(?:\$\(|`|\$\{)/gi,
    ],
  },
];
