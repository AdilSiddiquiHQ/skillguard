/**
 * SVG badge reporter — the free distribution loop.
 * Drop the SVG in your README and link it back to the reputation you earned.
 */

import { VERSION } from '../version.js';

const PALETTE = {
  pass: '#2ea44f',
  review: '#d29922',
  fail: '#d1242f',
};

function esc(text) {
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function textWidth(text) {
  return Math.round(String(text).length * 6.2) + 10;
}

export function renderBadge(report) {
  const s = report.summary;
  const verdict = s.failed > 0 ? 'fail' : s.review > 0 ? 'review' : 'pass';
  const label = 'skillsleuth';
  const value = verdict === 'pass' ? 'passing' : verdict === 'review' ? 'review' : 'failing';
  const color = PALETTE[verdict];

  const labelWidth = textWidth(label);
  const valueWidth = textWidth(value);
  const total = labelWidth + valueWidth;
  const height = 20;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="${height}" role="img" aria-label="${esc(label)}: ${esc(value)}">
  <title>${esc(label)}: ${esc(value)}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${total}" height="${height}" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="${height}" fill="#555"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="${height}" fill="${color}"/>
    <rect width="${total}" height="${height}" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="110" text-rendering="geometricPrecision">
    <text x="${labelWidth / 2 * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(labelWidth - 10) * 10}">${esc(label)}</text>
    <text x="${labelWidth / 2 * 10}" y="140" transform="scale(.1)" textLength="${(labelWidth - 10) * 10}">${esc(label)}</text>
    <text x="${(labelWidth + valueWidth / 2) * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(valueWidth - 10) * 10}">${esc(value)}</text>
    <text x="${(labelWidth + valueWidth / 2) * 10}" y="140" transform="scale(.1)" textLength="${(valueWidth - 10) * 10}">${esc(value)}</text>
  </g>
  <!-- skillsleuth ${VERSION} -->
</svg>
`;
}
