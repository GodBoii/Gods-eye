// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bilawal Sidhu. See licenses/gods-eye-view.txt.
// Vendored from bilawalsidhu/gods-eye-view at 1df2a272cf7cfbb2f1a4c637c897e90719b0af95, src/sources/tle.js.
/**
 * Parse three-line TLE catalog text into `{ name, line1, line2 }` entries.
 * Malformed sets are skipped without dropping the valid sets that follow.
 */
export function parseTleText(text) {
  const lines = String(text)
    .trim()
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const result = [];
  for (let i = 0; i < lines.length - 2; i++) {
    const name = lines[i];
    const line1 = lines[i + 1];
    const line2 = lines[i + 2];
    if (line1.startsWith('1 ') && line2.startsWith('2 ')) {
      result.push({ name, line1, line2 });
      i += 2;
    }
  }
  return result;
}

/** The NORAD catalog number from TLE line 1, or null. */
export function tleCatalogNumber(line1) {
  const number = Number.parseInt(String(line1).slice(2, 7), 10);
  return Number.isInteger(number) ? number : null;
}
