// SPDX-License-Identifier: MIT
// Types for the attributed upstream parser in tle.mjs.
export function parseTleText(text: string): { name: string; line1: string; line2: string }[];
export function tleCatalogNumber(line1: string): number | null;
