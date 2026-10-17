// SPDX-License-Identifier: Apache-2.0
// Adapted from gchq/CyberChef at cc70a4530b86aff4bc40ccc74b1ad4857eccdca2.
// Entropy.mjs calculateShannonEntropy, Crown Copyright 2016, n1474335.
// DefangURL.mjs defangURL, Crown Copyright 2018, arnydo and n1474335.
// Changes: typed functions, zero-entropy normalization, fixed defang options.
// Full license: licenses/cyberchef.txt. No upstream renderer or engine is bundled.

export function shannonEntropy(input: Uint8Array): number {
  if (input.length === 0) return 0;
  const occurrences = new Array<number>(256).fill(0);
  for (const value of input) occurrences[value]++;
  let entropy = 0;
  for (const count of occurrences) {
    if (count > 0) {
      const probability = count / input.length;
      entropy += (probability * Math.log(probability)) / Math.log(2);
    }
  }
  return entropy === 0 ? 0 : -entropy;
}

export function defangURL(input: string): string {
  return input
    .replace(/\./g, "[.]")
    .replace(/http/gi, "hxxp")
    .replace(/:\/\//g, "[://]");
}
