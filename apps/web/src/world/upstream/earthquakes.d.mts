// SPDX-License-Identifier: MIT
// Types for the attributed upstream normalizer in earthquakes.mjs.
export type Earthquake = {
 stableId: string; usgsId: string | null; lon: number; lat: number;
 depthKm: number | null; mag: number; place: string | null; time: number | null;
};
export function normalizeEarthquakeSnapshot(payload: unknown): Earthquake[] | null;
