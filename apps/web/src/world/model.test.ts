// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { geoDistance } from "d3-geo";
import {
  exportGeoJSON,
  parseLayer,
  safeURL,
  satelliteItems,
  savedPinsSchema,
} from "./model";
import type { Snapshot } from "./model";
import { parseTleText } from "./upstream/tle.mjs";

function snapshot(body: unknown, id: Snapshot["id"] = "earthquakes"): Snapshot {
  return {
    id,
    source: "fixture",
    sourceUrl: "https://example.org",
    status: "fresh",
    fetchedAt: new Date().toISOString(),
    expiresAt: new Date().toISOString(),
    body: typeof body === "string" ? body : JSON.stringify(body),
    error: "",
  };
}
const quake = {
  features: [
    {
      id: "test",
      geometry: { type: "Point", coordinates: [78, 20, 12] },
      properties: { mag: 4.2, place: "Fixture only", time: 1700000000000 },
    },
  ],
};

test("adapted earthquake normalization rejects malformed snapshots and filters magnitude", () => {
  const items = parseLayer(snapshot(quake), new Date());
  assert.equal(items.length, 1);
  assert.equal(items[0].lon, 78);
  assert.equal(items[0].lat, 20);
  assert.throws(() =>
    parseLayer(
      snapshot({
        features: [
          { geometry: { coordinates: [181, 20] }, properties: { mag: 4 } },
        ],
      }),
      new Date(),
    ),
  );
  assert.equal(
    parseLayer(
      snapshot({
        features: [
          { geometry: { coordinates: [0, 0] }, properties: { mag: 1 } },
        ],
      }),
      new Date(),
    ).length,
    0,
  );
});

test("NASA events use latest valid point and never turn source text into script links", () => {
  const body = {
    events: [
      {
        id: "demo",
        title: "Fixture event",
        categories: [{ title: "Wildfires" }],
        sources: [{ url: "javascript:alert(1)" }],
        geometry: [
          { type: "Point", coordinates: [2, 3], date: "2026-10-16T00:00:00Z" },
          { type: "Point", coordinates: [4, 5], date: "2026-10-17T00:00:00Z" },
        ],
      },
    ],
  };
  const items = parseLayer(snapshot(body, "events"), new Date());
  assert.equal(items[0].lon, 4);
  assert.equal(items[0].url, null);
  assert.equal(safeURL("https://user:password@example.org"), null);
  assert.equal(safeURL("https://example.org/"), "https://example.org/");
});

function checksum(line: string): string {
  const body = line.slice(0, 68).padEnd(68, " ");
  let sum = 0;
  for (const char of body) {
    if (char >= "0" && char <= "9") sum += Number(char);
    else if (char === "-") sum++;
  }
  return body + String(sum % 10);
}
const line1 = checksum(
  "1 25544U 98067A   26289.78971907  .00007803  00000+0  15012-3 0  9994",
);
const line2 = checksum(
  "2 25544  51.6326  58.3200 0004100  21.0000 339.0000 15.49000000400000",
);

test("adapted TLE parser recovers valid sets; SGP4 yields changing finite positions", () => {
  const text = `bad\nnot a TLE\nISS (FIXTURE)\n${line1}\n${line2}\n`;
  assert.equal(parseTleText(text).length, 1);
  const before = satelliteItems(text, new Date("2026-10-17T00:00:00Z"));
  const after = satelliteItems(text, new Date("2026-10-17T00:01:00Z"));
  assert.equal(before.length, 1);
  assert.equal(after.length, 1);
  assert.ok(Number.isFinite(before[0].lat));
  assert.ok((before[0].altitudeKm ?? 0) > 0);
  assert.notEqual(before[0].lon, after[0].lon);
  const corrupt = `ISS\n${line1.slice(0, 68)}${(Number(line1[68]) + 1) % 10}\n${line2}`;
  assert.equal(satelliteItems(corrupt, new Date()).length, 0);
});

test("saved pins are bounded and GeoJSON preserves longitude/latitude order", () => {
  assert.equal(
    savedPinsSchema.safeParse({
      version: 1,
      pins: [{ id: "pin", title: "A", lat: 91, lon: 0 }],
    }).success,
    false,
  );
  const items = parseLayer(snapshot(quake), new Date());
  const exported = exportGeoJSON(items);
  assert.deepEqual(exported.features[0].geometry.coordinates, [78, 20]);
  assert.equal(exported.features[0].properties.layer, "earthquakes");
});

test("globe hemisphere test distinguishes front and back", () => {
  assert.ok(geoDistance([0, 0], [10, 0]) < Math.PI / 2);
  assert.ok(geoDistance([0, 0], [180, 0]) > Math.PI / 2);
});

test("regional aircraft reject stale positions and preserve data attribution", () => {
  const at = new Date("2026-10-17T00:00:00Z");
  const data = {
    now: at.getTime(),
    ac: [
      {
        hex: "abc123",
        flight: "TEST001",
        lat: 20,
        lon: 79,
        seen_pos: 1,
        alt_baro: 30000,
      },
      { hex: "stale", lat: 20, lon: 79, seen_pos: 500 },
    ],
  };
  const items = parseLayer(snapshot(data, "aircraft"), at);
  assert.equal(items.length, 1);
  assert.equal(items[0].title, "Aircraft TEST001");
  assert.match(items[0].detail, /ODbL/);
  assert.match(exportGeoJSON(items).dataLicenses.aircraft, /ODbL/);
});
