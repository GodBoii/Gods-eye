// SPDX-License-Identifier: Apache-2.0
import { z } from "zod";
import {
  twoline2satrec,
  propagate,
  gstime,
  eciToGeodetic,
  degreesLat,
  degreesLong,
} from "satellite.js";
import { normalizeEarthquakeSnapshot } from "./upstream/earthquakes.mjs";
import { parseTleText, tleCatalogNumber } from "./upstream/tle.mjs";

export const layerIds = [
  "earthquakes",
  "events",
  "satellites",
  "aircraft",
] as const;
export type LayerId = (typeof layerIds)[number];
export const snapshotSchema = z.object({
  id: z.enum(layerIds),
  source: z.string(),
  sourceUrl: z.url(),
  status: z.enum(["fresh", "stale", "unavailable"]),
  fetchedAt: z.string().nullable(),
  expiresAt: z.string().nullable(),
  body: z.string().max(2 << 20),
  error: z.string(),
});
export type Snapshot = z.infer<typeof snapshotSchema>;
export type MapItem = {
  id: string;
  layer: LayerId | "pins";
  title: string;
  lon: number;
  lat: number;
  detail: string;
  observedAt: string | null;
  url: string | null;
  altitudeKm?: number;
};
export const pinSchema = z.object({
  id: z.string().max(128),
  title: z.string().trim().min(1).max(100),
  lon: z.number().finite().min(-180).max(180),
  lat: z.number().finite().min(-90).max(90),
});
export const savedPinsSchema = z.object({
  version: z.literal(1),
  pins: z.array(pinSchema).max(100),
});
export type Pin = z.infer<typeof pinSchema>;
const coordinate = z.tuple([
  z.number().finite().min(-180).max(180),
  z.number().finite().min(-90).max(90),
]);
const eventSchema = z.object({
  events: z
    .array(
      z.object({
        id: z.string(),
        title: z.string(),
        categories: z.array(z.object({ title: z.string() })),
        sources: z.array(z.object({ url: z.string() })),
        geometry: z
          .array(
            z.object({
              type: z.string(),
              coordinates: z.unknown(),
              date: z.string(),
            }),
          )
          .max(2000),
      }),
    )
    .max(200),
});

export function safeURL(value: string | null): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return (url.protocol === "https:" || url.protocol === "http:") &&
      !url.username &&
      !url.password
      ? url.href
      : null;
  } catch {
    return null;
  }
}

export function parseLayer(snapshot: Snapshot, at: Date): MapItem[] {
  if (snapshot.status === "unavailable") return [];
  if (snapshot.id === "satellites") return satelliteItems(snapshot.body, at);
  const payload: unknown = JSON.parse(snapshot.body);
  if (snapshot.id === "aircraft") return aircraftItems(payload, snapshot, at);
  if (snapshot.id === "earthquakes") {
    const rows = normalizeEarthquakeSnapshot(payload);
    if (!rows)
      throw new Error("USGS returned malformed coordinates or records.");
    return rows.slice(0, 2000).map((row) => ({
      id: `earthquake:${row.stableId}`,
      layer: "earthquakes",
      title: `M${row.mag.toFixed(1)} · ${(row.place ?? "Location unspecified").slice(0, 200)}`,
      lon: row.lon,
      lat: row.lat,
      detail: `Magnitude ${row.mag}; depth ${row.depthKm === null ? "unknown" : row.depthKm.toFixed(1) + " km"}. USGS events may be revised.`,
      observedAt: row.time === null ? null : new Date(row.time).toISOString(),
      url: row.usgsId
        ? safeURL(
            `https://earthquake.usgs.gov/earthquakes/eventpage/${encodeURIComponent(row.usgsId)}`,
          )
        : null,
    }));
  }
  const data = eventSchema.parse(payload);
  return data.events.flatMap((event) => {
    const locations = event.geometry
      .filter((geometry) => geometry.type === "Point")
      .map((geometry) => ({
        geometry,
        parsed: coordinate.safeParse(geometry.coordinates),
      }))
      .filter((value) => value.parsed.success);
    const latest = locations.sort(
      (a, b) => Date.parse(b.geometry.date) - Date.parse(a.geometry.date),
    )[0];
    if (!latest || !latest.parsed.success) return [];
    const [lon, lat] = latest.parsed.data;
    return [
      {
        id: `event:${event.id}`,
        layer: "events" as const,
        title: event.title.slice(0, 200),
        lon,
        lat,
        detail: `${event.categories.map((category) => category.title).join(", ")}. Latest reported point; event outlines and affected areas are not shown.`,
        observedAt: latest.geometry.date,
        url: safeURL(event.sources[0]?.url ?? null),
      },
    ];
  });
}

function validTLE(line: string, prefix: string): boolean {
  if (line.length !== 69 || !line.startsWith(prefix)) return false;
  let checksum = 0;
  for (const char of line.slice(0, 68)) {
    if (char >= "0" && char <= "9") checksum += Number(char);
    else if (char === "-") checksum++;
  }
  return checksum % 10 === Number(line[68]);
}

export function satelliteItems(body: string, at: Date): MapItem[] {
  return parseTleText(body)
    .slice(0, 200)
    .flatMap((row) => {
      if (
        !validTLE(row.line1, "1 ") ||
        !validTLE(row.line2, "2 ") ||
        row.line1.slice(2, 7) !== row.line2.slice(2, 7)
      )
        return [];
      const record = twoline2satrec(row.line1, row.line2);
      const elementAgeDays =
        at.getTime() / 86400000 + 2440587.5 - record.jdsatepoch;
      if (!Number.isFinite(elementAgeDays) || Math.abs(elementAgeDays) > 14)
        return [];
      const state = propagate(record, at);
      if (!state || !state.position) return [];
      const location = eciToGeodetic(state.position, gstime(at));
      const lon = degreesLong(location.longitude),
        lat = degreesLat(location.latitude);
      if (
        !Number.isFinite(lon) ||
        !Number.isFinite(lat) ||
        !Number.isFinite(location.height) ||
        location.height < 0
      )
        return [];
      return [
        {
          id: `satellite:${row.line1.slice(2, 7)}`,
          layer: "satellites" as const,
          title: row.name.slice(0, 100),
          lon,
          lat,
          detail: `NORAD ${tleCatalogNumber(row.line1) ?? "unknown"}; estimated altitude ${location.height.toFixed(0)} km. SGP4 position calculated from orbital elements, not a live GPS measurement. TLE epoch ${row.line1.slice(18, 32).trim()}.`,
          observedAt: at.toISOString(),
          url: "https://celestrak.org/NORAD/elements/",
          altitudeKm: location.height,
        },
      ];
    });
}

export function mapPin(pin: Pin): MapItem {
  return {
    ...pin,
    layer: "pins",
    detail: "Your locally saved map annotation.",
    observedAt: null,
    url: null,
  };
}

export function exportGeoJSON(items: MapItem[]) {
  return {
    type: "FeatureCollection",
    exportedAt: new Date().toISOString(),
    dataLicenses: {
      aircraft:
        "ADSB.lol data © ADSB.lol contributors, ODbL 1.0. https://www.adsb.lol/docs/open-data/api/ . Other layers retain their respective source terms.",
    },
    features: items.map((item) => ({
      type: "Feature",
      id: item.id,
      geometry: { type: "Point", coordinates: [item.lon, item.lat] },
      properties: {
        title: item.title,
        layer: item.layer,
        detail: item.detail,
        observedAt: item.observedAt,
        source: item.url,
      },
    })),
  };
}

const aircraftSchema = z.object({
  now: z.number().finite(),
  ac: z
    .array(
      z.object({
        hex: z.string().max(16),
        flight: z.string().max(30).optional(),
        lat: z.number().finite().optional(),
        lon: z.number().finite().optional(),
        seen_pos: z.number().finite().optional(),
        alt_baro: z.union([z.number().finite(), z.string()]).optional(),
      }),
    )
    .max(5000),
});

function aircraftItems(
  payload: unknown,
  snapshot: Snapshot,
  at: Date,
): MapItem[] {
  const data = aircraftSchema.parse(payload);
  const providerTime = data.now > 1e12 ? data.now : data.now * 1000;
  return data.ac.flatMap((record) => {
    const coordinates = coordinate.safeParse([record.lon, record.lat]);
    if (
      !coordinates.success ||
      record.seen_pos === undefined ||
      record.seen_pos < 0
    )
      return [];
    const observed = providerTime - record.seen_pos * 1000;
    if (at.getTime() - observed > 120000 || observed - at.getTime() > 60000)
      return [];
    const [lon, lat] = coordinates.data;
    const callsign = record.flight?.trim() || record.hex;
    return [
      {
        id: `aircraft:${record.hex}`,
        layer: "aircraft" as const,
        title: `Aircraft ${callsign}`,
        lon,
        lat,
        detail: `ADSB.lol · ODbL 1.0. Reported position within 250 nautical miles of 20°N, 79°E. Barometric altitude ${typeof record.alt_baro === "number" ? record.alt_baro.toFixed(0) + " ft" : (record.alt_baro ?? "unknown")}. Coverage depends on volunteer receivers; positions older than two minutes are hidden.`,
        observedAt: new Date(observed).toISOString(),
        url: safeURL(snapshot.sourceUrl),
      },
    ];
  });
}
