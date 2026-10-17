// SPDX-License-Identifier: Apache-2.0
import { useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import type { GeoPermissibleObjects } from "d3-geo";
import { z } from "zod";
import { message, request } from "../api";
import { Globe } from "./Globe";
import type { View } from "./Globe";
import {
  exportGeoJSON,
  layerIds,
  mapPin,
  parseLayer,
  pinSchema,
  savedPinsSchema,
  snapshotSchema,
} from "./model";
import type { LayerId, MapItem, Pin, Snapshot } from "./model";
import "./world.css";

type LayerState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; snapshot: Snapshot }
  | { kind: "error"; error: string };
const titles: Record<LayerId, string> = {
  earthquakes: "Earthquakes M2.5+",
  events: "Natural events",
  satellites: "Space stations",
  aircraft: "Aircraft · central India",
};
const notes: Record<LayerId, string> = {
  earthquakes: "USGS · past 24 hours",
  events: "NASA EONET · open, past 30 days",
  satellites: "CelesTrak · calculated positions",
  aircraft: "ADSB.lol · ODbL · 250 nm around 20°N, 79°E",
};
const landSchema = z.object({
  type: z.literal("FeatureCollection"),
  features: z.array(
    z.object({
      type: z.literal("Feature"),
      properties: z.record(z.string(), z.unknown()),
      geometry: z.object({
        type: z.literal("Polygon"),
        coordinates: z.array(z.array(z.tuple([z.number(), z.number()]))),
      }),
    }),
  ),
});

function download(items: MapItem[]) {
  const blob = new Blob([JSON.stringify(exportGeoJSON(items), null, 2)], {
    type: "application/geo+json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "godseye-world.geojson";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function WorldView() {
  const [view, setView] = useState<View>({ lon: 40, lat: 20, zoom: 1 });
  const [land, setLand] = useState<GeoPermissibleObjects | null>(null);
  const [landError, setLandError] = useState("");
  const [enabled, setEnabled] = useState<Record<LayerId, boolean>>({
    earthquakes: true,
    events: true,
    satellites: false,
    aircraft: false,
  });
  const [layers, setLayers] = useState<Record<LayerId, LayerState>>({
    earthquakes: { kind: "idle" },
    events: { kind: "idle" },
    satellites: { kind: "idle" },
    aircraft: { kind: "idle" },
  });
  const [pins, setPins] = useState<Pin[]>([]);
  const [pinStorage, setPinStorage] = useState<"loading" | "ready" | "error">(
    "loading",
  );
  const [notice, setNotice] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [revision, setRevision] = useState(0);
  const [clock, setClock] = useState(() => new Date());
  useEffect(() => {
    const controller = new AbortController();
    void fetch("/world/land.geojson", { signal: controller.signal })
      .then((response) => {
        if (!response.ok)
          throw new Error("The bundled land map could not load.");
        return response.json();
      })
      .then((value: unknown) => {
        if (!controller.signal.aborted) setLand(landSchema.parse(value));
      })
      .catch((error) => {
        if (!controller.signal.aborted) setLandError(message(error));
      });
    return () => controller.abort();
  }, []);
  useEffect(() => {
    try {
      const stored = localStorage.getItem("godseye.world.pins.v1");
      if (stored) setPins(savedPinsSchema.parse(JSON.parse(stored)).pins);
      setPinStorage("ready");
    } catch {
      setPinStorage("error");
      setNotice(
        "Saved pins could not be loaded. Existing browser storage has been preserved.",
      );
    }
  }, []);
  useEffect(() => {
    if (pinStorage !== "ready") return;
    try {
      localStorage.setItem(
        "godseye.world.pins.v1",
        JSON.stringify({ version: 1, pins }),
      );
    } catch {
      setPinStorage("error");
      setNotice(
        "Pins cannot be saved in this browser. Export your current view to preserve them.",
      );
    }
  }, [pins, pinStorage]);
  useEffect(() => {
    const timer = setInterval(() => {
      if (!document.hidden) setClock(new Date());
    }, 10000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    const timer = setInterval(() => {
      if (document.hidden) return;
      const due = layerIds.some((id) => {
        const layer = layers[id];
        return (
          enabled[id] &&
          (layer.kind === "error" ||
            (layer.kind === "ready" &&
              (layer.snapshot.status === "unavailable" ||
                (layer.snapshot.expiresAt !== null &&
                  Date.parse(layer.snapshot.expiresAt) < Date.now()))))
        );
      });
      if (due) setRevision((value) => value + 1);
    }, 60000);
    return () => clearInterval(timer);
  }, [enabled, layers]);
  useEffect(() => {
    const controller = new AbortController();
    for (const id of layerIds) {
      if (!enabled[id]) continue;
      setLayers((current) => ({ ...current, [id]: { kind: "loading" } }));
      void request(`/api/world/${id}`, { signal: controller.signal })
        .then((value) => {
          const snapshot = snapshotSchema.parse(value);
          if (snapshot.id !== id) throw new Error("Unexpected layer response.");
          parseLayer(snapshot, new Date());
          if (!controller.signal.aborted)
            setLayers((current) => ({
              ...current,
              [id]: { kind: "ready", snapshot },
            }));
        })
        .catch((error) => {
          if (!controller.signal.aborted)
            setLayers((current) => ({
              ...current,
              [id]: { kind: "error", error: message(error) },
            }));
        });
    }
    return () => controller.abort();
  }, [enabled, revision]);
  const processed = useMemo(() => {
    const items: MapItem[] = [];
    const errors: string[] = [];
    for (const id of layerIds) {
      const layer = layers[id];
      if (enabled[id] && layer.kind === "ready") {
        try {
          items.push(...parseLayer(layer.snapshot, clock));
        } catch (error) {
          errors.push(`${titles[id]}: ${message(error)}`);
        }
      }
    }
    return { items: [...items, ...pins.map(mapPin)], errors };
  }, [layers, enabled, pins, clock]);
  const active = processed.items.find((item) => item.id === selected) ?? null;
  const filtered = processed.items.filter((item) =>
    `${item.title} ${item.layer}`.toLowerCase().includes(query.toLowerCase()),
  );
  const pages = Math.max(1, Math.ceil(filtered.length / 25)),
    currentPage = Math.min(page, pages - 1);
  function select(item: MapItem) {
    setSelected(item.id);
    setView((current) => ({ ...current, lon: item.lon, lat: item.lat }));
  }
  function addPin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const result = pinSchema.safeParse({
      id: crypto.randomUUID(),
      title: data.get("title"),
      lon: Number(data.get("lon")),
      lat: Number(data.get("lat")),
    });
    if (!result.success) {
      setNotice("Use a label and valid latitude/longitude values.");
      return;
    }
    if (pins.length >= 100) {
      setNotice(
        "The limit is 100 saved pins. Export your view before removing pins.",
      );
      return;
    }
    setPins((current) => [...current, result.data]);
    setNotice("Pin added locally.");
    select(mapPin(result.data));
    form.reset();
  }
  function goTo(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const lat = Number(data.get("latitude")),
      lon = Number(data.get("longitude"));
    if (
      Number.isFinite(lat) &&
      Number.isFinite(lon) &&
      Math.abs(lat) <= 90 &&
      Math.abs(lon) <= 180
    )
      setView((current) => ({ ...current, lat, lon }));
  }
  return (
    <div className="world-workspace">
      <div className="world-topline">
        <span className="badge observed">FREE / NO API KEYS</span>
        <span>Vector globe · public data · local annotations</span>
        <button
          onClick={() => download(processed.items)}
          disabled={processed.items.length === 0}
        >
          Export GeoJSON ↓
        </button>
      </div>
      {notice && (
        <p className="notice" role="status">
          {notice}
        </p>
      )}
      {landError && (
        <p className="error" role="alert">
          {landError}
        </p>
      )}
      {processed.errors.map((error) => (
        <p className="error" role="alert" key={error}>
          {error}
        </p>
      ))}
      <div className="world-layout">
        <aside className="panel world-layers">
          <div className="panel-title">
            <h2>Public layers</h2>
            <span className="eyebrow">LIVE SOURCES</span>
          </div>
          {layerIds.map((id) => {
            const layer = layers[id];
            const count = processed.items.filter(
              (item) => item.layer === id,
            ).length;
            return (
              <div className={`world-layer ${id}`} key={id}>
                <label className="checkbox">
                  <input
                    type="checkbox"
                    checked={enabled[id]}
                    onChange={(event) => {
                      const checked = event.currentTarget.checked;
                      setEnabled((current) => ({
                        ...current,
                        [id]: checked,
                      }));
                    }}
                  />
                  <strong>{titles[id]}</strong>
                  <span className="world-layer-dot" />
                </label>
                <small>{notes[id]}</small>
                <div className="world-layer-status" aria-live="polite">
                  {!enabled[id]
                    ? "Off"
                    : layer.kind === "idle"
                      ? "Waiting"
                      : layer.kind === "loading"
                        ? "Loading…"
                        : layer.kind === "error"
                          ? layer.error
                          : layer.snapshot.status === "unavailable"
                            ? "Unavailable"
                            : `${count} records · ${layer.snapshot.status !== "fresh" ? layer.snapshot.status : layer.snapshot.expiresAt && Date.parse(layer.snapshot.expiresAt) < clock.getTime() ? "refresh due" : "fresh"}`}
                </div>
                {enabled[id] && layer.kind === "ready" && (
                  <>
                    <small>
                      {layer.snapshot.fetchedAt
                        ? `Fetched ${new Date(layer.snapshot.fetchedAt).toLocaleString()}`
                        : "Not fetched"}
                    </small>
                    {layer.snapshot.error && (
                      <p className="world-feed-error">{layer.snapshot.error}</p>
                    )}
                    <a
                      href={layer.snapshot.sourceUrl}
                      target="_blank"
                      rel="noreferrer"
                    >
                      Source ↗
                    </a>
                  </>
                )}
              </div>
            );
          })}
          <button onClick={() => setRevision((value) => value + 1)}>
            Refresh enabled layers
          </button>
          <p className="muted small">
            Earthquakes cache for 1 minute; natural events for 10 minutes;
            orbital elements for 2 hours; aircraft for 30 seconds. Enabled
            layers are checked for refresh each minute. Provider outages remain
            visible.
          </p>
          <form className="world-view-fields" onSubmit={goTo}>
            <h3>Go to coordinates</h3>
            <label>
              Latitude
              <input
                required
                name="latitude"
                type="number"
                min={-90}
                max={90}
                step="any"
                defaultValue="20"
              />
            </label>
            <label>
              Longitude
              <input
                required
                name="longitude"
                type="number"
                min={-180}
                max={180}
                step="any"
                defaultValue="40"
              />
            </label>
            <button type="submit">Go to coordinates</button>
            <div className="inline-actions">
              <button
                type="button"
                onClick={() => setView({ lon: 78.96, lat: 20.59, zoom: 1 })}
              >
                India
              </button>
              <button
                type="button"
                onClick={() => setView({ lon: -20, lat: 20, zoom: 1 })}
              >
                Atlantic
              </button>
            </div>
          </form>
        </aside>
        <section className="panel world-stage">
          <div className="panel-title">
            <h2>World view</h2>
            <span className="eyebrow">{processed.items.length} RECORDS</span>
          </div>
          <Globe
            land={land}
            items={processed.items}
            view={view}
            setView={setView}
            selected={selected}
            select={select}
          />
          <div className="world-inspector" aria-live="polite">
            {active ? (
              <>
                <span className={`badge ${active.layer}`}>{active.layer}</span>
                <h3>{active.title}</h3>
                <p>{active.detail}</p>
                <code>
                  {active.lat.toFixed(4)}°, {active.lon.toFixed(4)}°
                </code>
                {active.observedAt && (
                  <p className="muted small">
                    Observation / calculation:{" "}
                    {new Date(active.observedAt).toLocaleString()}
                  </p>
                )}
                {active.url && (
                  <a href={active.url} target="_blank" rel="noreferrer">
                    Provider details ↗
                  </a>
                )}
                {active.layer === "pins" && (
                  <button
                    onClick={() => {
                      setPins((current) =>
                        current.filter((pin) => pin.id !== active.id),
                      );
                      setSelected(null);
                    }}
                  >
                    Remove this pin
                  </button>
                )}
              </>
            ) : (
              <>
                <h3>Select a record to inspect its evidence.</h3>
                <p>
                  Rotate the globe or use the record list below. Satellite
                  markers show estimated ground positions, not surveillance
                  imagery.
                </p>
              </>
            )}
          </div>
        </section>
      </div>
      <div className="world-lower">
        <section className="panel">
          <div className="panel-title">
            <h2>Enabled layers / record list</h2>
            <span className="count">{filtered.length}</span>
          </div>
          <label className="search-label">
            Filter map records
            <input
              type="search"
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(0);
              }}
              placeholder="Search location, event, station or pin"
            />
          </label>
          {filtered.length === 0 ? (
            <div className="empty">
              <h3>No records in the enabled layers</h3>
              <p>
                Enable a layer, refresh it, or add your own pin. An unavailable
                feed is never replaced by invented live data.
              </p>
            </div>
          ) : (
            <div className="world-records">
              {filtered
                .slice(currentPage * 25, currentPage * 25 + 25)
                .map((item) => (
                  <button
                    key={item.id}
                    className={selected === item.id ? "selected" : ""}
                    onClick={() => select(item)}
                  >
                    <span className={`world-record-dot ${item.layer}`} />
                    <span>
                      <strong>{item.title}</strong>
                      <small>
                        {item.layer} · {item.lat.toFixed(2)}°,{" "}
                        {item.lon.toFixed(2)}°
                      </small>
                    </span>
                    <span>↗</span>
                  </button>
                ))}
            </div>
          )}
          <div className="pagination">
            <button
              disabled={currentPage === 0}
              onClick={() => setPage(currentPage - 1)}
            >
              Previous
            </button>
            <span>
              {currentPage + 1} / {pages}
            </span>
            <button
              disabled={currentPage + 1 >= pages}
              onClick={() => setPage(currentPage + 1)}
            >
              Next
            </button>
          </div>
        </section>
        <section className="panel world-pins">
          <h2>Your map pins</h2>
          <p className="muted small">
            Saved in this browser, on this origin. Export GeoJSON to keep a
            portable copy.
          </p>
          <form onSubmit={addPin} className="form-stack">
            <label>
              Pin label
              <input
                required
                name="title"
                maxLength={100}
                placeholder="My infrastructure location"
              />
            </label>
            <label>
              Pin latitude
              <input
                required
                name="lat"
                type="number"
                min={-90}
                max={90}
                step="any"
                placeholder="20.59"
              />
            </label>
            <label>
              Pin longitude
              <input
                required
                name="lon"
                type="number"
                min={-180}
                max={180}
                step="any"
                placeholder="78.96"
              />
            </label>
            <button
              className="primary"
              disabled={pinStorage !== "ready" || pins.length >= 100}
            >
              + Save map pin
            </button>
          </form>
          <p className="muted small">
            {pins.length} / 100 pins saved. This does not locate assets
            automatically.
          </p>
        </section>
      </div>
      <details className="panel world-attribution">
        <summary>Sources, attribution and what is included</summary>
        <p>
          Source helpers adapted from{" "}
          <a
            href="https://github.com/bilawalsidhu/gods-eye-view"
            target="_blank"
            rel="noreferrer"
          >
            God's Eye View by Bilawal Sidhu
          </a>
          , MIT. Globe land data: Natural Earth, public domain. Public feeds:
          USGS, NASA EONET and CelesTrak, under their respective usage policies.
          Source data can be delayed or revised. Regional aircraft data ©
          ADSB.lol contributors,{" "}
          <a
            href="https://www.adsb.lol/docs/open-data/api/"
            target="_blank"
            rel="noreferrer"
          >
            ODbL 1.0
          </a>
          . Attribution and share-alike obligations apply when redistributing
          derived databases.
        </p>
        <p>
          This section includes a vector globe, earthquake/natural-event layers,
          calculated station positions, regional aircraft, record inspection,
          local pins and GeoJSON export. It has no paid imagery, photorealistic
          tiles, provider keys, AI voice, camera feeds, ship feeds or restricted
          bundled datasets.
        </p>
        <p>
          Station TLEs cover the available five-digit catalog subset. The globe
          is a geographic context view, not an indication of security coverage
          or asset ownership.
        </p>
      </details>
    </div>
  );
}
