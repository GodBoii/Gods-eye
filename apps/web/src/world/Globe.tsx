// SPDX-License-Identifier: Apache-2.0
import { useMemo, useRef } from "react";
import type { Dispatch, SetStateAction } from "react";
import { geoDistance, geoGraticule10, geoOrthographic, geoPath } from "d3-geo";
import type { GeoPermissibleObjects } from "d3-geo";
import type { MapItem } from "./model";

export type View = { lon: number; lat: number; zoom: number };
export function moveView(current: View, lon: number, lat: number): View {
  return {
    ...current,
    lon: ((lon + 540) % 360) - 180,
    lat: Math.max(-85, Math.min(85, lat)),
  };
}

export function Globe({
  land,
  items,
  view,
  setView,
  selected,
  select,
}: {
  land: GeoPermissibleObjects | null;
  items: MapItem[];
  view: View;
  setView: Dispatch<SetStateAction<View>>;
  selected: string | null;
  select: (item: MapItem) => void;
}) {
  const drag = useRef<{
    x: number;
    y: number;
    lon: number;
    lat: number;
  } | null>(null);
  const projection = useMemo(
    () =>
      geoOrthographic()
        .translate([360, 270])
        .scale(228 * view.zoom)
        .rotate([-view.lon, -view.lat]),
    [view],
  );
  const path = geoPath(projection);
  const visible = items.filter(
    (item) =>
      geoDistance([item.lon, item.lat], [view.lon, view.lat]) <
      Math.PI / 2 - 0.005,
  );
  return (
    <div className="world-globe">
      <svg
        viewBox="0 0 720 540"
        role="img"
        aria-label="Interactive world globe. Drag to rotate, use arrow keys to pan, and plus or minus to zoom."
        tabIndex={0}
        onKeyDown={(event) => {
          const steps: Record<string, [number, number]> = {
            ArrowLeft: [-15, 0],
            ArrowRight: [15, 0],
            ArrowUp: [0, 10],
            ArrowDown: [0, -10],
          };
          const step = steps[event.key];
          if (step) {
            event.preventDefault();
            setView((current) =>
              moveView(current, current.lon + step[0], current.lat + step[1]),
            );
          }
          if (event.key === "+" || event.key === "-") {
            event.preventDefault();
            setView((current) => ({
              ...current,
              zoom: Math.max(
                0.7,
                Math.min(
                  2.2,
                  current.zoom + (event.key === "+" ? 0.15 : -0.15),
                ),
              ),
            }));
          }
        }}
        onPointerDown={(event) => {
          if (event.button !== 0) return;
          drag.current = {
            x: event.clientX,
            y: event.clientY,
            lon: view.lon,
            lat: view.lat,
          };
          event.currentTarget.setPointerCapture(event.pointerId);
        }}
        onPointerMove={(event) => {
          const start = drag.current;
          if (start)
            setView((current) =>
              moveView(
                current,
                start.lon - (event.clientX - start.x) * 0.35,
                start.lat + (event.clientY - start.y) * 0.35,
              ),
            );
        }}
        onPointerUp={() => {
          drag.current = null;
        }}
        onPointerCancel={() => {
          drag.current = null;
        }}
      >
        <title>Public-source world view</title>
        <defs>
          <radialGradient id="ocean">
            <stop offset="0" stopColor="#1b333a" />
            <stop offset=".85" stopColor="#10272e" />
            <stop offset="1" stopColor="#0b161c" />
          </radialGradient>
          <clipPath id="world-disc">
            <circle cx="360" cy="270" r={228 * view.zoom} />
          </clipPath>
        </defs>
        <circle
          cx="360"
          cy="270"
          r={228 * view.zoom + 5}
          className="world-atmosphere"
        />
        <circle cx="360" cy="270" r={228 * view.zoom} fill="url(#ocean)" />
        <g clipPath="url(#world-disc)">
          {land && <path d={path(land) ?? undefined} className="world-land" />}
          <path
            d={path(geoGraticule10()) ?? undefined}
            className="world-grid"
          />
          {visible.map((item) => {
            const point = projection([item.lon, item.lat]);
            if (!point) return null;
            return (
              <g
                key={item.id}
                className={`world-marker ${item.layer} ${selected === item.id ? "chosen" : ""}`}
                onPointerDown={(event) => event.stopPropagation()}
                onClick={(event) => {
                  event.stopPropagation();
                  select(item);
                }}
              >
                <circle
                  cx={point[0]}
                  cy={point[1]}
                  r={selected === item.id ? 9 : 7}
                  className="world-marker-hit"
                />
                <circle
                  cx={point[0]}
                  cy={point[1]}
                  r={selected === item.id ? 5 : 3.5}
                />
                <title>{item.title}</title>
              </g>
            );
          })}
        </g>
        <text x="24" y="32" className="world-map-label">
          ORTHOGRAPHIC / WGS84
        </text>
        <text x="24" y="514" className="world-map-label">
          {view.lat.toFixed(2)}° LAT · {view.lon.toFixed(2)}° LON
        </text>
        <text x="696" y="514" textAnchor="end" className="world-map-label">
          {visible.length} VISIBLE
        </text>
      </svg>
      <div className="world-map-controls" aria-label="Globe controls">
        <button
          aria-label="Rotate west"
          onClick={() =>
            setView((current) =>
              moveView(current, current.lon - 25, current.lat),
            )
          }
        >
          ←
        </button>
        <button
          aria-label="Rotate east"
          onClick={() =>
            setView((current) =>
              moveView(current, current.lon + 25, current.lat),
            )
          }
        >
          →
        </button>
        <button
          aria-label="Rotate north"
          onClick={() =>
            setView((current) =>
              moveView(current, current.lon, current.lat + 20),
            )
          }
        >
          ↑
        </button>
        <button
          aria-label="Rotate south"
          onClick={() =>
            setView((current) =>
              moveView(current, current.lon, current.lat - 20),
            )
          }
        >
          ↓
        </button>
        <button
          aria-label="Zoom in"
          disabled={view.zoom >= 2.2}
          onClick={() =>
            setView((current) => ({
              ...current,
              zoom: Math.min(2.2, current.zoom + 0.2),
            }))
          }
        >
          +
        </button>
        <button
          aria-label="Zoom out"
          disabled={view.zoom <= 0.7}
          onClick={() =>
            setView((current) => ({
              ...current,
              zoom: Math.max(0.7, current.zoom - 0.2),
            }))
          }
        >
          −
        </button>
        <button onClick={() => setView({ lon: 40, lat: 20, zoom: 1 })}>
          Reset globe
        </button>
      </div>
    </div>
  );
}
