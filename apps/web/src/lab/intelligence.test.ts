// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import {
  filterIntelligenceFindings,
  intelligenceSchema,
} from "./intelligence-data";

test("intelligence validates data and combines tool, asset, severity and multi-term search", () => {
  const data = intelligenceSchema.parse({
    generatedAt: "2026-11-01T00:00:00Z",
    reportCount: 1,
    entities: [],
    relations: [],
    reports: [],
    limited: false,
    gaps: [],
    findings: [
      {
        id: "a",
        entityId: "host-a",
        title: "Configuration exposure",
        target: "https://a.test/config",
        detail: "Review candidate",
        severity: "high",
        firstSeen: "2026-10-31T00:00:00Z",
        lastSeen: "2026-11-01T00:00:00Z",
        references: [
          {
            reportId: "r",
            findingId: "f",
            tool: "nuclei",
            severity: "high",
            recordedAt: "2026-11-01T00:00:00Z",
            inputSha256: "",
          },
        ],
      },
      {
        id: "b",
        entityId: "host-b",
        title: "Debug exposure",
        target: "https://b.test/debug",
        detail: "Review candidate",
        severity: "medium",
        firstSeen: "2026-10-31T00:00:00Z",
        lastSeen: "2026-11-01T00:00:00Z",
        references: [],
      },
    ],
  });
  assert.deepEqual(
    filterIntelligenceFindings(data, {
      query: "  CONFIG  NuClEi  ",
      severity: "high",
      entity: "host-a",
    }).map((f) => f.id),
    ["a"],
  );
  assert.equal(
    filterIntelligenceFindings(data, {
      query: "config",
      severity: "medium",
      entity: null,
    }).length,
    0,
  );
  assert.equal(
    filterIntelligenceFindings(data, {
      query: "",
      severity: "all",
      entity: "host-b",
    }).length,
    1,
  );
  assert.equal(
    filterIntelligenceFindings(data, {
      query: "",
      severity: "all",
      entity: null,
    }).length,
    2,
  );
  assert.equal(
    intelligenceSchema.safeParse({
      ...data,
      findings: [{ ...data.findings[0], severity: "verified" }],
    }).success,
    false,
  );
});
