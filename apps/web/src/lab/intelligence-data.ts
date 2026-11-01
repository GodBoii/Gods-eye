// SPDX-License-Identifier: Apache-2.0
import { z } from "zod";
import { summariesSchema } from "./api";

export const severitySchema = z.enum([
  "critical",
  "high",
  "medium",
  "low",
  "info",
]);
export const intelligenceSchema = z.object({
  generatedAt: z.iso.datetime(),
  reportCount: z.number().int().nonnegative(),
  entities: z.array(
    z.object({
      id: z.string(),
      kind: z.string(),
      label: z.string(),
      reportIds: z.array(z.string()),
      findingCount: z.number().int().nonnegative(),
    }),
  ),
  findings: z.array(
    z.object({
      id: z.string(),
      entityId: z.string(),
      title: z.string(),
      target: z.string(),
      detail: z.string(),
      severity: severitySchema,
      firstSeen: z.iso.datetime(),
      lastSeen: z.iso.datetime(),
      references: z.array(
        z.object({
          reportId: z.string(),
          findingId: z.string(),
          tool: z.string(),
          severity: severitySchema,
          recordedAt: z.iso.datetime(),
          inputSha256: z.string(),
        }),
      ),
    }),
  ),
  relations: z.array(
    z.object({
      source: z.string(),
      target: z.string(),
      relation: z.string(),
      reportIds: z.array(z.string()),
    }),
  ),
  reports: summariesSchema,
  limited: z.boolean(),
  gaps: z.array(z.string()),
});
export type IntelligenceData = z.infer<typeof intelligenceSchema>;

export function filterIntelligenceFindings(
  data: IntelligenceData,
  {
    query,
    severity,
    entity,
  }: { query: string; severity: string; entity: string | null },
) {
  const terms = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
  return data.findings.filter((finding) => {
    if (entity !== null && finding.entityId !== entity) return false;
    if (severity !== "all" && finding.severity !== severity) return false;
    const content =
      `${finding.title} ${finding.target} ${finding.detail} ${finding.references.map((ref) => ref.tool).join(" ")}`.toLowerCase();
    return terms.every((term) => content.includes(term));
  });
}
