// SPDX-License-Identifier: Apache-2.0
import { z } from "zod";
import { request } from "../api";

const node = z.object({ id: z.string(), kind: z.string(), label: z.string() });
const edge = z.object({
  source: z.string(),
  target: z.string(),
  relation: z.string(),
});
export const reportSchema = z.object({
  id: z.string(),
  tool: z.string(),
  summary: z.string(),
  createdAt: z.string(),
  inputSha256: z.string(),
  findings: z.array(
    z.object({
      id: z.string(),
      title: z.string(),
      severity: z.string(),
      target: z.string(),
      detail: z.string(),
    }),
  ),
  observations: z.array(
    z.object({ kind: z.string(), target: z.string(), value: z.string() }),
  ),
  nodes: z.array(node),
  edges: z.array(edge),
  artifacts: z.array(
    z.object({
      name: z.string(),
      offset: z.number().int().nonnegative(),
      length: z.number().int().positive(),
    }),
  ),
  gaps: z.array(z.string()),
  limited: z.boolean(),
});
export const summariesSchema = z.array(
  z.object({
    id: z.string(),
    tool: z.string(),
    summary: z.string(),
    createdAt: z.string(),
    findingCount: z.number(),
    observationCount: z.number(),
    limited: z.boolean(),
  }),
);
export const catalogSchema = z.object({
  tools: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      category: z.string(),
      license: z.string(),
      source: z.string().url(),
      mode: z.string(),
      available: z.string(),
      limit: z.string(),
    }),
  ),
  formats: z.array(
    z.object({ id: z.string(), label: z.string(), extension: z.string() }),
  ),
  maxInputBytes: z.number(),
});
export type Report = z.infer<typeof reportSchema>;
export type Summary = z.infer<typeof summariesSchema>[number];
export type Catalog = z.infer<typeof catalogSchema>;

export async function upload(
  path: string,
  file: File,
  signal?: AbortSignal,
): Promise<Report> {
  if (file.size === 0 || file.size > 8 * 1024 * 1024)
    throw new Error("Select a non-empty file up to 8 MiB");
  const response = await fetch(path, {
    method: "POST",
    body: file,
    signal,
    headers: {
      "Content-Type": "application/octet-stream",
      "X-GodsEye-Request": "1",
    },
  });
  const body: unknown = await response.json();
  if (!response.ok) {
    const error = z.object({ error: z.string() }).safeParse(body);
    throw new Error(
      error.success
        ? error.data.error
        : `Upload failed with status ${response.status}`,
    );
  }
  return reportSchema.parse(body);
}

export async function diagnose(
  mode: string,
  target: string,
  ports: string,
  signal?: AbortSignal,
) {
  const parsedPorts =
    mode === "tcp" ? ports.split(",").map((value) => Number(value.trim())) : [];
  if (
    mode === "tcp" &&
    (parsedPorts.length > 32 ||
      parsedPorts.some(
        (value) => !Number.isInteger(value) || value < 1 || value > 65535,
      ) ||
      new Set(parsedPorts).size !== parsedPorts.length)
  )
    throw new Error("Use 1 to 32 unique comma-separated ports from 1 to 65535");
  return reportSchema.parse(
    await request("/api/lab/diagnose", {
      method: "POST",
      signal,
      body: JSON.stringify({
        mode,
        target,
        ports: parsedPorts,
        authorized: true,
      }),
    }),
  );
}
