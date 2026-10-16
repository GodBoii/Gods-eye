// SPDX-License-Identifier: Apache-2.0
import { z } from "zod";

const assetSchema = z.object({
  id: z.string(),
  name: z.string(),
  kind: z.string(),
  target: z.string(),
  owner: z.string(),
  createdAt: z.string(),
});
const findingSchema = z.object({
  id: z.string(),
  title: z.string(),
  rule: z.string(),
  severity: z.string(),
  file: z.string(),
  line: z.number(),
  description: z.string(),
});
export const runSchema = z.object({
  id: z.string(),
  target: z.string(),
  kind: z.string(),
  status: z.enum([
    "running",
    "cancelling",
    "completed",
    "partial",
    "failed",
    "cancelled",
  ]),
  startedAt: z.string(),
  finishedAt: z.string().nullable(),
  files: z.number(),
  findingCount: z.number(),
  findings: z.array(findingSchema),
  checks: z.array(
    z.object({ name: z.string(), status: z.string(), detail: z.string() }),
  ),
  gaps: z.array(z.string()),
  error: z.string(),
});
export const stateSchema = z.object({
  workspace: z.string(),
  assets: z.array(assetSchema),
  runs: z.array(runSchema),
});
export type State = z.infer<typeof stateSchema>;
export type Run = z.infer<typeof runSchema>;
export type Asset = z.infer<typeof assetSchema>;

export async function request(
  path: string,
  options: RequestInit = {},
): Promise<unknown> {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", "X-GodsEye-Request": "1" },
  });
  const body: unknown = await response.json();
  if (!response.ok) {
    const error = z.object({ error: z.string() }).safeParse(body);
    throw new Error(
      error.success ? error.data.error : `Request failed (${response.status})`,
    );
  }
  return body;
}

export async function startCheck(
  target: string,
  kind: string,
): Promise<string> {
  const response = await request("/api/runs", {
    method: "POST",
    body: JSON.stringify({ target, kind, authorized: true }),
  });
  return z.object({ id: z.string() }).parse(response).id;
}

export const categories = [
  {
    id: "source",
    label: "Source code",
    coverage: "Secret patterns",
    available: true,
  },
  {
    id: "website",
    label: "Website",
    coverage: "HTTPS response check",
    available: true,
  },
  {
    id: "api",
    label: "API",
    coverage: "HTTPS response check",
    available: true,
  },
  {
    id: "backend",
    label: "Backend service",
    coverage: "HTTPS response check",
    available: true,
  },
  {
    id: "application",
    label: "Application",
    coverage: "HTTPS endpoint only",
    available: true,
  },
  {
    id: "database",
    label: "Database",
    coverage: "Inventory only",
    available: false,
  },
  {
    id: "cloud",
    label: "Cloud resource",
    coverage: "Inventory only",
    available: false,
  },
  {
    id: "container",
    label: "Container",
    coverage: "Inventory only",
    available: false,
  },
  {
    id: "network",
    label: "Network",
    coverage: "Inventory only",
    available: false,
  },
];
export function categoryLabel(kind: string): string {
  return categories.find((item) => item.id === kind)?.label ?? kind;
}
export function message(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "The request could not be completed.";
}
