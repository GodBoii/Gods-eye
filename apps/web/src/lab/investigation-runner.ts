// SPDX-License-Identifier: Apache-2.0
import { z } from "zod";
import { request, runSchema } from "../api";
import type { Run } from "../api";
import { diagnose, reportSchema, upload } from "./api";
import type { Report } from "./api";
import type { PlanItem } from "./investigation-plan";
import { researchIdentifier } from "./identifier-research";
import type { Research } from "./identifier-research";

export type Outcome =
  | { kind: "research"; research: Research }
  | { kind: "queued" | "running" | "skipped" | "stopped" }
  | { kind: "error"; error: string }
  | { kind: "report"; report: Report }
  | { kind: "run"; run: Run }
  | { kind: "manual"; links: { label: string; url: string }[] }
  | { kind: "context" };

function pause(signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    signal.throwIfAborted();
    const abort = () => {
      clearTimeout(timer);
      reject(signal.reason);
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve();
    }, 700);
    signal.addEventListener("abort", abort, { once: true });
  });
}

export async function executeStep(
  item: PlanItem,
  cancellation: AbortSignal,
): Promise<Outcome> {
  const signal = AbortSignal.any([cancellation, AbortSignal.timeout(100_000)]);
  signal.throwIfAborted();
  const op = item.operation;
  switch (op.kind) {
    case "research":
      return {
        kind: "research",
        research: researchIdentifier(op.researchKind, op.target),
      };
    case "breach":
      return {
        kind: "report",
        report: reportSchema.parse(
          await request("/api/lab/email-breaches", {
            method: "POST",
            signal,
            body: JSON.stringify({ email: op.target, authorized: true }),
          }),
        ),
      };
    case "context":
      return { kind: "context" };
    case "manual":
      return { kind: "manual", links: op.links };
    case "file":
      return {
        kind: "report",
        report: await upload("/api/lab/file?mode=file", op.file, signal),
      };
    case "dns":
      return {
        kind: "report",
        report: await diagnose("dns", op.target, "", signal),
      };
    case "assessment":
      return {
        kind: "report",
        report: reportSchema.parse(
          await request("/api/lab/assess", {
            method: "POST",
            signal,
            body: JSON.stringify({
              tool: op.tool,
              target: op.target,
              input: "",
              encoding: "text",
              ports: [],
              authorized: true,
              runEngine: false,
            }),
          }),
        ),
      };
    case "check": {
      const { id } = z.object({ id: z.string() }).parse(
        await request("/api/runs", {
          method: "POST",
          signal,
          body: JSON.stringify({
            target: op.target,
            kind: op.checkKind,
            authorized: true,
          }),
        }),
      );
      try {
        const deadline = Date.now() + 90_000;
        while (Date.now() < deadline) {
          const run = runSchema.parse(
            await request(`/api/runs/${encodeURIComponent(id)}`, { signal }),
          );
          if (run.status !== "running" && run.status !== "cancelling")
            return { kind: "run", run };
          await pause(signal);
        }
        throw new Error(
          "Timed out waiting for this check. Open Saved results to inspect its server status before retrying.",
        );
      } finally {
        if (signal.aborted) {
          // The cancellation request must outlive the aborted polling request.
          await request(`/api/runs/${encodeURIComponent(id)}/cancel`, {
            method: "POST",
            signal: AbortSignal.timeout(5_000),
          });
        }
      }
    }
  }
}

export function outcomeLabel(outcome: Outcome): string {
  switch (outcome.kind) {
    case "research":
      return "Local analysis / review links";
    case "run":
      return outcome.run.status === "completed"
        ? "Completed"
        : outcome.run.status === "partial"
          ? "Limited"
          : outcome.run.status;
    case "report":
      return outcome.report.limited ? "Limited" : "Completed";
    case "manual":
      return "Needs manual review";
    case "context":
      return "No automated lookup";
    case "queued":
      return "Waiting";
    case "running":
      return "Running";
    case "skipped":
      return "Not selected";
    case "stopped":
      return "Stopped";
    case "error":
      return "Failed";
  }
}
