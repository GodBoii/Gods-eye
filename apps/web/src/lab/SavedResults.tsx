// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from "react";
import { message, request } from "../api";
import { reportSchema, summariesSchema } from "./api";
import type { Report, Summary } from "./api";
import { Evidence } from "./Evidence";
import "./workbench.css";

type Load =
  | { kind: "loading" }
  | { kind: "error"; error: string }
  | { kind: "ready"; reports: Summary[] };
export function SavedResults() {
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [revision, setRevision] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<
    | { kind: "loading" }
    | { kind: "error"; error: string }
    | { kind: "ready"; report: Report }
    | null
  >(null);
  useEffect(() => {
    const controller = new AbortController();
    setLoad({ kind: "loading" });
    void request("/api/lab/reports", { signal: controller.signal })
      .then((body) => {
        if (!controller.signal.aborted)
          setLoad({ kind: "ready", reports: summariesSchema.parse(body) });
      })
      .catch((error) => {
        if (!controller.signal.aborted)
          setLoad({ kind: "error", error: message(error) });
      });
    return () => controller.abort();
  }, [revision]);
  useEffect(() => {
    if (!selected) return;
    const controller = new AbortController();
    setDetail({ kind: "loading" });
    void request(`/api/lab/reports/${encodeURIComponent(selected)}`, {
      signal: controller.signal,
    })
      .then((body) => {
        if (!controller.signal.aborted)
          setDetail({ kind: "ready", report: reportSchema.parse(body) });
      })
      .catch((error) => {
        if (!controller.signal.aborted)
          setDetail({ kind: "error", error: message(error) });
      });
    return () => controller.abort();
  }, [selected, revision]);
  return (
    <section className="saved-reports">
      <div className="section-toolbar">
        <p className="muted small">
          Last 20 normalized reports on this server. Raw files and investigation
          context are not retained here.
        </p>
        <button onClick={() => setRevision((value) => value + 1)}>
          Refresh reports
        </button>
      </div>
      {load.kind === "loading" && <p role="status">Loading saved reports…</p>}
      {load.kind === "error" && (
        <p className="error" role="alert">
          {load.error}
        </p>
      )}
      {load.kind === "ready" &&
        (load.reports.length ? (
          <div className="saved-report-list">
            {load.reports.map((report) => (
              <button
                key={report.id}
                aria-pressed={selected === report.id}
                onClick={() => setSelected(report.id)}
              >
                <span>
                  <strong>{report.summary}</strong>
                  <small>
                    {report.tool} ·{" "}
                    {new Date(report.createdAt).toLocaleString()}
                  </small>
                </span>
                <span>
                  {report.findingCount} findings
                  {report.limited ? " · limited" : ""} →
                </span>
              </button>
            ))}
          </div>
        ) : (
          <div className="empty">
            <h2>No saved reports yet</h2>
            <p>
              Run an investigation or import evidence in Advanced. Completed
              reports will appear here.
            </p>
          </div>
        ))}
      {detail?.kind === "loading" && <p role="status">Opening evidence…</p>}
      {detail?.kind === "error" && (
        <p className="error" role="alert">
          {detail.error}
        </p>
      )}
      {detail?.kind === "ready" && (
        <Evidence
          key={detail.report.id}
          report={detail.report}
          sourceFile={null}
        />
      )}
    </section>
  );
}
