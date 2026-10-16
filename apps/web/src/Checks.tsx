// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from "react";
import { message, request, runSchema } from "./api";
import type { Run } from "./api";

export function Checks({
  runs,
  selected,
  select,
  cancel,
}: {
  runs: Run[];
  selected: string | null;
  select: (id: string) => void;
  cancel: (id: string) => void;
}) {
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const summary = runs.find((item) => item.id === selected) ?? runs[0];
  const [detail, setDetail] = useState<Run | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    setDetail(null);
    setError("");
    if (summary)
      void request(`/api/runs/${summary.id}`, { signal: controller.signal })
        .then((value) => {
          if (!controller.signal.aborted) setDetail(runSchema.parse(value));
        })
        .catch((error) => {
          if (!controller.signal.aborted) setError(message(error));
        });
    return () => controller.abort();
  }, [summary?.id, summary?.status]);
  const run = detail?.id === summary?.id ? detail : summary;
  if (!run)
    return (
      <section className="panel empty">
        <span className="empty-mark">⌕</span>
        <h2>No checks yet</h2>
        <p>
          Start a source scan or HTTPS check from Overview. Results will appear
          here.
        </p>
      </section>
    );
  if (error)
    return (
      <section className="panel error" role="alert">
        {error}
      </section>
    );
  if (!detail)
    return (
      <section className="panel empty" role="status">
        Loading check evidence…
      </section>
    );
  const pending = run.status === "running" || run.status === "cancelling";
  const matches = run.findings.filter((item) =>
    `${item.title} ${item.file} ${item.rule}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  const pages = Math.max(1, Math.ceil(matches.length / 25));
  const currentPage = Math.min(page, pages - 1);
  return (
    <div className="checks-layout">
      <aside className="panel history">
        <h2>Session history</h2>
        <p className="muted small">
          Last 20 checks. Export reports before closing the server.
        </p>
        {runs.map((item) => (
          <button
            className={`history-item ${run.id === item.id ? "selected" : ""}`}
            key={item.id}
            onClick={() => {
              select(item.id);
              setPage(0);
              setExpanded(null);
            }}
          >
            <span className={`badge ${item.status}`}>{item.status}</span>
            <strong>{item.target}</strong>
            <span className="muted small">
              {new Date(item.startedAt).toLocaleTimeString()} ·{" "}
              {item.findingCount} candidates
            </span>
          </button>
        ))}
      </aside>
      <section className="panel results">
        <div className="panel-title">
          <div>
            <span className="eyebrow">
              {run.kind === "source" ? "Source scan" : "HTTPS response check"}
            </span>
            <h2 className="target-title">{run.target}</h2>
          </div>
          <span className={`badge ${run.status}`}>{run.status}</span>
        </div>
        <div className="result-toolbar">
          <span className="muted">
            {run.kind === "source"
              ? `${run.files} files inspected · ${run.findings.length} candidates`
              : "Read-only · no crawling or payloads"}
          </span>
          <div className="inline-actions">
            {pending ? (
              <button
                disabled={run.status === "cancelling"}
                onClick={() => cancel(run.id)}
              >
                Cancel check
              </button>
            ) : (
              <>
                <a
                  className="button"
                  href={`/api/runs/${run.id}/report?format=json`}
                >
                  Export JSON ↓
                </a>
                {run.kind === "source" && run.status !== "failed" && (
                  <a
                    className="button"
                    href={`/api/runs/${run.id}/report?format=sarif`}
                  >
                    SARIF ↓
                  </a>
                )}
              </>
            )}
          </div>
        </div>
        {run.error && (
          <p className="error" role="alert">
            {run.error}
          </p>
        )}
        {run.gaps.length > 0 && (
          <div className="notice">
            <strong>Incomplete coverage</strong>
            <ul>
              {run.gaps.map((gap) => (
                <li key={gap}>{gap}</li>
              ))}
            </ul>
          </div>
        )}
        {pending && (
          <div role="status" className="empty">
            <span className="activity-dot" />
            <h3>
              {run.status === "cancelling"
                ? "Stopping the check…"
                : "Inspecting your target…"}
            </h3>
            <p>Results appear when this bounded check completes.</p>
          </div>
        )}
        {run.checks.length > 0 && (
          <div className="check-list">
            {run.checks.map((check) => (
              <article key={check.name}>
                <span className={`badge ${check.status}`}>{check.status}</span>
                <div>
                  <h3>{check.name}</h3>
                  <p>{check.detail}</p>
                </div>
              </article>
            ))}
          </div>
        )}
        {!pending && run.kind === "source" && (
          <>
            <label className="search-label">
              Filter findings
              <input
                type="search"
                placeholder="Search file, rule or finding"
                value={search}
                onChange={(event) => {
                  setSearch(event.target.value);
                  setPage(0);
                }}
              />
            </label>
            {matches.length === 0 ? (
              <div className="empty">
                <span className="empty-mark">⊙</span>
                <h3>
                  {run.findings.length
                    ? "No matching findings"
                    : run.status === "completed"
                      ? "No supported patterns detected"
                      : "No findings retained"}
                </h3>
                <p>
                  {run.status === "completed"
                    ? "This scan checks three credential patterns. It is not a full security assessment."
                    : "Review coverage and status before drawing conclusions."}
                </p>
              </div>
            ) : (
              <>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Finding / location</th>
                        <th>Review</th>
                      </tr>
                    </thead>
                    <tbody>
                      {matches
                        .slice(currentPage * 25, currentPage * 25 + 25)
                        .map((finding) => (
                          <tr key={finding.id}>
                            <td>
                              <span className="badge high">
                                {finding.severity}
                              </span>
                            </td>
                            <td>
                              <strong>{finding.title}</strong>
                              <code>
                                {finding.file}:{finding.line}
                              </code>
                              {expanded === finding.id && (
                                <div className="finding-detail">
                                  <p>{finding.description}</p>
                                  <p>
                                    Rule: <code>{finding.rule}</code>
                                  </p>
                                  <p>
                                    Credential content is withheld. Verify the
                                    candidate in your local source.
                                  </p>
                                </div>
                              )}
                            </td>
                            <td>
                              <button
                                aria-expanded={expanded === finding.id}
                                onClick={() =>
                                  setExpanded(
                                    expanded === finding.id ? null : finding.id,
                                  )
                                }
                              >
                                {expanded === finding.id ? "Close" : "Inspect"}
                              </button>
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
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
                    disabled={currentPage + 1 === pages}
                    onClick={() => setPage(currentPage + 1)}
                  >
                    Next
                  </button>
                </div>
              </>
            )}
          </>
        )}
      </section>
    </div>
  );
}
