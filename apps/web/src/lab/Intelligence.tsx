// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState } from "react";
import { message, request } from "../api";
import { reportSchema } from "./api";
import type { Report } from "./api";
import { Evidence } from "./Evidence";
import {
  filterIntelligenceFindings,
  intelligenceSchema,
  severitySchema,
} from "./intelligence-data";
import type { IntelligenceData } from "./intelligence-data";
import "./intelligence.css";
import "./workbench.css";

type Load =
  | { kind: "loading" }
  | { kind: "error"; error: string }
  | { kind: "ready"; data: IntelligenceData };
type EvidenceLoad =
  | { kind: "loading" }
  | { kind: "error"; error: string }
  | { kind: "ready"; report: Report };
const date = (value: string) => new Date(value).toLocaleString();

export default function Intelligence({
  investigate,
}: {
  investigate: () => void;
}) {
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [revision, setRevision] = useState(0);
  const [reportId, setReportId] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<EvidenceLoad>({ kind: "loading" });
  const sourceHeading = useRef<HTMLHeadingElement>(null);
  const sourceOpener = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (reportId) sourceHeading.current?.focus();
  }, [reportId]);
  useEffect(() => {
    const controller = new AbortController();
    setLoad({ kind: "loading" });
    void request("/api/lab/intelligence", { signal: controller.signal })
      .then((body) => {
        if (!controller.signal.aborted)
          setLoad({ kind: "ready", data: intelligenceSchema.parse(body) });
      })
      .catch((error) => {
        if (!controller.signal.aborted)
          setLoad({ kind: "error", error: message(error) });
      });
    return () => controller.abort();
  }, [revision]);
  useEffect(() => {
    if (!reportId) return;
    const controller = new AbortController();
    setEvidence({ kind: "loading" });
    void request(`/api/lab/reports/${encodeURIComponent(reportId)}`, {
      signal: controller.signal,
    })
      .then((body) => {
        if (!controller.signal.aborted)
          setEvidence({ kind: "ready", report: reportSchema.parse(body) });
      })
      .catch((error) => {
        if (!controller.signal.aborted)
          setEvidence({ kind: "error", error: message(error) });
      });
    return () => controller.abort();
  }, [reportId, revision]);
  function refresh() {
    setReportId(null);
    setRevision((value) => value + 1);
  }
  function openReport(id: string) {
    if (document.activeElement instanceof HTMLElement)
      sourceOpener.current = document.activeElement;
    if (id !== reportId) {
      setEvidence({ kind: "loading" });
      setReportId(id);
    } else sourceHeading.current?.focus();
  }
  function closeReport() {
    setReportId(null);
    sourceOpener.current?.focus();
  }
  return (
    <section className="intelligence" aria-label="Connected intelligence">
      <div className="page-heading intelligence-heading">
        <div>
          <span className="eyebrow">EVIDENCE / ASSETS / EXPOSURE</span>
          <h1>Intelligence</h1>
          <p>
            Connect collected evidence, trace its sources and decide what to
            investigate next.
          </p>
        </div>
        <div className="intelligence-actions">
          <button onClick={refresh} disabled={load.kind === "loading"}>
            Refresh intelligence
          </button>
          <a className="button" href="/api/lab/intelligence?download=1">
            Export intelligence ↓
          </a>
        </div>
      </div>
      {load.kind === "loading" && (
        <p role="status">Connecting retained evidence…</p>
      )}
      {load.kind === "error" && (
        <div className="error" role="alert">
          <p>Could not load intelligence: {load.error}</p>
          <button onClick={refresh}>Retry</button>
        </div>
      )}
      {load.kind === "ready" && (
        <IntelligenceSnapshot
          data={load.data}
          investigate={investigate}
          openReport={openReport}
        />
      )}
      {reportId && (
        <section
          className="intelligence-source-detail"
          aria-label="Selected source report"
        >
          <div className="section-toolbar">
            <h2 ref={sourceHeading} tabIndex={-1}>
              Source evidence
            </h2>
            <button onClick={closeReport}>Close source report</button>
          </div>
          {evidence.kind === "loading" && (
            <p role="status">Loading source evidence…</p>
          )}
          {evidence.kind === "error" && (
            <p className="error" role="alert">
              {evidence.error} The report may have expired from the 20-report
              retention window. Refresh intelligence to reconnect retained
              sources.
            </p>
          )}
          {evidence.kind === "ready" && (
            <Evidence
              key={evidence.report.id}
              report={evidence.report}
              sourceFile={null}
            />
          )}
        </section>
      )}
    </section>
  );
}

function IntelligenceSnapshot({
  data,
  investigate,
  openReport,
}: {
  data: IntelligenceData;
  investigate: () => void;
  openReport: (id: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [assetQuery, setAssetQuery] = useState("");
  const [entity, setEntity] = useState<string | null>(null);
  const [severity, setSeverity] = useState("all");
  const [page, setPage] = useState(0);
  const active = data.entities.find((item) => item.id === entity);
  const activeId = active?.id ?? null;
  const findings = filterIntelligenceFindings(data, {
    query,
    severity,
    entity: activeId,
  });
  const lastPage = Math.max(0, Math.ceil(findings.length / 25) - 1);
  const currentPage = Math.min(page, lastPage);
  const entities = data.entities.filter((item) =>
    item.label.toLowerCase().includes(assetQuery.toLowerCase().trim()),
  );
  const entityLabels = new Map(
    data.entities.map((item) => [item.id, item.label]),
  );
  const relations = activeId
    ? data.relations.filter(
        (item) => item.source === activeId || item.target === activeId,
      )
    : data.relations;
  const urgent = data.findings.filter(
    (item) => item.severity === "critical" || item.severity === "high",
  ).length;
  return (
    <>
      <dl className="intelligence-totals">
        <div>
          <dt>Unique findings</dt>
          <dd>{data.findings.length}</dd>
        </div>
        <div>
          <dt>Critical / high candidates</dt>
          <dd>{urgent}</dd>
        </div>
        <div>
          <dt>Connected assets</dt>
          <dd>{data.entities.length}</dd>
        </div>
        <div>
          <dt>Source reports</dt>
          <dd>{data.reportCount}</dd>
        </div>
      </dl>
      <p className="muted small">
        Snapshot {date(data.generatedAt)} · Reported severity · Human
        verification required{data.limited ? " · Limited coverage" : ""}
      </p>
      {data.reportCount === 0 ? (
        <div className="panel empty">
          <h2>No collected evidence yet</h2>
          <p>
            Run an investigation or import an existing scanner report in
            Advanced. Evidence will connect here as reports are saved.
          </p>
          <button className="primary" onClick={investigate}>
            Start an investigation
          </button>
        </div>
      ) : (
        <>
          <div className="intelligence-workspace">
            <aside
              className="intelligence-assets"
              aria-label="Connected assets"
            >
              <h2>Assets & targets</h2>
              <label>
                Find an asset
                <input
                  type="search"
                  value={assetQuery}
                  onChange={(event) => setAssetQuery(event.target.value)}
                  placeholder="Host, IP or resource"
                />
              </label>
              <button
                className="intelligence-asset"
                aria-pressed={activeId === null}
                onClick={() => {
                  setEntity(null);
                  setPage(0);
                }}
              >
                <strong>All assets</strong>
                <span>{data.findings.length} findings</span>
              </button>
              {entities.slice(0, 100).map((item) => (
                <button
                  key={item.id}
                  className="intelligence-asset"
                  aria-pressed={activeId === item.id}
                  onClick={() => {
                    setEntity(item.id);
                    setPage(0);
                  }}
                >
                  <small>{item.kind}</small>
                  <strong>{item.label}</strong>
                  <span>
                    {item.findingCount} findings · {item.reportIds.length}{" "}
                    reports
                  </span>
                </button>
              ))}
              {entities.length === 0 && (
                <p className="muted">No assets match this search.</p>
              )}
              {entities.length > 100 && (
                <p className="muted small">
                  Showing 100 of {entities.length}. Refine your asset search.
                </p>
              )}
            </aside>
            <div className="intelligence-triage">
              <h2>{active ? active.label : "Finding triage"}</h2>
              <div className="intelligence-filters">
                <label>
                  Search findings
                  <input
                    type="search"
                    value={query}
                    onChange={(event) => {
                      setQuery(event.target.value);
                      setPage(0);
                    }}
                    placeholder="Finding, endpoint, detail or tool"
                  />
                </label>
                <label>
                  Reported severity
                  <select
                    value={severity}
                    onChange={(event) => {
                      setSeverity(event.target.value);
                      setPage(0);
                    }}
                  >
                    <option value="all">All severities</option>
                    {severitySchema.options.map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <p className="muted small" role="status">
                {findings.length} matching findings
                {active ? ` on ${active.label}` : ""}
              </p>
              {findings.length === 0 && (
                <p className="empty">
                  No matching findings. Assets with observations only can still
                  have recorded relationships below.
                </p>
              )}
              {findings
                .slice(currentPage * 25, currentPage * 25 + 25)
                .map((finding) => (
                  <IntelligenceFinding
                    key={finding.id}
                    finding={finding}
                    openReport={openReport}
                  />
                ))}
              {findings.length > 25 && (
                <div className="intelligence-pagination">
                  <button
                    disabled={currentPage === 0}
                    onClick={() => setPage(currentPage - 1)}
                  >
                    Previous
                  </button>
                  <span>
                    Page {currentPage + 1} of {lastPage + 1}
                  </span>
                  <button
                    disabled={currentPage === lastPage}
                    onClick={() => setPage(currentPage + 1)}
                  >
                    Next
                  </button>
                </div>
              )}
            </div>
          </div>
          <section
            className="intelligence-relationships"
            aria-label="Recorded relationships"
          >
            <h2>Recorded relationships{active ? ` · ${active.label}` : ""}</h2>
            <p className="muted small">
              Directed relationships from source graphs. Select an endpoint to
              pivot into its findings. Shared hosts do not prove ownership.
            </p>
            {relations.length ? (
              <>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Source</th>
                        <th>Relation</th>
                        <th>Target</th>
                        <th>Evidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {relations.slice(0, 50).map((relation) => (
                        <tr
                          key={`${relation.source}-${relation.target}-${relation.relation}`}
                        >
                          <td>
                            <button
                              onClick={() => {
                                setEntity(relation.source);
                                setPage(0);
                              }}
                            >
                              {entityLabels.get(relation.source) ??
                                relation.source}
                            </button>
                          </td>
                          <td>{relation.relation}</td>
                          <td>
                            <button
                              onClick={() => {
                                setEntity(relation.target);
                                setPage(0);
                              }}
                            >
                              {entityLabels.get(relation.target) ??
                                relation.target}
                            </button>
                          </td>
                          <td>
                            {relation.reportIds.map((id) => (
                              <button key={id} onClick={() => openReport(id)}>
                                Source report
                              </button>
                            ))}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {relations.length > 50 && (
                  <p className="muted small">
                    Showing 50 of {relations.length} relationships. Select an
                    asset or export the full snapshot.
                  </p>
                )}
              </>
            ) : (
              <p className="muted">
                No infrastructure relationships recorded for this selection.
              </p>
            )}
          </section>
          <details className="intelligence-sources">
            <summary>
              Source register · {data.reports.length} retained reports
            </summary>
            <ul>
              {data.reports.map((report) => (
                <li key={report.id}>
                  <button onClick={() => openReport(report.id)}>
                    {report.tool} · {date(report.createdAt)}
                  </button>
                  <span>
                    {report.summary}
                    {report.limited ? " · Limited" : ""}
                  </span>
                </li>
              ))}
            </ul>
          </details>
        </>
      )}
      <details className="intelligence-coverage">
        <summary>Coverage & interpretation</summary>
        <ul>
          {data.gaps.map((gap) => (
            <li key={gap}>{gap}</li>
          ))}
        </ul>
      </details>
    </>
  );
}

function IntelligenceFinding({
  finding,
  openReport,
}: {
  finding: IntelligenceData["findings"][number];
  openReport: (id: string) => void;
}) {
  return (
    <article className="intelligence-finding" key={finding.id}>
      <header>
        <span
          className={`intelligence-severity intelligence-severity-${finding.severity}`}
        >
          {finding.severity}
        </span>
        <h3>{finding.title}</h3>
      </header>
      <code>{finding.target || "No target recorded"}</code>
      <p>{finding.detail}</p>
      <div className="intelligence-finding-meta">
        <span>{finding.references.length} source records</span>
        <span>First recorded {date(finding.firstSeen)}</span>
        <span>Last recorded {date(finding.lastSeen)}</span>
      </div>
      <details>
        <summary>Trace evidence & sources</summary>
        <ul className="intelligence-provenance">
          {finding.references.map((ref) => (
            <li key={`${ref.reportId}-${ref.findingId}`}>
              <div>
                <strong>{ref.tool}</strong> · {ref.severity} ·{" "}
                {date(ref.recordedAt)}
              </div>
              <code>Finding {ref.findingId}</code>
              {ref.inputSha256 && <code>Input SHA-256 {ref.inputSha256}</code>}
              <button onClick={() => openReport(ref.reportId)}>
                Open source report
              </button>
            </li>
          ))}
        </ul>
      </details>
    </article>
  );
}
