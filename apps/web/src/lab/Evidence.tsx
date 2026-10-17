// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import type { Report } from "./api";

function quantity(count: number, singular: string, plural = `${singular}s`) {
  return `${count} ${count === 1 ? singular : plural}`;
}

function EvidenceGraph({ report }: { report: Report }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const visible = report.nodes.filter((node) =>
    `${node.kind} ${node.label}`.toLowerCase().includes(search.toLowerCase()),
  );
  const active = selected
    ? report.nodes.find((node) => node.id === selected)
    : visible[0];
  const links = report.edges.filter(
    (edge) => edge.source === active?.id || edge.target === active?.id,
  );
  const connected = new Set(
    links.flatMap((edge) => [edge.source, edge.target]),
  );
  const nodes = [
    active,
    ...report.nodes.filter(
      (node) => connected.has(node.id) && node.id !== active?.id,
    ),
  ]
    .filter((node) => node !== undefined)
    .slice(0, 13);
  const points = nodes.map((node, index) => {
    if (index === 0) return { node, x: 350, y: 195 };
    const angle = ((index - 1) / Math.max(1, nodes.length - 1)) * Math.PI * 2;
    return {
      node,
      x: 350 + Math.cos(angle) * 250,
      y: 195 + Math.sin(angle) * 140,
    };
  });
  return (
    <div className="evidence-graph">
      <label>
        Find a node
        <input
          type="search"
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setSelected(null);
          }}
          placeholder="Domain, IP, resource or directory object"
        />
      </label>
      <div className="graph-workspace">
        <div className="graph-index" aria-label="Evidence nodes">
          {visible.slice(0, 100).map((node) => (
            <button
              key={node.id}
              aria-pressed={active?.id === node.id}
              onClick={() => setSelected(node.id)}
            >
              <small>{node.kind}</small>
              <span>{node.label}</span>
            </button>
          ))}
          {visible.length === 0 && <p className="muted">No matching nodes.</p>}
          {visible.length > 100 && (
            <p className="muted small">
              Showing 100 of {visible.length}. Refine your search.
            </p>
          )}
        </div>
        <div className="graph-detail">
          {active ? (
            <>
              <svg
                viewBox="0 0 700 390"
                role="img"
                aria-label={`Relationships for ${active.label}. Connections are listed below.`}
              >
                {points.slice(1).map((point) => (
                  <line
                    key={point.node.id}
                    x1="350"
                    y1="195"
                    x2={point.x}
                    y2={point.y}
                  />
                ))}
                {points.map(({ node, x, y }, index) => (
                  <g key={node.id}>
                    <circle
                      cx={x}
                      cy={y}
                      r={index === 0 ? 9 : 5}
                      className={index === 0 ? "graph-origin" : ""}
                    />
                    <text x={x} y={y + 24} textAnchor="middle">
                      {node.label.length > 22
                        ? `${node.label.slice(0, 20)}…`
                        : node.label}
                    </text>
                    <title>
                      {node.kind}: {node.label}
                    </title>
                  </g>
                ))}
              </svg>
              <p className="muted small">
                Selected node and up to 12 neighbors. Relation direction is
                recorded in the table.
              </p>
              <h3>{active.label}</h3>
              {links.length ? (
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Source</th>
                        <th>Relation</th>
                        <th>Target</th>
                      </tr>
                    </thead>
                    <tbody>
                      {links.slice(0, 50).map((edge) => (
                        <tr
                          key={`${edge.source}-${edge.target}-${edge.relation}`}
                        >
                          <td>
                            {report.nodes.find(
                              (node) => node.id === edge.source,
                            )?.label ?? edge.source}
                          </td>
                          <td>{edge.relation}</td>
                          <td>
                            {report.nodes.find(
                              (node) => node.id === edge.target,
                            )?.label ?? edge.target}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="muted">
                  No relationships recorded for this node.
                </p>
              )}
              {links.length > 50 && (
                <p className="muted small">
                  Showing 50 of {links.length} relationships. Export JSON for
                  all retained edges.
                </p>
              )}
            </>
          ) : (
            <div className="lab-empty">
              <p>No graph nodes in this report.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function Evidence({
  report,
  sourceFile,
}: {
  report: Report;
  sourceFile: File | null;
}) {
  const [view, setView] = useState(
    report.findings.length ? "Findings" : "Observations",
  );
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const filter = search.toLowerCase();
  const findings = report.findings.filter((finding) =>
    `${finding.title} ${finding.target} ${finding.detail} ${finding.severity}`
      .toLowerCase()
      .includes(filter),
  );
  const observations = report.observations.filter((item) =>
    `${item.kind} ${item.target} ${item.value}`.toLowerCase().includes(filter),
  );
  const total = view === "Findings" ? findings.length : observations.length;
  const lastPage = Math.max(0, Math.ceil(total / 25) - 1);
  const current = Math.min(page, lastPage);
  function recover(offset: number, length: number, name: string) {
    if (!sourceFile || offset + length > sourceFile.size) return;
    const objectURL = URL.createObjectURL(
      sourceFile.slice(offset, offset + length, "application/octet-stream"),
    );
    const anchor = document.createElement("a");
    anchor.href = objectURL;
    anchor.download = name;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(objectURL), 1000);
  }
  return (
    <section className="lab-evidence" aria-label="Evidence report">
      <header className="lab-result-header">
        <div>
          <span className="eyebrow">
            {report.tool} / {new Date(report.createdAt).toLocaleString()}
          </span>
          <h2>{report.summary}</h2>
        </div>
        <a
          className="button"
          href={`/api/lab/reports/${encodeURIComponent(report.id)}?download=1`}
        >
          Export JSON ↗
        </a>
      </header>
      <div className="lab-result-stats">
        <span>{quantity(report.findings.length, "finding")}</span>
        <span>{quantity(report.observations.length, "observation")}</span>
        <span>
          {quantity(report.nodes.length, "node")} ·{" "}
          {quantity(report.edges.length, "edge")}
        </span>
        {report.limited && <span className="badge partial">Limited</span>}
      </div>
      <div className="lab-segments" aria-label="Evidence view">
        {["Findings", "Observations", "Graph"].map((item) => (
          <button
            key={item}
            aria-pressed={view === item}
            onClick={() => {
              setView(item);
              setPage(0);
              setSearch("");
            }}
          >
            {item}
          </button>
        ))}
      </div>
      {view === "Graph" ? (
        <EvidenceGraph report={report} />
      ) : (
        <>
          <label className="search-label">
            Filter evidence
            <input
              type="search"
              value={search}
              onChange={(event) => {
                setSearch(event.target.value);
                setPage(0);
              }}
              placeholder="Search target, rule or observation"
            />
          </label>
          {view === "Findings" ? (
            findings.length ? (
              <div className="lab-findings">
                {findings
                  .slice(current * 25, current * 25 + 25)
                  .map((finding) => (
                    <details key={finding.id}>
                      <summary>
                        <span className={`badge ${finding.severity}`}>
                          {finding.severity}
                        </span>
                        <span>
                          {finding.title}
                          <code>{finding.target}</code>
                        </span>
                        <span aria-hidden="true">+</span>
                      </summary>
                      <p>{finding.detail}</p>
                    </details>
                  ))}
              </div>
            ) : (
              <div className="lab-empty">
                <h3>
                  {report.findings.length
                    ? "No matching findings"
                    : "No findings retained"}
                </h3>
                <p>
                  Observations and coverage explain what this report contains. A
                  clean result does not establish that a system is secure.
                </p>
              </div>
            )
          ) : observations.length ? (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Observation</th>
                    <th>Target</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {observations
                    .slice(current * 25, current * 25 + 25)
                    .map((item, index) => (
                      <tr key={`${current}-${index}`}>
                        <td>{item.kind}</td>
                        <td>
                          <code>{item.target}</code>
                        </td>
                        <td>{item.value}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="lab-empty">
              <p>No matching observations.</p>
            </div>
          )}
          {lastPage > 0 && (
            <div className="pagination">
              <button
                disabled={current === 0}
                onClick={() => setPage(current - 1)}
              >
                Previous
              </button>
              <span>
                {current + 1} / {lastPage + 1}
              </span>
              <button
                disabled={current === lastPage}
                onClick={() => setPage(current + 1)}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
      {report.artifacts.length > 0 && (
        <section className="lab-artifacts">
          <h3>Recovery candidates</h3>
          <p className="muted small">
            Downloads slice bytes from the original file in this tab. Candidates
            may be incomplete or unsafe to open.
          </p>
          {report.artifacts.map((artifact) => (
            <div key={artifact.name}>
              <code>
                {artifact.name} · offset {artifact.offset} · {artifact.length}{" "}
                bytes
              </code>
              <button
                disabled={!sourceFile}
                onClick={() =>
                  recover(artifact.offset, artifact.length, artifact.name)
                }
              >
                Download slice
              </button>
            </div>
          ))}
          {!sourceFile && (
            <p className="muted small">
              Analyze the original file again to enable downloads. File content
              is not retained with the report.
            </p>
          )}
        </section>
      )}
      <details className="lab-coverage">
        <summary>
          Coverage and provenance{" "}
          <span>{quantity(report.gaps.length, "note")}</span>
        </summary>
        <ul>
          {report.gaps.map((gap) => (
            <li key={gap}>{gap}</li>
          ))}
        </ul>
        {report.inputSha256 && (
          <p>
            Input SHA-256 <code>{report.inputSha256}</code>
          </p>
        )}
      </details>
    </section>
  );
}
