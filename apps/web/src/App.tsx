// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Assets } from "./Assets";
import { Checks } from "./Checks";
import {
  categories,
  categoryLabel,
  message,
  request,
  startCheck,
  stateSchema,
} from "./api";
import type { Asset, State } from "./api";

type Page = "Overview" | "Assets" | "Checks" | "Coverage";
type Load =
  | { kind: "loading" }
  | { kind: "ready"; data: State }
  | { kind: "failed"; error: string };

export default function App() {
  const [page, setPage] = useState<Page>("Overview");
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [revision, setRevision] = useState(0);
  const [kind, setKind] = useState("source");
  const [target, setTarget] = useState(".");
  const [authorized, setAuthorized] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [action, setAction] = useState<"idle" | "busy">("idle");
  const [error, setError] = useState("");
  const refresh = () => setRevision((value) => value + 1);
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      if (document.hidden) {
        timer = setTimeout(() => void poll(), 10000);
        return;
      }
      let delay = 5000;
      try {
        const data = stateSchema.parse(
          await request("/api/state", { signal: controller.signal }),
        );
        if (
          data.runs.some(
            (run) => run.status === "running" || run.status === "cancelling",
          )
        )
          delay = 1000;
        if (!controller.signal.aborted) setLoad({ kind: "ready", data });
      } catch (error) {
        if (!controller.signal.aborted)
          setLoad({ kind: "failed", error: message(error) });
      }
      if (!controller.signal.aborted)
        timer = setTimeout(() => void poll(), delay);
    }
    const visible = () => {
      if (!document.hidden) setRevision((value) => value + 1);
    };
    document.addEventListener("visibilitychange", visible);
    void poll();
    return () => {
      controller.abort();
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [revision]);

  async function start(event: FormEvent) {
    event.preventDefault();
    if (!authorized) return;
    setAction("busy");
    setError("");
    try {
      const id = await startCheck(target, kind);
      setSelected(id);
      setPage("Checks");
      refresh();
    } catch (error) {
      setError(message(error));
    } finally {
      setAction("idle");
    }
  }
  async function cancel(id: string) {
    try {
      await request(`/api/runs/${id}/cancel`, { method: "POST" });
      refresh();
    } catch (error) {
      setError(message(error));
    }
  }
  function inspect(asset: Asset) {
    setKind(asset.kind);
    setTarget(asset.target);
    setAuthorized(false);
    setPage("Overview");
  }
  const data = load.kind === "ready" ? load.data : null;
  const running =
    data?.runs.some(
      (run) => run.status === "running" || run.status === "cancelling",
    ) ?? false;
  const latest = data?.runs[0];
  return (
    <div className="app-shell">
      <a href="#main" className="skip-link">
        Skip to workspace
      </a>
      <aside className="sidebar">
        <a
          className="brand"
          href="#"
          onClick={(event) => {
            event.preventDefault();
            setPage("Overview");
          }}
        >
          <span className="brand-symbol">◉</span>
          <span>
            GOD'S EYE<small>SECURITY WORKSPACE</small>
          </span>
        </a>
        <div className="workspace-tag">
          <span className="status-dot" /> Local workspace{" "}
          <span className="muted">01</span>
        </div>
        <span className="nav-heading">WORKSPACE</span>
        <nav aria-label="Main navigation">
          {(["Overview", "Assets", "Checks", "Coverage"] satisfies Page[]).map(
            (item, index) => (
              <button
                key={item}
                aria-current={page === item ? "page" : undefined}
                className={page === item ? "nav-active" : ""}
                onClick={() => {
                  setPage(item);
                  setError("");
                }}
              >
                <span className="nav-number">0{index + 1}</span>
                {item}
                {item === "Assets" && (
                  <span className="nav-count">{data?.assets.length ?? 0}</span>
                )}
                {item === "Checks" && running && (
                  <span className="activity-dot" />
                )}
              </button>
            ),
          )}
        </nav>
        <div className="sidebar-note">
          <span className="eyebrow">CONTROL BOUNDARY</span>
          <p>
            Your systems.
            <br />
            Your evidence.
          </p>
          <small>
            Local source checks and explicit, authorized HTTPS inspection.
          </small>
        </div>
        <div className="sidebar-bottom">
          <span className="status-dot" />
          <span>
            Local server <small>v0.2 · open source</small>
          </span>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <span>
            Workspace <span className="slash">/</span> <strong>{page}</strong>
          </span>
          <span className="local-chip">● &nbsp; LOOPBACK ONLY</span>
        </header>
        <main id="main">
          <div className="page-heading">
            <div>
              <span className="eyebrow">OBSERVE / VERIFY / REVIEW</span>
              <h1>
                {page === "Overview"
                  ? "Know what you’re exposing."
                  : page === "Assets"
                    ? "Define your scope."
                    : page === "Checks"
                      ? "Follow the evidence."
                      : "Know the boundaries."}
              </h1>
              <p>
                {page === "Overview"
                  ? "A clear view of your systems, checks and security evidence."
                  : page === "Assets"
                    ? "Sites, APIs, source code and the infrastructure behind them."
                    : page === "Checks"
                      ? "Real check results, with coverage and limitations kept visible."
                      : "What this build can inspect, and what still needs an engine."}
              </p>
            </div>
            <span className="build-label">
              LOCAL EDITION
              <br />
              <strong>0.2 / ACTIVE BUILD</strong>
            </span>
          </div>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          {load.kind === "loading" && (
            <div className="panel empty" role="status">
              Connecting to your workspace…
            </div>
          )}
          {load.kind === "failed" && (
            <div className="panel empty" role="alert">
              <h2>Workspace unavailable</h2>
              <p>{load.error}</p>
              <button onClick={refresh}>Retry connection</button>
            </div>
          )}
          {data && (
            <>
              {page === "Overview" && (
                <>
                  <section className="metrics" aria-label="Workspace summary">
                    <div>
                      <span>Registered assets</span>
                      <strong>
                        {data.assets.length.toString().padStart(2, "0")}
                      </strong>
                      <small>Owned scope · not coverage</small>
                    </div>
                    <div>
                      <span>Session checks</span>
                      <strong>
                        {data.runs.length.toString().padStart(2, "0")}
                      </strong>
                      <small>
                        {running
                          ? "A check is running"
                          : "Ready for your next check"}
                      </small>
                    </div>
                    <div>
                      <span>Latest candidates</span>
                      <strong>
                        {latest
                          ? latest.findingCount.toString().padStart(2, "0")
                          : "—"}
                      </strong>
                      <small>
                        {latest
                          ? "Candidates require verification"
                          : "No checks completed yet"}
                      </small>
                    </div>
                    <div>
                      <span>Native capabilities</span>
                      <strong>02</strong>
                      <small>Secret patterns / HTTPS response</small>
                    </div>
                  </section>
                  <div className="overview-grid">
                    <section className="panel scan-panel">
                      <div className="panel-title">
                        <h2>Start a check</h2>
                        <span className="eyebrow">01 / inspect</span>
                      </div>
                      <form onSubmit={start} className="form-stack">
                        <label>
                          Target type
                          <select
                            value={kind}
                            onChange={(event) => {
                              setKind(event.target.value);
                              setTarget(
                                event.target.value === "source" ? "." : "",
                              );
                              setAuthorized(false);
                            }}
                          >
                            {categories
                              .filter((item) => item.available)
                              .map((item) => (
                                <option key={item.id} value={item.id}>
                                  {item.label}
                                </option>
                              ))}
                          </select>
                        </label>
                        <label>
                          {kind === "source"
                            ? "Directory inside workspace"
                            : "Public HTTPS endpoint"}
                          <input
                            required
                            value={target}
                            onChange={(event) => {
                              setTarget(event.target.value);
                              setAuthorized(false);
                            }}
                            placeholder={
                              kind === "source"
                                ? "services/backend"
                                : "https://your-domain.com"
                            }
                            maxLength={1024}
                          />
                        </label>
                        <div className="scope-note">
                          <span>
                            {kind === "source"
                              ? "WORKSPACE ROOT"
                              : "CHECK COVERAGE"}
                          </span>
                          <code>
                            {kind === "source"
                              ? data.workspace
                              : "One HEAD request · TLS · response headers"}
                          </code>
                        </div>
                        <label className="checkbox">
                          <input
                            type="checkbox"
                            checked={authorized}
                            onChange={(event) =>
                              setAuthorized(event.target.checked)
                            }
                          />
                          I own this target or have permission to assess it.
                        </label>
                        <button
                          className="primary"
                          disabled={!authorized || action === "busy" || running}
                        >
                          {running
                            ? "A check is already running"
                            : action === "busy"
                              ? "Starting…"
                              : "Run check ↗"}
                        </button>
                        <p className="muted small">
                          {kind === "source"
                            ? "Credential values stay out of reports. Source files are not modified."
                            : "No redirects, crawling or attack payloads. Private addresses are not supported in this version."}
                        </p>
                      </form>
                    </section>
                    <section className="panel activity">
                      <div className="panel-title">
                        <h2>Recent activity</h2>
                        <span className="eyebrow">02 / evidence</span>
                      </div>
                      {data.runs.length === 0 ? (
                        <div className="empty">
                          <div className="scope-orbit">
                            <span>◎</span>
                          </div>
                          <h3>Ready when you are.</h3>
                          <p>
                            Start with a local source check.
                            <br />
                            Your first results will appear here.
                          </p>
                        </div>
                      ) : (
                        <div className="activity-list">
                          {data.runs.slice(0, 5).map((run) => (
                            <button
                              key={run.id}
                              onClick={() => {
                                setSelected(run.id);
                                setPage("Checks");
                              }}
                            >
                              <span className={`badge ${run.status}`}>
                                {run.status}
                              </span>
                              <strong>{run.target}</strong>
                              <small>
                                {categoryLabel(run.kind)} ·{" "}
                                {new Date(run.startedAt).toLocaleTimeString()}
                              </small>
                              <span className="activity-arrow">↗</span>
                            </button>
                          ))}
                        </div>
                      )}
                      <div className="panel-footer">
                        Checks remain available during this server session.
                      </div>
                    </section>
                  </div>
                  <section className="scope-strip">
                    <div>
                      <span className="eyebrow">
                        NEXT / BUILD YOUR INVENTORY
                      </span>
                      <h2>One workspace. Every layer of your stack.</h2>
                      <p>
                        Register deployed services alongside source
                        repositories. Keep untested assets visible.
                      </p>
                    </div>
                    <button onClick={() => setPage("Assets")}>
                      Manage assets →
                    </button>
                  </section>
                </>
              )}
              {page === "Assets" && (
                <Assets
                  assets={data.assets}
                  refresh={refresh}
                  inspect={inspect}
                />
              )}
              {page === "Checks" && (
                <Checks
                  runs={data.runs}
                  selected={selected}
                  select={setSelected}
                  cancel={(id) => void cancel(id)}
                />
              )}
              {page === "Coverage" && (
                <>
                  <section className="panel">
                    <div className="panel-title">
                      <h2>Capability coverage</h2>
                      <span className="badge neutral">
                        No external tool integrations
                      </span>
                    </div>
                    <div className="table-scroll">
                      <table>
                        <thead>
                          <tr>
                            <th>Asset category</th>
                            <th>Available now</th>
                            <th>Depth</th>
                          </tr>
                        </thead>
                        <tbody>
                          {categories.map((item) => (
                            <tr key={item.id}>
                              <td>
                                <strong>{item.label}</strong>
                              </td>
                              <td>{item.coverage}</td>
                              <td>
                                <span
                                  className={`badge ${item.available ? "observed" : "neutral"}`}
                                >
                                  {item.available
                                    ? "Limited checks"
                                    : "Not assessed"}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </section>
                  <div className="coverage-notes">
                    <section className="panel">
                      <h2>A platform you can extend</h2>
                      <p>
                        Dependency auditing, API schemas, runtime telemetry,
                        infrastructure policy, graph analysis and network
                        diagnostics are planned. Registering an asset does not
                        enable those checks.
                      </p>
                    </section>
                    <section className="panel">
                      <h2>Windows now. Linux when needed.</h2>
                      <p>
                        This control panel runs locally on Windows. Ubuntu is
                        the server target for future network and privileged
                        collectors. Arch is optional, not a requirement.
                      </p>
                    </section>
                  </div>
                  <div className="notice">
                    No tool has access to “all internet data.” Coverage depends
                    on explicit targets, available data, credentials,
                    permissions and implemented checks. Private data and
                    authenticated application routes are not collected by this
                    build.
                  </div>
                </>
              )}
            </>
          )}
          <footer className="main-footer">
            <span>GOD'S EYE / LOCAL SECURITY WORKSPACE</span>
            <span>Evidence over assumptions.</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
