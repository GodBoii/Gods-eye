// SPDX-License-Identifier: Apache-2.0
import { lazy, Suspense, useEffect, useState } from "react";
import { Assets } from "./Assets";
import { Checks } from "./Checks";
import { EarthConsole } from "./EarthConsole";
import { message, request, stateSchema } from "./api";
import type { Asset, State } from "./api";
import Investigation from "./lab/Investigation";
import { SavedResults } from "./lab/SavedResults";
import "./theme.css";
import "./investigation.css";

const Workbench = lazy(() => import("./lab/Workbench"));
const ToolLibrary = lazy(() =>
  import("./lab/Workbench").then((module) => ({ default: module.ToolLibrary })),
);
type Page = "Investigate" | "Saved results" | "Advanced" | "Earth console";
type Load =
  | { kind: "loading" }
  | { kind: "ready"; data: State }
  | { kind: "failed"; error: string };

export default function App() {
  const [page, setPage] = useState<Page>("Investigate");
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [revision, setRevision] = useState(0);
  const [advanced, setAdvanced] = useState("Specialist tools");
  const [historyView, setHistoryView] = useState("Analysis reports");
  const [selected, setSelected] = useState<string | null>(null);
  const [seed, setSeed] = useState<{ target: string; kind: string } | null>(
    null,
  );
  const [investigating, setInvestigating] = useState(false);
  const [error, setError] = useState("");
  const refresh = () => setRevision((value) => value + 1);
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [page]);
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
        if (!controller.signal.aborted) {
          setLoad({ kind: "ready", data });
          setError("");
        }
      } catch (error) {
        if (!controller.signal.aborted) {
          const detail = message(error);
          setLoad((previous) =>
            previous.kind === "ready"
              ? previous
              : { kind: "failed", error: detail },
          );
          setError(detail);
        }
      }
      if (!controller.signal.aborted)
        timer = setTimeout(() => void poll(), delay);
    }
    const visible = () => {
      if (!document.hidden) refresh();
    };
    document.addEventListener("visibilitychange", visible);
    void poll();
    return () => {
      controller.abort();
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [revision]);
  async function cancel(id: string) {
    try {
      await request(`/api/runs/${encodeURIComponent(id)}/cancel`, {
        method: "POST",
      });
      refresh();
    } catch (error) {
      setError(message(error));
    }
  }
  function inspect(asset: Asset) {
    if (investigating) {
      setError(
        "An investigation is running. Stop it or wait for it to finish before inspecting another asset.",
      );
      return;
    }
    setSeed({ target: asset.target, kind: asset.kind });
    setPage("Investigate");
  }
  const data = load.kind === "ready" ? load.data : null;
  return (
    <div className="app-shell security-skin guided-shell">
      <a href="#main" className="skip-link">
        Skip to workspace
      </a>
      <header className="workspace-header">
        <button
          className="workspace-brand"
          onClick={() => setPage("Investigate")}
        >
          <span aria-hidden="true">◉</span> GOD’S EYE{" "}
          <small>Local investigation workspace</small>
        </button>
        <nav aria-label="Main navigation">
          {(
            [
              "Investigate",
              "Saved results",
              "Advanced",
              "Earth console",
            ] satisfies Page[]
          ).map((item) => (
            <button
              key={item}
              aria-current={page === item ? "page" : undefined}
              className={page === item ? "nav-active" : ""}
              onClick={() => {
                setPage(item);
                setError("");
              }}
            >
              {item}
              {item === "Investigate" && investigating && (
                <span className="activity-dot" aria-label="Running" />
              )}
            </button>
          ))}
        </nav>
        <span className="connection-state">
          <span className="status-dot" />
          {load.kind === "loading"
            ? "Connecting"
            : load.kind === "failed" || error
              ? "Connection / action issue"
              : "Local server connected"}
        </span>
      </header>
      <main id="main">
        {error && load.kind === "ready" && (
          <p className="error" role="alert">
            {error}
            <button onClick={refresh}>Reconnect</button>
          </p>
        )}
        {load.kind === "loading" && (
          <div className="panel empty" role="status">
            Connecting to your local workspace…
          </div>
        )}
        {load.kind === "failed" && (
          <div className="panel empty" role="alert">
            <h1>Workspace unavailable</h1>
            <p>{load.error}</p>
            <button onClick={refresh}>Retry connection</button>
          </div>
        )}
        {data && (
          <>
            <div hidden={page !== "Investigate"}>
              <Investigation
                workspace={data.workspace}
                seed={seed}
              onActivity={(busy) => {
                setInvestigating(busy);
                if (!busy) refresh();
              }}
              />
            </div>
            {page === "Saved results" && (
              <>
                <div className="page-heading">
                  <div>
                    <h1>Saved results</h1>
                    <p>
                      Reopen evidence, review coverage and export what matters.
                    </p>
                  </div>
                </div>
                <div
                  className="workspace-subnav"
                  aria-label="Result categories"
                >
                  {["Analysis reports", "Source & HTTPS checks"].map((item) => (
                    <button
                      key={item}
                      aria-pressed={historyView === item}
                      onClick={() => setHistoryView(item)}
                    >
                      {item}
                    </button>
                  ))}
                </div>
                {historyView === "Analysis reports" ? (
                  <SavedResults />
                ) : (
                  <Checks
                    runs={data.runs}
                    selected={selected}
                    select={setSelected}
                    cancel={(id) => void cancel(id)}
                  />
                )}
              </>
            )}
            {page === "Advanced" && (
              <>
                <div className="page-heading">
                  <div>
                    <h1>Advanced workspace</h1>
                    <p>
                      Use individual modules, import existing evidence or manage
                      your inventory.
                    </p>
                  </div>
                </div>
                <div
                  className="workspace-subnav"
                  aria-label="Advanced categories"
                >
                  {["Specialist tools", "Asset inventory", "Tool coverage"].map(
                    (item) => (
                      <button
                        key={item}
                        aria-pressed={advanced === item}
                        onClick={() => setAdvanced(item)}
                      >
                        {item}
                      </button>
                    ),
                  )}
                </div>
                {advanced === "Asset inventory" ? (
                  <Assets
                    assets={data.assets}
                    refresh={refresh}
                    inspect={inspect}
                  />
                ) : (
                  <Suspense fallback={<p role="status">Loading tools…</p>}>
                    {advanced === "Specialist tools" ? (
                      <Workbench />
                    ) : (
                      <ToolLibrary />
                    )}
                  </Suspense>
                )}
              </>
            )}
            {page === "Earth console" && (
              <>
                <div className="page-heading">
                  <div>
                    <h1>Earth console</h1>
                    <p>
                      Explore public geographic sources in the separate Earth
                      workspace.
                    </p>
                  </div>
                </div>
                <EarthConsole />
              </>
            )}
          </>
        )}
        <footer className="workspace-footer">
          <span>GOD’S EYE · LOCAL WORKSPACE</span>
          <span>Results include their scope and limitations.</span>
        </footer>
      </main>
    </div>
  );
}
