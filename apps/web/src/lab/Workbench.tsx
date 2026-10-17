// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { message, request } from "../api";
import {
  catalogSchema,
  diagnose,
  reportSchema,
  summariesSchema,
  upload,
} from "./api";
import type { Catalog, Report, Summary } from "./api";
import { Evidence } from "./Evidence";
import { LocalRecipes, ProfileReview } from "./LocalRecipes";
import "./workbench.css";

type Load =
  | { kind: "loading" }
  | { kind: "ready"; catalog: Catalog; history: Summary[] }
  | { kind: "error"; error: string };
type Operation = (signal: AbortSignal) => Promise<Report>;
type Perform = (operation: Operation, file?: File) => void;

function ImportForm({
  catalog,
  busy,
  perform,
}: {
  catalog: Catalog;
  busy: boolean;
  perform: Perform;
}) {
  const [format, setFormat] = useState("nmap");
  const [file, setFile] = useState<File | null>(null);
  const selected = catalog.formats.find((item) => item.id === format);
  function submit(event: FormEvent) {
    event.preventDefault();
    if (file)
      perform((signal) =>
        upload(
          `/api/lab/import?format=${encodeURIComponent(format)}`,
          file,
          signal,
        ),
      );
  }
  return (
    <section>
      <div className="lab-section-intro">
        <span className="eyebrow">01 / import evidence</span>
        <h2>Import a security report.</h2>
        <p>
          Normalize existing assessments into searchable findings, observations
          and relationships. Imports run offline.
        </p>
      </div>
      <form className="lab-upload-form" onSubmit={submit}>
        <label>
          Report format
          <select
            value={format}
            disabled={busy}
            onChange={(event) => {
              setFormat(event.target.value);
              setFile(null);
            }}
          >
            {catalog.formats.map((item) => (
              <option key={item.id} value={item.id}>
                {item.label}
              </option>
            ))}
          </select>
        </label>
        <label className="lab-file-picker">
          Report file · up to 8 MiB
          <input
            key={format}
            type="file"
            required
            accept={selected?.extension}
            disabled={busy}
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          />
          <small>
            {file
              ? `${file.name} · ${(file.size / 1024).toFixed(1)} KiB`
              : "XML, JSON, JSONL or CSV, matching the selected format"}
          </small>
        </label>
        <button className="primary" disabled={!file || busy}>
          {busy ? "Processing…" : "Import report ↗"}
        </button>
      </form>
      <p className="lab-footnote">
        Raw request bodies, authorization headers and cookies stay out of
        normalized reports. Titles, paths and resource names may still be
        sensitive.
      </p>
    </section>
  );
}

function DiagnosticsForm({
  busy,
  perform,
}: {
  busy: boolean;
  perform: Perform;
}) {
  const [mode, setMode] = useState("tcp");
  const [target, setTarget] = useState("");
  const [ports, setPorts] = useState("80,443");
  const [authorized, setAuthorized] = useState(false);
  function submit(event: FormEvent) {
    event.preventDefault();
    if (authorized)
      perform((signal) => diagnose(mode, target.trim(), ports, signal));
  }
  return (
    <section>
      <div className="lab-section-intro">
        <span className="eyebrow">02 / network diagnostics</span>
        <h2>Check a host or domain.</h2>
        <p>
          Check selected TCP ports or review DNS and mail policies using the
          system resolver. Connections have a ten-second deadline.
        </p>
      </div>
      <form className="lab-diagnostic-form" onSubmit={submit}>
        <label>
          Diagnostic
          <select
            value={mode}
            disabled={busy}
            onChange={(event) => {
              setMode(event.target.value);
              setTarget("");
              setAuthorized(false);
            }}
          >
            <option value="tcp">TCP connectivity</option>
            <option value="dns">DNS and mail policy</option>
          </select>
        </label>
        <label>
          {mode === "tcp" ? "Hostname or IP address" : "Domain"}
          <input
            required
            disabled={busy}
            value={target}
            maxLength={253}
            onChange={(event) => {
              setTarget(event.target.value);
              setAuthorized(false);
            }}
            placeholder={mode === "tcp" ? "127.0.0.1" : "your-domain.com"}
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        {mode === "tcp" && (
          <label>
            TCP ports · comma separated
            <input
              required
              disabled={busy}
              value={ports}
              onChange={(event) => {
                setPorts(event.target.value);
                setAuthorized(false);
              }}
              maxLength={200}
              placeholder="80,443,8765"
            />
          </label>
        )}
        <label className="checkbox lab-wide">
          <input
            type="checkbox"
            checked={authorized}
            disabled={busy}
            onChange={(event) => setAuthorized(event.target.checked)}
          />
          I own this target or have permission to assess it.
        </label>
        <button className="primary" disabled={busy || !authorized}>
          {busy ? "Checking…" : "Run diagnostic ↗"}
        </button>
      </form>
      <p className="lab-footnote">
        {mode === "tcp"
          ? "Up to 32 explicit ports, four connections at a time, one resolved address. Private hosts and loopback are supported. No payloads or service fingerprinting."
          : "A/AAAA, NS, MX, SPF and DMARC. DNS queries contact infrastructure. No subdomain guessing or crawling."}
      </p>
    </section>
  );
}

function FileForm({ busy, perform }: { busy: boolean; perform: Perform }) {
  const [mode, setMode] = useState("file");
  const [file, setFile] = useState<File | null>(null);
  function submit(event: FormEvent) {
    event.preventDefault();
    if (file)
      perform(
        (signal) => upload(`/api/lab/file?mode=${mode}`, file, signal),
        file,
      );
  }
  return (
    <section>
      <div className="lab-section-intro">
        <span className="eyebrow">03 / offline analysis</span>
        <h2>Inspect a file, capture or policy.</h2>
        <p>
          Analyze file bytes, Ethernet packet captures or an AWS IAM policy.
          Uploaded contents are processed locally and discarded after analysis.
        </p>
      </div>
      <form className="lab-upload-form" onSubmit={submit}>
        <label>
          Analysis
          <select
            disabled={busy}
            value={mode}
            onChange={(event) => {
              setMode(event.target.value);
              setFile(null);
            }}
          >
            <option value="file">File identity and recovery candidates</option>
            <option value="pcap">Classic Ethernet PCAP</option>
            <option value="iam">AWS IAM policy JSON</option>
          </select>
        </label>
        <label className="lab-file-picker">
          Input file · up to 8 MiB
          <input
            key={mode}
            type="file"
            required
            disabled={busy}
            accept={
              mode === "pcap"
                ? ".pcap,.cap"
                : mode === "iam"
                  ? ".json"
                  : undefined
            }
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          />
          <small>
            {file
              ? `${file.name} · ${(file.size / 1024).toFixed(1)} KiB`
              : "Choose evidence from this computer"}
          </small>
        </label>
        <button className="primary" disabled={!file || busy}>
          {busy ? "Analyzing…" : "Analyze file ↗"}
        </button>
      </form>
      <p className="lab-footnote">
        {mode === "file"
          ? "SHA-256, MIME, byte entropy and up to 32 PNG/JPEG/PDF/ZIP signature candidates. Recovery downloads use byte slices from your original file."
          : mode === "pcap"
            ? "IPv4/IPv6 conversations, TCP/UDP ports and packet counts. Export PCAPNG as classic PCAP or TShark JSON before importing."
            : "Flags broad allowed actions, resources, public principals and selected sensitive IAM actions. Effective access depends on policies and conditions outside this file."}
      </p>
    </section>
  );
}

const workspaceModes = [
  { id: "import", label: "Report import", detail: "14 documented formats" },
  { id: "network", label: "Network", detail: "TCP + DNS posture" },
  { id: "files", label: "Files & cloud", detail: "PCAP, recovery, IAM" },
  { id: "recipes", label: "Data recipes", detail: "18 local operations" },
  { id: "profiles", label: "Profile review", detail: "Manual public links" },
];

export default function Workbench() {
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [revision, setRevision] = useState(0);
  const [mode, setMode] = useState("import");
  const [report, setReport] = useState<Report | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [sourceFile, setSourceFile] = useState<File | null>(null);
  const active = useRef<AbortController | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    void Promise.all([
      request("/api/lab/catalog", { signal: controller.signal }).then((value) =>
        catalogSchema.parse(value),
      ),
      request("/api/lab/reports", { signal: controller.signal }).then((value) =>
        summariesSchema.parse(value),
      ),
    ])
      .then(([catalog, history]) => {
        if (!controller.signal.aborted)
          setLoad({ kind: "ready", catalog, history });
      })
      .catch((error) => {
        if (!controller.signal.aborted)
          setLoad({ kind: "error", error: message(error) });
      });
    return () => controller.abort();
  }, [revision]);
  useEffect(() => () => active.current?.abort(), []);

  function perform(operation: Operation, file?: File) {
    if (active.current) return;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setError("");
    void operation(controller.signal)
      .then((result) => {
        if (!controller.signal.aborted) {
          setReport(result);
          setSourceFile(file ?? null);
          setRevision((value) => value + 1);
        }
      })
      .catch((error) => {
        if (!controller.signal.aborted) setError(message(error));
      })
      .finally(() => {
        if (active.current === controller) {
          active.current = null;
          setBusy(false);
        }
      });
  }

  if (load.kind === "loading")
    return (
      <div className="panel lab-empty" role="status">
        Loading tools and evidence…
      </div>
    );
  if (load.kind === "error")
    return (
      <div className="panel error" role="alert">
        <p>{load.error}</p>
        <button
          onClick={() => {
            setLoad({ kind: "loading" });
            setRevision((value) => value + 1);
          }}
        >
          Retry
        </button>
      </div>
    );
  return (
    <div className="lab-workspace">
      <div className="lab-topline">
        <span>
          <span className="status-dot" /> Local processing
        </span>
        <span>Evidence persists · last 20 reports</span>
        <span>{load.catalog.tools.length} reference tools</span>
      </div>
      <div className="lab-layout">
        <aside className="lab-operation-index" aria-label="Workbench tools">
          {workspaceModes.map((item, index) => (
            <button
              key={item.id}
              disabled={busy}
              aria-pressed={mode === item.id}
              onClick={() => {
                setMode(item.id);
                setError("");
              }}
            >
              <span className="lab-index-number">0{index + 1}</span>
              <span>
                {item.label}
                <small>{item.detail}</small>
              </span>
              <span aria-hidden="true">↗</span>
            </button>
          ))}
        </aside>
        <div className="lab-operation-panel">
          {mode === "import" && (
            <ImportForm catalog={load.catalog} busy={busy} perform={perform} />
          )}
          {mode === "network" && (
            <DiagnosticsForm busy={busy} perform={perform} />
          )}
          {mode === "files" && <FileForm busy={busy} perform={perform} />}
          {mode === "recipes" && <LocalRecipes />}
          {mode === "profiles" && <ProfileReview />}
          {busy && (
            <div className="lab-progress" role="status">
              <span>Processing bounded operation…</span>
              <button
                onClick={() => {
                  active.current?.abort();
                  active.current = null;
                  setBusy(false);
                  setError(
                    "Stopped waiting for the operation. Check saved reports before retrying, because the server may have completed it.",
                  );
                }}
              >
                Cancel
              </button>
            </div>
          )}
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
        </div>
      </div>
      {mode !== "recipes" && mode !== "profiles" && (
        <>
          <details className="lab-history">
            <summary>
              Saved evidence <span>{load.history.length} / 20 reports</span>
            </summary>
            {load.history.length === 0 ? (
              <p className="muted small">
                Imported and native reports will appear here.
              </p>
            ) : (
              <div className="lab-history-list">
                {load.history.map((item) => (
                  <button
                    key={item.id}
                    disabled={busy}
                    aria-pressed={report?.id === item.id}
                    onClick={() =>
                      perform((signal) =>
                        request(
                          `/api/lab/reports/${encodeURIComponent(item.id)}`,
                          { signal },
                        ).then((value) => reportSchema.parse(value)),
                      )
                    }
                  >
                    <span>{item.tool}</span>
                    <span>{new Date(item.createdAt).toLocaleString()}</span>
                    <span>
                      {item.findingCount} findings · {item.observationCount}{" "}
                      observations
                    </span>
                  </button>
                ))}
              </div>
            )}
          </details>
          {report ? (
            <Evidence key={report.id} report={report} sourceFile={sourceFile} />
          ) : (
            <div className="lab-waiting">
              <span className="lab-crosshair" aria-hidden="true">
                +
              </span>
              <div>
                <h2>Evidence lands here.</h2>
                <p>
                  Import a report or run a local analysis to inspect findings
                  and relationships.
                </p>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export function ToolLibrary() {
  const [load, setLoad] = useState<
    | { kind: "loading" }
    | { kind: "ready"; catalog: Catalog }
    | { kind: "error"; error: string }
  >({ kind: "loading" });
  const [search, setSearch] = useState("");
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    void request("/api/lab/catalog", { signal: controller.signal })
      .then((value) => {
        if (!controller.signal.aborted)
          setLoad({ kind: "ready", catalog: catalogSchema.parse(value) });
      })
      .catch((error) => {
        if (!controller.signal.aborted)
          setLoad({ kind: "error", error: message(error) });
      });
    return () => controller.abort();
  }, [revision]);
  if (load.kind === "loading")
    return <p role="status">Loading tool coverage…</p>;
  if (load.kind === "error")
    return (
      <div className="error" role="alert">
        <p>{load.error}</p>
        <button onClick={() => setRevision((value) => value + 1)}>Retry</button>
      </div>
    );
  const tools = load.catalog.tools.filter((tool) =>
    `${tool.name} ${tool.category} ${tool.mode} ${tool.available}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  return (
    <section className="tool-library">
      <div className="lab-topline">
        <span>{load.catalog.tools.length} requested tools reviewed</span>
        <span>Native subsets + report compatibility</span>
        <span>External engines are not bundled</span>
      </div>
      <label className="search-label">
        Find a tool or capability
        <input
          type="search"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Nmap, cloud, capture, graph…"
        />
      </label>
      <div className="tool-table">
        <div className="tool-table-heading">
          <span>Reference / source</span>
          <span>Available in God's Eye</span>
          <span>Scope and license</span>
        </div>
        {tools.map((tool) => (
          <article key={tool.id}>
            <div>
              <span className="eyebrow">{tool.category}</span>
              <h2>
                <a href={tool.source} target="_blank" rel="noopener noreferrer">
                  {tool.name} ↗
                </a>
              </h2>
              <span
                className={`badge ${tool.mode === "Excluded" ? "limited" : "neutral"}`}
              >
                {tool.mode}
              </span>
            </div>
            <p>{tool.available}</p>
            <div>
              <p>{tool.limit}</p>
              <small>{tool.license}</small>
            </div>
          </article>
        ))}
      </div>
      {tools.length === 0 && (
        <div className="lab-empty">No matching tools.</div>
      )}
      <p className="lab-footnote">
        Native subsets provide the specific functionality listed here. Report
        compatibility does not install or reproduce an upstream engine. Reused
        CyberChef helpers and Sherlock templates retain their original licenses
        and pinned provenance.
      </p>
    </section>
  );
}
