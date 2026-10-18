// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { z } from "zod";
import { message, request } from "../api";

const capabilitiesSchema = z.array(
  z.object({
    id: z.string(),
    name: z.string().default(""),
    coverage: z.string(),
    inputHelp: z.string(),
    inputKind: z.string(),
    limit: z.string(),
    engine: z.string(),
    engineAvailable: z.boolean(),
  }),
);
type Capability = z.infer<typeof capabilitiesSchema>[number];
type Load =
  | { kind: "loading" }
  | { kind: "ready"; tools: Capability[] }
  | { kind: "failed"; error: string };

export type AssessmentRequest = {
  tool: string;
  target: string;
  input: string;
  encoding: "text" | "base64";
  ports: number[];
  authorized: boolean;
  runEngine: boolean;
};

export function Assessments({
  busy,
  onRun,
}: {
  busy: boolean;
  onRun: (request: AssessmentRequest, file?: File) => void;
}) {
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [revision, setRevision] = useState(0);
  const [tool, setTool] = useState("nuclei");
  const [target, setTarget] = useState("");
  const [input, setInput] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [ports, setPorts] = useState("80,443");
  const [authorized, setAuthorized] = useState(false);
  const [engine, setEngine] = useState(false);
  const [reading, setReading] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    void request("/api/lab/capabilities", { signal: controller.signal })
      .then((body) => {
        if (!controller.signal.aborted)
          setLoad({ kind: "ready", tools: capabilitiesSchema.parse(body) });
      })
      .catch((error) => {
        if (!controller.signal.aborted)
          setLoad({ kind: "failed", error: message(error) });
      });
    return () => controller.abort();
  }, [revision]);
  if (load.kind === "loading")
    return <p role="status">Loading assessment capabilities…</p>;
  if (load.kind === "failed")
    return (
      <div role="alert">
        <p>{load.error}</p>
        <button
          onClick={() => {
            setLoad({ kind: "loading" });
            setRevision((value) => value + 1);
          }}
        >
          Retry capabilities
        </button>
      </div>
    );
  const selected = load.tools.find((item) => item.id === tool) ?? load.tools[0];
  if (!selected)
    return <p>No assessment modules are available in this server build.</p>;
  const disabled = busy || reading;
  const needsPorts =
    selected.id === "nmap" ||
    selected.id === "netcat" ||
    selected.id === "hping3";
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!selected || !authorized) return;
    setError("");
    setReading(true);
    try {
      const parsedPorts = needsPorts
        ? ports.split(",").map((value) => Number(value.trim()))
        : [];
      if (
        needsPorts &&
        (parsedPorts.length > 32 ||
          parsedPorts.some(
            (value) => !Number.isInteger(value) || value < 1 || value > 65535,
          ) ||
          new Set(parsedPorts).size !== parsedPorts.length)
      )
        throw new Error("Use 1 to 32 unique ports from 1 to 65535.");
      let data = input;
      let encoding: AssessmentRequest["encoding"] = "text";
      if (file) {
        if (file.size === 0 || file.size > 6 * 1024 * 1024)
          throw new Error("Choose a non-empty input file up to 6 MiB.");
        const bytes = new Uint8Array(await file.arrayBuffer());
        let binary = "";
        for (let offset = 0; offset < bytes.length; offset += 4096)
          binary += String.fromCharCode(
            ...bytes.subarray(offset, offset + 4096),
          );
        data = btoa(binary);
        encoding = "base64";
      }
      if (new TextEncoder().encode(data).length > 8 * 1024 * 1024)
        throw new Error("Assessment input exceeds the upload limit.");
      onRun(
        {
          tool: selected.id,
          target: target.trim(),
          input: data,
          encoding,
          ports: parsedPorts,
          authorized,
          runEngine: engine,
        },
        file ?? undefined,
      );
    } catch (error) {
      setError(message(error));
    } finally {
      setReading(false);
    }
  }
  return (
    <section>
      <div className="lab-section-intro">
        <span className="eyebrow">Run / collect / verify</span>
        <h2>Run an assessment.</h2>
        <p>
          Choose a module, provide its target or evidence, and inspect the
          findings with explicit coverage limits.
        </p>
      </div>
      <form
        className="lab-diagnostic-form"
        onSubmit={(event) => void submit(event)}
      >
        <label className="lab-wide">
          Assessment module
          <select
            value={selected.id}
            disabled={disabled}
            onChange={(event) => {
              setTool(event.target.value);
              setTarget("");
              setInput("");
              setFile(null);
              setAuthorized(false);
              setEngine(false);
              setError("");
            }}
          >
            {load.tools.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name || item.id}
              </option>
            ))}
          </select>
        </label>
        <p className="lab-wide lab-footnote">
          {selected.coverage}
          <br />
          {selected.inputHelp}
        </p>
        <label className="lab-wide">
          Target URL, hostname or evidence label
          <input
            disabled={disabled}
            value={target}
            maxLength={4096}
            spellCheck={false}
            autoComplete="off"
            placeholder={
              selected.inputKind === "url"
                ? "https://your-domain.com/"
                : "As specified by the selected module"
            }
            onChange={(event) => {
              setTarget(event.target.value);
              setAuthorized(false);
            }}
          />
        </label>
        {needsPorts && (
          <label className="lab-wide">
            Assessment ports
            <input
              disabled={disabled}
              value={ports}
              onChange={(event) => {
                setPorts(event.target.value);
                setAuthorized(false);
              }}
            />
          </label>
        )}
        <label className="lab-wide">
          Evidence or configuration text
          <textarea
            rows={6}
            maxLength={6 * 1024 * 1024}
            value={input}
            disabled={disabled || file !== null}
            placeholder="Optional input in the format described above"
            onChange={(event) => {
              setInput(event.target.value);
              setAuthorized(false);
            }}
          />
        </label>
        <label className="lab-wide lab-file-picker">
          Or choose an evidence file, up to 6 MiB
          <input
            key={selected.id}
            type="file"
            disabled={disabled}
            onChange={(event) => {
              setFile(event.target.files?.[0] ?? null);
              setAuthorized(false);
            }}
          />
          <small>
            {file
              ? file.name
              : "Raw input is processed locally by this server; normalized reports are saved."}
          </small>
        </label>
        {selected.engine && (
          <label className="checkbox lab-wide">
            <input
              type="checkbox"
              disabled={disabled || !selected.engineAvailable}
              checked={engine}
              onChange={(event) => {
                setEngine(event.target.checked);
                setAuthorized(false);
              }}
            />
            {selected.engineAvailable
              ? `Use installed ${selected.engine} engine`
              : `${selected.engine} engine is not installed; native assessment is available`}
          </label>
        )}
        <p className="lab-wide lab-footnote">{selected.limit}</p>
        <label className="checkbox lab-wide">
          <input
            type="checkbox"
            disabled={disabled}
            checked={authorized}
            onChange={(event) => setAuthorized(event.target.checked)}
          />
          I own this target or have permission to assess it.
        </label>
        <button className="primary" disabled={disabled || !authorized}>
          {reading
            ? "Reading input…"
            : busy
              ? "Assessing…"
              : "Run assessment ↗"}
        </button>
        {error && (
          <p role="alert" className="error lab-wide">
            {error}
          </p>
        )}
      </form>
    </section>
  );
}
