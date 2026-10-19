// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState } from "react";
import { message } from "../api";
import { StepResult } from "./InvestigationResult";
import { InputEntry, ConfirmInputs, ReviewPlan } from "./InvestigationSetup";
import { buildPlan, parseInputs, validateInput } from "./investigation-plan";
import type { InvestigationInput, PlanItem } from "./investigation-plan";
import { executeStep, outcomeLabel } from "./investigation-runner";
import type { Outcome } from "./investigation-runner";
import "./workbench.css";

type Session =
  | { kind: "editing"; step: "inputs" | "confirm" | "plan" }
  | {
      kind: "running" | "finished";
      outcomes: Record<string, Outcome>;
      startedAt: string;
    };

export default function Investigation({
  workspace,
  seed,
  onActivity,
}: {
  workspace: string;
  seed: { target: string; kind: string } | null;
  onActivity: (busy: boolean) => void;
}) {
  const [text, setText] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [inputs, setInputs] = useState<InvestigationInput[]>([]);
  const [plan, setPlan] = useState<PlanItem[]>([]);
  const [session, setSession] = useState<Session>({
    kind: "editing",
    step: "inputs",
  });
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState("");
  const active = useRef<AbortController | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => () => active.current?.abort(), []);
  useEffect(() => {
    if (!seed || active.current) return;
    setText(seed.target);
    setInputs([
      {
        id: "asset",
        value: seed.target,
        kind: seed.kind === "source" ? "source" : "website",
        included: true,
        file: null,
      },
    ]);
    setFiles([]);
    setSession({ kind: "editing", step: "confirm" });
    setAuthorized(false);
    setError("");
  }, [seed]);
  const stage = session.kind === "editing" ? session.step : "results";
  useEffect(() => {
    heading.current?.focus();
  }, [stage]);

  function confirmInputs() {
    try {
      const parsed = parseInputs(text);
      if (files.length > 5)
        throw new Error("Attach up to five files per investigation.");
      files.forEach((file, index) =>
        parsed.push({
          id: `file-${index}`,
          value: file.name,
          kind: file.type.startsWith("image/") ? "photo" : "file",
          included: true,
          file,
        }),
      );
      if (!parsed.length)
        throw new Error("Add at least one input or file to continue.");
      setInputs(parsed);
      setSession({ kind: "editing", step: "confirm" });
      setError("");
    } catch (error) {
      setError(message(error));
    }
  }
  function createPlan() {
    try {
      if (!inputs.some((input) => input.included))
        throw new Error("Select at least one input to include.");
      setPlan(buildPlan(inputs));
      setAuthorized(false);
      setSession({ kind: "editing", step: "plan" });
      setError("");
    } catch (error) {
      setError(message(error));
    }
  }
  async function run() {
    if (active.current || !authorized) return;
    const controller = new AbortController();
    active.current = controller;
    onActivity(true);
    const startedAt = new Date().toISOString();
    const outcomes: Record<string, Outcome> = Object.fromEntries(
      plan.map((item) => [
        item.id,
        { kind: item.selected ? "queued" : "skipped" },
      ]),
    );
    const publish = (kind: "running" | "finished") =>
      setSession({ kind, outcomes: { ...outcomes }, startedAt });
    publish("running");
    setError("");
    try {
      for (const item of plan) {
        if (!item.selected) continue;
        if (controller.signal.aborted) {
          outcomes[item.id] = { kind: "stopped" };
          continue;
        }
        outcomes[item.id] = { kind: "running" };
        publish("running");
        try {
          outcomes[item.id] = await executeStep(item, controller.signal);
        } catch (error) {
          outcomes[item.id] = controller.signal.aborted
            ? { kind: "stopped" }
            : { kind: "error", error: message(error) };
        }
        publish("running");
      }
    } finally {
      active.current = null;
      onActivity(false);
      publish("finished");
    }
  }
  const selectedCount = plan.filter((item) => item.selected).length;
  const canRun = selectedCount > 0 && authorized;
  const finishedCount =
    session.kind !== "editing"
      ? Object.values(session.outcomes).filter(
          (outcome) => !["queued", "running", "skipped"].includes(outcome.kind),
        ).length
      : 0;
  const needsPermission = plan.some(
    (item) =>
      item.selected &&
      ["check", "assessment", "dns", "breach"].includes(item.operation.kind),
  );
  function exportResult() {
    if (session.kind === "editing") return;
    const result = {
      version: 1,
      startedAt: session.startedAt,
      inputs: inputs
        .filter((input) => input.included)
        .map(({ id, value, kind }) => ({ id, value, kind })),
      steps: plan.map((item) => ({
        id: item.id,
        inputId: item.inputId,
        title: item.title,
        coverage: item.detail,
        outcome: session.outcomes[item.id],
      })),
    };
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(result, null, 2)], { type: "application/json" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `godseye-investigation-${session.startedAt.replace(/[:.]/g, "-")}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return (
    <div className="investigation">
      <ol className="investigation-steps" aria-label="Investigation progress">
        {[
          { id: "inputs", label: "Add inputs" },
          { id: "confirm", label: "Confirm context" },
          { id: "plan", label: "Review plan" },
          { id: "results", label: "Results" },
        ].map((step, index) => (
          <li
            key={step.id}
            aria-current={stage === step.id ? "step" : undefined}
          >
            <span>{index + 1}</span>
            {step.label}
          </li>
        ))}
      </ol>
      <div className="investigation-title">
        <span className="eyebrow">
          {stage === "inputs"
            ? "START AN INVESTIGATION"
            : stage === "confirm"
              ? "YOUR INPUTS"
              : stage === "plan"
                ? "PROPOSED CHECKS"
                : "INVESTIGATION RESULTS"}
        </span>
        <h1 ref={heading} tabIndex={-1}>
          {stage === "inputs"
            ? "What do you want to investigate?"
            : stage === "confirm"
              ? "Tell us what each input means."
              : stage === "plan"
                ? "Here’s what will run."
                : session.kind === "running"
                  ? "Your investigation is running."
                  : "Review what we found."}
        </h1>
        <p>
          {stage === "inputs"
            ? "Start with what you have. We’ll help you choose the relevant checks."
            : stage === "confirm"
              ? "Types are suggested by format. Correct them before building your plan."
              : stage === "plan"
                ? "Checks are selected from your confirmed input types. Review their scope before starting."
                : "Each check has its own status, evidence and coverage. Unverified inputs stay unverified."}
        </p>
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {stage === "inputs" && (
        <InputEntry
          text={text}
          files={files}
          setText={setText}
          setFiles={setFiles}
          confirmInputs={confirmInputs}
        />
      )}
      {stage === "confirm" && (
        <ConfirmInputs
          inputs={inputs}
          setInputs={setInputs}
          workspace={workspace}
          createPlan={createPlan}
          onBack={() => {
            setError("");
            setSession({ kind: "editing", step: "inputs" });
          }}
        />
      )}
      {stage === "plan" && (
        <ReviewPlan
          inputs={inputs}
          plan={plan}
          setPlan={setPlan}
          authorized={authorized}
          setAuthorized={setAuthorized}
          needsPermission={needsPermission}
          canRun={canRun}
          run={run}
          onBack={() => {
            setError("");
            setSession({ kind: "editing", step: "confirm" });
          }}
        />
      )}
      {session.kind !== "editing" && (
        <>
          <div className="investigation-progress" role="status">
            <span>
              {finishedCount} of {selectedCount} selected steps processed
              {session.kind === "running"
                ? " · checks run in sequence"
                : " · review statuses below"}
            </span>
            <progress
              max={Math.max(1, selectedCount)}
              value={finishedCount}
              aria-label="Steps processed"
            />
            {session.kind === "running" ? (
              <button onClick={() => active.current?.abort()}>
                Stop investigation
              </button>
            ) : (
              <button onClick={exportResult}>Export investigation ↓</button>
            )}
          </div>
          {session.kind === "finished" && (
            <p className="result-retention muted small">
              The full investigation stays in this tab until you start again or
              reload. Export it to retain input context and step statuses.
              Server reports are available in Saved results. Local identifier
              analysis and review links are included in this export only.
            </p>
          )}
          {session.kind === "finished" &&
            Object.values(session.outcomes).some(
              (outcome) => outcome.kind === "stopped",
            ) && (
              <p className="notice">
                Stopped waiting. Some server operations may have finished.
                Review Saved results before retrying.
              </p>
            )}
          <div className="investigation-results">
            {plan.map((item) => {
              const outcome = session.outcomes[item.id] ?? { kind: "queued" };
              return (
                <article className="investigation-result" key={item.id}>
                  <header>
                    <div>
                      <span className="plan-input">
                        {
                          inputs.find((input) => input.id === item.inputId)
                            ?.value
                        }
                      </span>
                      <h2>{item.title}</h2>
                    </div>
                    <span className={`step-status status-${outcome.kind}`}>
                      {outcomeLabel(outcome)}
                    </span>
                  </header>
                  <p className="muted small">{item.detail}</p>
                  <StepResult item={item} outcome={outcome} />
                </article>
              );
            })}
          </div>
          {session.kind === "finished" && (
            <div className="investigation-actions">
              <p className="muted small">
                Keep useful evidence, then refine the inputs or start again.
              </p>
              <button
                onClick={() => {
                  setAuthorized(false);
                  setSession({ kind: "editing", step: "confirm" });
                }}
              >
                Refine investigation
              </button>
              <button
                onClick={() => {
                  setText("");
                  setFiles([]);
                  setInputs([]);
                  setPlan([]);
                  setAuthorized(false);
                  setSession({ kind: "editing", step: "inputs" });
                }}
              >
                New investigation
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
