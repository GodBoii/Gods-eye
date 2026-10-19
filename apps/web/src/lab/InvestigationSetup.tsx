// SPDX-License-Identifier: Apache-2.0
import type { Dispatch, SetStateAction } from "react";
import { inputKinds, validateInput } from "./investigation-plan";
import type {
  InputKind,
  InvestigationInput,
  PlanItem,
} from "./investigation-plan";

const attachmentKinds: { id: InputKind; label: string }[] = [
  { id: "file", label: "Evidence file" },
  { id: "photo", label: "Photo" },
];

export function InputEntry({
  text,
  files,
  setText,
  setFiles,
  confirmInputs,
}: {
  text: string;
  files: File[];
  setText: Dispatch<SetStateAction<string>>;
  setFiles: Dispatch<SetStateAction<File[]>>;
  confirmInputs: () => void;
}) {
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        confirmInputs();
      }}
      className="investigation-entry"
    >
      <label htmlFor="investigation-inputs">What you already know</label>
      <textarea
        id="investigation-inputs"
        rows={7}
        value={text}
        maxLength={32000}
        onChange={(event) => setText(event.target.value)}
        placeholder={
          "https://example.com\nname@example.com\n@username\n./my-project"
        }
        aria-describedby="input-help"
        spellCheck={false}
      />
      <p id="input-help" className="muted small">
        One item per line, up to 20. URLs, codebase paths, names, email
        addresses, phone numbers, addresses, social handles, companies or apps.
      </p>
      <div className="investigation-attach">
        <label htmlFor="investigation-files">
          Attach photos or evidence files
          <input
            id="investigation-files"
            type="file"
            multiple
            onChange={(event) => setFiles(Array.from(event.target.files ?? []))}
            aria-describedby="file-help"
          />
        </label>
        <small id="file-help">
          Up to 5 files · 8 MiB each · processed by your local server
        </small>
      </div>
      {files.length > 0 && (
        <ul className="attachment-list">
          {files.map((file, index) => (
            <li key={`${file.name}-${index}`}>
              {file.name} <span>{(file.size / 1024).toFixed(1)} KiB</span>
            </li>
          ))}
        </ul>
      )}
      <div className="investigation-actions">
        <p className="muted small">Nothing runs until you review the plan.</p>
        <button className="primary" disabled={!text.trim() && !files.length}>
          Continue →
        </button>
      </div>
      <details className="investigation-help">
        <summary>What can the system investigate?</summary>
        <p>
          Websites, domains, email domain configuration, local source
          directories and file bytes have automated checks. Social handles and
          profile URLs support manual link review. Names, phone numbers, street
          addresses, company names, app names and other details are retained as
          context with no automated lookup.
        </p>
        <p>
          For a remote code repository, provide a local checkout path inside the
          workspace. Pasted code is not treated as a directory. Use Advanced for
          specialized evidence imports and assessment modules.
        </p>
      </details>
    </form>
  );
}

export function ConfirmInputs({
  inputs,
  setInputs,
  workspace,
  createPlan,
  onBack,
}: {
  inputs: InvestigationInput[];
  setInputs: Dispatch<SetStateAction<InvestigationInput[]>>;
  workspace: string;
  createPlan: () => void;
  onBack: () => void;
}) {
  return (
    <>
      <div className="confirmed-inputs">
        {inputs.map((input, index) => {
          const validation = input.included ? validateInput(input) : null;
          return (
            <fieldset key={input.id} className="confirmed-input">
              <legend>Input {index + 1}</legend>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={input.included}
                  onChange={(event) =>
                    setInputs(
                      inputs.map((item) =>
                        item.id === input.id
                          ? { ...item, included: event.target.checked }
                          : item,
                      ),
                    )
                  }
                />
                Include this input
              </label>
              <div className="input-context-row">
                <label>
                  {input.file ? "Attached file" : "Value"}
                  <input
                    value={input.value}
                    readOnly={input.file !== null}
                    disabled={!input.included}
                    maxLength={4096}
                    onChange={(event) =>
                      setInputs(
                        inputs.map((item) =>
                          item.id === input.id
                            ? { ...item, value: event.target.value }
                            : item,
                        ),
                      )
                    }
                    aria-invalid={!!validation}
                    aria-describedby={
                      validation ? `${input.id}-error` : undefined
                    }
                  />
                </label>
                <label>
                  Input type
                  <select
                    aria-label={`Input ${index + 1} type`}
                    value={input.kind}
                    disabled={!input.included}
                    onChange={(event) => {
                      const kind = [...inputKinds, ...attachmentKinds].find(
                        (kind) => kind.id === event.target.value,
                      );
                      if (kind)
                        setInputs(
                          inputs.map((item) =>
                            item.id === input.id
                              ? { ...item, kind: kind.id }
                              : item,
                          ),
                        );
                    }}
                  >
                    {input.file ? (
                      <>
                        <option value="photo">Photo</option>
                        <option value="file">Evidence file</option>
                      </>
                    ) : (
                      inputKinds.map((kind) => (
                        <option key={kind.id} value={kind.id}>
                          {kind.label}
                        </option>
                      ))
                    )}
                  </select>
                </label>
              </div>
              {validation && (
                <p id={`${input.id}-error`} className="error small">
                  {validation}
                </p>
              )}
            </fieldset>
          );
        })}
      </div>
      <p className="workspace-path muted small">
        Source directories resolve inside <code>{workspace}</code>
      </p>
      <div className="investigation-actions">
        <button onClick={onBack}>← Edit inputs</button>
        <button
          className="primary"
          disabled={
            !inputs.some((input) => input.included) ||
            inputs.some(
              (input) => input.included && validateInput(input) !== null,
            )
          }
          onClick={createPlan}
        >
          Build investigation plan →
        </button>
      </div>
    </>
  );
}

export function ReviewPlan({
  inputs,
  plan,
  setPlan,
  authorized,
  setAuthorized,
  needsPermission,
  canRun,
  run,
  onBack,
}: {
  inputs: InvestigationInput[];
  plan: PlanItem[];
  setPlan: Dispatch<SetStateAction<PlanItem[]>>;
  authorized: boolean;
  setAuthorized: Dispatch<SetStateAction<boolean>>;
  needsPermission: boolean;
  canRun: boolean;
  run: () => Promise<void>;
  onBack: () => void;
}) {
  return (
    <>
      <div className="investigation-plan">
        {plan.map((item) => (
          <article className="plan-row" key={item.id}>
            {item.operation.kind === "context" ? (
              <span className="context-mark" aria-hidden="true">
                i
              </span>
            ) : (
              <input
                type="checkbox"
                checked={item.selected}
                aria-label={
                  item.title +
                  " for " +
                  inputs.find((input) => input.id === item.inputId)?.value
                }
                onChange={(event) => {
                  setPlan(
                    plan.map((step) =>
                      step.id === item.id
                        ? { ...step, selected: event.target.checked }
                        : step,
                    ),
                  );
                  setAuthorized(false);
                }}
              />
            )}
            <div>
              <span className="plan-input">
                {inputs.find((input) => input.id === item.inputId)?.value}
              </span>
              <h2>{item.title}</h2>
              <p>{item.detail}</p>
            </div>
            <span className="plan-mode">
              {item.operation.kind === "context"
                ? "Context only"
                : item.operation.kind === "manual"
                  ? "Manual review"
                  : item.operation.kind === "file" ||
                      (item.operation.kind === "check" &&
                        item.operation.checkKind === "source")
                    ? "Local analysis"
                    : "Network check"}
            </span>
          </article>
        ))}
      </div>
      <label className="checkbox investigation-consent">
        <input
          type="checkbox"
          checked={authorized}
          onChange={(event) => setAuthorized(event.target.checked)}
        />
        {needsPermission
          ? "I own the selected targets or have permission to run these checks."
          : "I have reviewed the selected analysis and manual review steps."}
      </label>
      <div className="investigation-actions">
        <button onClick={onBack}>← Adjust context</button>
        <button
          className="primary"
          disabled={!canRun}
          onClick={() => void run()}
        >
          Start investigation →
        </button>
      </div>
    </>
  );
}
