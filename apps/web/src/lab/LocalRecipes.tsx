// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import type { FormEvent } from "react";
import { message } from "../api";
import { bake, operations, profileLinks } from "./recipes";

export function LocalRecipes() {
  const [input, setInput] = useState("");
  const [recipe, setRecipe] = useState([{ id: 0, operation: "from-base64" }]);
  const [nextID, setNextID] = useState(1);
  const [result, setResult] = useState<
    | { kind: "empty" }
    | { kind: "busy" }
    | { kind: "ready"; output: string }
    | { kind: "error"; error: string }
  >({ kind: "empty" });
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState("");
  async function run(event: FormEvent) {
    event.preventDefault();
    setResult({ kind: "busy" });
    setCopied(false);
    setCopyError("");
    try {
      setResult({
        kind: "ready",
        output: await bake(
          input,
          recipe.map((item) => item.operation),
        ),
      });
    } catch (error) {
      setResult({ kind: "error", error: message(error) });
    }
  }
  return (
    <section className="lab-recipes">
      <div className="lab-section-intro">
        <span className="eyebrow">CyberChef / local data recipes</span>
        <h2>Build a data recipe.</h2>
        <p>
          Runs inside your browser. Input is not sent to the server or saved.
          Two helper algorithms are adapted from CyberChef under Apache-2.0.
        </p>
      </div>
      <form onSubmit={(event) => void run(event)}>
        <div className="recipe-grid">
          <label>
            Input · up to 64 KiB
            <textarea
              value={input}
              disabled={result.kind === "busy"}
              onChange={(event) => {
                setInput(event.target.value);
                setResult({ kind: "empty" });
              }}
              spellCheck={false}
              maxLength={65536}
              placeholder="Paste data to inspect or transform"
            />
          </label>
          <div className="recipe-steps">
            <h3>Recipe</h3>
            {recipe.map((step, index) => (
              <div key={step.id}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                <label className="sr-only" htmlFor={`recipe-${step.id}`}>
                  Operation {index + 1}
                </label>
                <select
                  id={`recipe-${step.id}`}
                  value={step.operation}
                  disabled={result.kind === "busy"}
                  onChange={(event) => {
                    setRecipe(
                      recipe.map((item) =>
                        item.id === step.id
                          ? { ...item, operation: event.target.value }
                          : item,
                      ),
                    );
                    setResult({ kind: "empty" });
                  }}
                >
                  {operations.map((operation) => (
                    <option key={operation.id} value={operation.id}>
                      {operation.label}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  aria-label={`Remove operation ${index + 1}`}
                  disabled={recipe.length === 1 || result.kind === "busy"}
                  onClick={() => {
                    setRecipe(recipe.filter((item) => item.id !== step.id));
                    setResult({ kind: "empty" });
                  }}
                >
                  ×
                </button>
              </div>
            ))}
            <div className="inline-actions">
              <button
                type="button"
                disabled={recipe.length >= 10 || result.kind === "busy"}
                onClick={() => {
                  setRecipe([
                    ...recipe,
                    { id: nextID, operation: "json-format" },
                  ]);
                  setNextID(nextID + 1);
                  setResult({ kind: "empty" });
                }}
              >
                + Add operation
              </button>
              <button className="primary" disabled={result.kind === "busy"}>
                {result.kind === "busy" ? "Running…" : "Run recipe"}
              </button>
            </div>
          </div>
        </div>
      </form>
      {result.kind === "error" && (
        <p className="error" role="alert">
          {result.error}
        </p>
      )}
      <div className="recipe-output">
        <div className="panel-title">
          <h3>Output</h3>
          <button
            disabled={result.kind !== "ready"}
            onClick={() => {
              if (result.kind !== "ready") return;
              void navigator.clipboard
                .writeText(result.output)
                .then(() => setCopied(true))
                .catch((error) => setCopyError(message(error)));
            }}
          >
            {copied ? "Copied" : "Copy output"}
          </button>
        </div>
        <pre aria-live="polite">
          {result.kind === "ready"
            ? result.output
            : result.kind === "busy"
              ? "Running recipe…"
              : "Run a recipe to see the result."}
        </pre>
        {copyError && (
          <p className="error" role="alert">
            Could not copy output. {copyError} Select and copy the output
            manually.
          </p>
        )}
      </div>
    </section>
  );
}

export function ProfileReview() {
  const [username, setUsername] = useState("");
  const [result, setResult] = useState<
    | { kind: "empty" }
    | {
        kind: "ready";
        links: ReturnType<typeof profileLinks>;
        username: string;
      }
    | { kind: "error"; error: string }
  >({ kind: "empty" });
  function submit(event: FormEvent) {
    event.preventDefault();
    try {
      setResult({ kind: "ready", links: profileLinks(username), username });
    } catch (error) {
      setResult({ kind: "error", error: message(error) });
    }
  }
  return (
    <section>
      <div className="lab-section-intro">
        <span className="eyebrow">Sherlock / manual profile review</span>
        <h2>Review a public username.</h2>
        <p>
          Generate links using nine pinned Sherlock URL templates. Links are
          unverified. Matching usernames do not establish that accounts belong
          to the same person.
        </p>
      </div>
      <form className="lab-inline-form" onSubmit={submit}>
        <label>
          Username
          <input
            required
            maxLength={39}
            value={username}
            onChange={(event) => {
              setUsername(event.target.value);
              setResult({ kind: "empty" });
            }}
            placeholder="Your public username"
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <button className="primary">Generate review links</button>
      </form>
      {result.kind === "error" && (
        <p className="error" role="alert">
          {result.error}
        </p>
      )}
      {result.kind === "ready" && (
        <div className="profile-links">
          <p className="muted small">
            {result.links.length} manual links for {result.username}. No
            requests have been made to these sites.
          </p>
          {result.links.map((link) => (
            <a
              key={link.name}
              href={link.url}
              target="_blank"
              rel="noopener noreferrer"
            >
              <span>{link.name}</span>
              <span>Unverified ↗</span>
            </a>
          ))}
        </div>
      )}
    </section>
  );
}
