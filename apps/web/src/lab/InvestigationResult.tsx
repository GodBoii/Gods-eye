// SPDX-License-Identifier: Apache-2.0
import { Evidence } from "./Evidence";
import type { PlanItem } from "./investigation-plan";
import type { Outcome } from "./investigation-runner";

export function StepResult({
  item,
  outcome,
}: {
  item: PlanItem;
  outcome: Outcome;
}) {
  if (outcome.kind === "research")
    return (
      <section className="identifier-research" aria-label="Identifier research">
        <dl className="identifier-facts">
          {outcome.research.facts.map((fact) => (
            <div key={fact.label}>
              <dt>{fact.label}</dt>
              <dd>{fact.value}</dd>
            </div>
          ))}
        </dl>
        <ul className="coverage-notes">
          {outcome.research.notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
        <details className="result-evidence">
          <summary>
            Explore public sources · {outcome.research.links.length} review
            links
          </summary>
          <p className="muted small">
            Opening a search or profile link shares its query with that service.
            Results and account ownership remain unverified.
          </p>
          <div className="manual-links">
            {outcome.research.links.map((link) => (
              <a
                key={link.url}
                className="button"
                href={link.url}
                target="_blank"
                rel="noopener noreferrer"
              >
                {link.label} ↗
              </a>
            ))}
          </div>
        </details>
      </section>
    );
  if (outcome.kind === "error")
    return (
      <p className="error">
        {outcome.error} Review this input and try a new investigation, or use
        Advanced for individual checks.
      </p>
    );
  if (outcome.kind === "manual")
    return (
      <div className="manual-links">
        {outcome.links.map((link) => (
          <a
            key={link.url}
            className="button"
            href={link.url}
            target="_blank"
            rel="noreferrer"
          >
            {link.label} ↗
          </a>
        ))}
        <p className="muted small">
          Opening a link does not verify an account or connect it to a person.
        </p>
      </div>
    );
  if (outcome.kind === "report")
    return (
      <>
        <p>{outcome.report.summary}</p>
        {outcome.report.tool === "email-breaches" && (
          <p className="muted small">
            Source:{" "}
            <a
              href="https://xposedornot.com/"
              target="_blank"
              rel="noopener noreferrer"
            >
              XposedOrNot
            </a>
            . Historical indexed exposure does not prove current account
            compromise.
          </p>
        )}
        <p className="muted small">
          {outcome.report.findings.length} findings ·{" "}
          {outcome.report.observations.length} observations ·{" "}
          {outcome.report.gaps.length} coverage notes
        </p>
        <details className="result-evidence">
          <summary>View evidence & coverage</summary>
          <Evidence
            report={outcome.report}
            sourceFile={
              item.operation.kind === "file" ? item.operation.file : null
            }
          />
        </details>
      </>
    );
  if (outcome.kind === "run") {
    const run = outcome.run;
    return (
      <>
        <p>
          {run.kind === "source"
            ? `${run.files} files inspected. ${run.findingCount} credential candidates require review.`
            : `${run.checks.length} response checks returned. ${run.reviewCount} items require review.`}
        </p>
        {run.error && <p className="error">{run.error}</p>}
        {run.gaps.length > 0 && (
          <ul className="coverage-notes">
            {run.gaps.map((gap) => (
              <li key={gap}>{gap}</li>
            ))}
          </ul>
        )}
        <details className="result-evidence">
          <summary>View check details</summary>
          {run.checks.map((check) => (
            <article className="check-detail" key={check.name}>
              <strong>
                {check.name} · {check.status}
              </strong>
              <p>{check.detail}</p>
            </article>
          ))}
          {run.findings.map((finding) => (
            <article className="check-detail" key={finding.id}>
              <strong>
                {finding.title} · {finding.severity}
              </strong>
              <code>
                {finding.file}:{finding.line}
              </code>
              <p>{finding.description}</p>
            </article>
          ))}
          <p className="muted small">
            {run.kind === "source"
              ? "Coverage is limited to three credential patterns. This is not a full code security review."
              : "One HTTPS endpoint was checked. This does not establish that the site is secure."}
          </p>
          <a
            className="button"
            href={`/api/runs/${encodeURIComponent(run.id)}/report?format=json`}
          >
            Export check JSON ↓
          </a>
        </details>
      </>
    );
  }
  return null;
}
