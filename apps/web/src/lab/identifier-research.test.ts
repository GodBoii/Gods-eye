// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { researchIdentifier, validateIdentifier } from "./identifier-research";
import { buildPlan, parseInputs } from "./investigation-plan";
import { executeStep, outcomeLabel } from "./investigation-runner";

test("phone research normalizes international numbers without assigning an owner", () => {
  const research = researchIdentifier("phone", "+44 (20) 7946-0018");
  assert.ok(
    research.facts.some(
      (fact) => fact.label === "E.164 number" && fact.value === "+442079460018",
    ),
  );
  assert.ok(
    research.facts.some(
      (fact) => fact.label === "Numbering-plan region" && fact.value === "GB",
    ),
  );
  assert.ok(research.notes.some((note) => note.includes("reassigned")));
  assert.ok(
    research.links.every(
      (link) => new URL(link.url).searchParams.get("q") === '"+442079460018"',
    ),
  );
  for (const value of [
    "020 7946 0018",
    "+999 123456789",
    "+1",
    "+44 20 7946 0018 ext 42",
    "Call +44 20 7946 0018",
  ])
    assert.ok(validateIdentifier("phone", value));
});

test("email parsing preserves case, dots and tags in the local part", () => {
  const research = researchIdentifier(
    "email",
    " Alice.Example+Research@EXAMPLE.COM ",
  );
  assert.ok(
    research.facts.some(
      (fact) =>
        fact.label === "Domain-normalized address" &&
        fact.value === "Alice.Example+Research@example.com",
    ),
  );
  for (const value of [
    "a..b@example.com",
    ".a@example.com",
    "a.@example.com",
    "a@-example.com",
    "a@example-.com",
    "a b@example.com",
    `${"x".repeat(65)}@example.com`,
  ])
    assert.ok(validateIdentifier("email", value));
});

test("username candidates are templates, with search fallback for unsupported IDs", () => {
  assert.ok(
    researchIdentifier("username", "@example_user").links.some(
      (link) => link.url === "https://gitlab.com/example_user",
    ),
  );
  const research = researchIdentifier("username", "@example.person");
  assert.equal(research.links.length, 2);
  assert.ok(research.notes.some((note) => note.includes("punctuation")));
  for (const value of [
    "../../admin",
    "x?token=y",
    "x#fragment",
    "https://example.com/user",
  ])
    assert.ok(validateIdentifier("username", value));
});

test("name research supports Unicode and safely encodes search queries", () => {
  const value = 'Renée 李 "site:example.com"';
  const research = researchIdentifier("person", value);
  assert.equal(research.facts[0]?.value, value);
  assert.equal(
    new URL(research.links[0]?.url ?? "").searchParams.get("q"),
    '"Renée 李  site:example.com "',
  );
  assert.ok(validateIdentifier("person", "Alice\u202eSmith"));
  assert.ok(validateIdentifier("person", "A"));
});

test("email breaches require explicit plan selection and research runs without I/O", async () => {
  const inputs = parseInputs(
    "name@example.com\n+44 20 7946 0018\n@example\nExample Person",
  );
  const person = inputs.find((input) => input.value === "Example Person");
  assert.ok(person);
  person.kind = "person";
  const plan = buildPlan(inputs);
  assert.equal(
    plan.find((step) => step.operation.kind === "breach")?.selected,
    false,
  );
  assert.equal(
    plan.filter((step) => step.operation.kind === "research").length,
    4,
  );
  const phone = plan.find(
    (step) =>
      step.operation.kind === "research" &&
      step.operation.researchKind === "phone",
  );
  assert.ok(phone);
  const result = await executeStep(phone, new AbortController().signal);
  assert.equal(result.kind, "research");
  assert.equal(outcomeLabel(result), "Local analysis / review links");
  const cancelled = new AbortController();
  cancelled.abort();
  await assert.rejects(executeStep(phone, cancelled.signal));
});
