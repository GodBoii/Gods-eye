// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import {
  buildPlan,
  parseInputs,
  suggestKind,
  validateInput,
} from "./investigation-plan";

test("format suggestions distinguish profiles, email, paths and ambiguous names", () => {
  for (const [value, kind] of [
    ["https://example.com/api", "website"],
    ["https://www.instagram.com/example/", "profile"],
    ["https://x.com", "website"],
    ["https://x.com/example", "profile"],
    ["name@example.com", "email"],
    ["+1 (202) 555-0100", "phone"],
    ["1234567890123", "details"],
    ["example.com", "domain"],
    ["C:\\projects\\example", "source"],
    ["./project", "source"],
    ["@example", "username"],
    ["Example Person", "details"],
  ])
    assert.equal(suggestKind(value ?? ""), kind);
});

test("confirmed context determines routing and excludes deselected inputs", () => {
  const inputs = parseInputs(
    "https://example.com\nname@example.com\n./source\nA Person\nexample.com",
  );
  const person = inputs.find((input) => input.value === "A Person");
  const domain = inputs.find((input) => input.kind === "domain");
  assert.ok(person && domain);
  person.kind = "person";
  domain.included = false;
  const plan = buildPlan(inputs);
  assert.equal(plan.length, 8);
  assert.equal(
    plan.filter((item) => item.operation.kind === "assessment").length,
    2,
  );
  assert.equal(
    plan.find(
      (item) =>
        item.operation.kind === "assessment" &&
        item.operation.tool === "skipfish",
    )?.selected,
    false,
  );
  assert.deepEqual(
    plan.find((item) => item.operation.kind === "dns")?.operation,
    { kind: "dns", target: "example.com" },
  );
  assert.ok(
    plan.some(
      (item) =>
        item.operation.kind === "check" &&
        item.operation.checkKind === "source",
    ),
  );
  assert.ok(plan.some((item) => item.operation.kind === "research"));
  assert.equal(
    plan.find((item) => item.operation.kind === "breach")?.selected,
    false,
  );
  assert.ok(!plan.some((item) => item.inputId === domain.id));
  const first = inputs[0];
  assert.ok(first);
  first.kind = "profile";
  const revised = buildPlan(inputs);
  assert.equal(revised[0]?.operation.kind, "manual");
  assert.ok(!revised.some((item) => item.operation.kind === "assessment"));
});

test("social usernames make manual links without live identity assertions", () => {
  const [input] = parseInputs("@example.person");
  assert.ok(input);
  input.kind = "instagram";
  const [step] = buildPlan([input]);
  assert.equal(step?.operation.kind, "manual");
  if (step?.operation.kind === "manual")
    assert.equal(
      step.operation.links[0]?.url,
      "https://www.instagram.com/example.person",
    );
  input.value = "example/../../other";
  assert.throws(() => buildPlan([input]), /username/);
});

test("input validation rejects unsafe URL schemes, credentials, malformed domains and oversized files", () => {
  const [input] = parseInputs("https://example.com");
  assert.ok(input);
  for (const value of [
    "javascript:alert(1)",
    "file:///secret",
    "https://name:password@example.com",
    "http://example.com",
  ]) {
    assert.ok(validateInput({ ...input, value }));
  }
  assert.equal(
    validateInput({
      ...input,
      kind: "profile",
      value: "http://example.com/user",
    }),
    null,
  );
  assert.ok(
    validateInput({ ...input, kind: "domain", value: "example.com/path" }),
  );
  assert.ok(validateInput({ ...input, kind: "email", value: "person@" }));
  assert.ok(
    validateInput({ ...input, kind: "file", file: new File([], "empty.txt") }),
  );
  assert.ok(
    validateInput({
      ...input,
      kind: "file",
      file: new File([new Uint8Array(8 * 1024 * 1024 + 1)], "large.txt"),
    }),
  );
});

test("text parsing bounds input count and deduplicates exact repeated lines", () => {
  assert.equal(
    parseInputs("example.com\r\n\nexample.com\n @example ").length,
    2,
  );
  assert.throws(
    () =>
      parseInputs(
        Array.from({ length: 21 }, (_, index) => `item ${index}`).join("\n"),
      ),
    /20/,
  );
});

test("photos route to byte analysis and unsupported details remain context only", () => {
  const [input] = parseInputs("photo.png");
  assert.ok(input);
  const file = new File(["fixture"], "photo.png", { type: "image/png" });
  const [step] = buildPlan([{ ...input, kind: "photo", file }]);
  assert.equal(step?.operation.kind, "file");
  for (const kind of ["address", "company", "app", "details"] as const) {
    assert.deepEqual(buildPlan([{ ...input, kind }])[0]?.operation, {
      kind: "context",
    });
  }
});
