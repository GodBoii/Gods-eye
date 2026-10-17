// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { bake, profileLinks } from "./recipes";
import { shannonEntropy } from "./upstream/cyberchef";

test("recipes preserve UTF-8 through chained encodings and hash known bytes", async () => {
  const input = "Security परीक्षण 🔍";
  assert.equal(
    await bake(input, ["to-base64", "from-base64", "to-hex", "from-hex"]),
    input,
  );
  assert.equal(
    await bake("abc", ["sha256"]),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
  assert.equal(
    await bake("https://example.test/a?x=1", ["url-encode", "url-decode"]),
    "https://example.test/a?x=1",
  );
  assert.equal(await bake("Hello", ["rot13", "rot13"]), "Hello");
  assert.equal(
    await bake('{"x": 1}', ["json-format", "json-minify"]),
    '{"x":1}',
  );
  assert.equal(await bake("b\na\nb", ["sort-lines", "unique-lines"]), "a\nb");
});

test("adapted CyberChef helpers retain entropy behavior and defang links", async () => {
  assert.equal(shannonEntropy(new Uint8Array()), 0);
  assert.equal(shannonEntropy(new Uint8Array([1, 1, 1, 1])), 0);
  assert.equal(
    shannonEntropy(Uint8Array.from({ length: 256 }, (_, index) => index)),
    8,
  );
  assert.equal(
    await bake("https://example.test/path", ["defang"]),
    "hxxps[://]example[.]test/path",
  );
});

test("recipe limits and malformed encodings fail explicitly", async () => {
  for (const [input, recipe] of [
    ["a".repeat(65537), ["to-base64"]],
    ["x", []],
    ["x", Array<string>(11).fill("rot13")],
    ["%", ["from-base64"]],
    ["fff", ["from-hex"]],
    ["ff", ["from-hex"]],
    ["%GG", ["url-decode"]],
    ["invalid", ["json-format"]],
    ["x", ["unknown"]],
    ["a".repeat(65536), Array<string>(8).fill("to-base64")],
  ] satisfies [string, string[]][])
    await assert.rejects(bake(input, recipe));
});

test("JWT inspection makes no trust claim and format hints stay ambiguous", async () => {
  const token = `${btoa('{"alg":"none"}')}.${btoa('{"sub":"fixture"}')}.`;
  const output: unknown = JSON.parse(await bake(token, ["jwt"]));
  assert.equal(typeof output, "object");
  assert.match(await bake(token, ["jwt"]), /NOT verified/);
  assert.match(await bake("a".repeat(32), ["hash-hints"]), /MD5, NTLM/);
  await assert.rejects(bake("one.part", ["jwt"]));
});

test("Sherlock templates generate manual links without accepting path injection", () => {
  const links = profileLinks("fixture-user");
  assert.equal(links.length, 9);
  assert.ok(links.every((link) => new URL(link.url).protocol === "https:"));
  assert.equal(
    links.find((link) => link.name === "HackerNews")?.url,
    "https://news.ycombinator.com/user?id=fixture-user",
  );
  assert.ok(
    !profileLinks("fixture_user").some((link) => link.name === "GitHub"),
  );
  for (const input of [
    "",
    "../secret",
    "name?token=x",
    "name@example.test",
    "<script>",
    "a".repeat(40),
  ])
    assert.throws(() => profileLinks(input));
});
