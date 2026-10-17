// SPDX-License-Identifier: Apache-2.0
import { defangURL, shannonEntropy } from "./upstream/cyberchef";
import { profileTemplates } from "./upstream/profiles";

export const operations = [
  { id: "to-base64", label: "To Base64" },
  { id: "from-base64", label: "From Base64 to UTF-8" },
  { id: "to-hex", label: "To hex" },
  { id: "from-hex", label: "From hex to UTF-8" },
  { id: "url-encode", label: "URL encode" },
  { id: "url-decode", label: "URL decode" },
  { id: "json-format", label: "Format JSON" },
  { id: "json-minify", label: "Minify JSON" },
  { id: "sha256", label: "SHA-256" },
  { id: "sha384", label: "SHA-384" },
  { id: "sha512", label: "SHA-512" },
  { id: "entropy", label: "Byte entropy" },
  { id: "defang", label: "Defang text" },
  { id: "rot13", label: "ROT13" },
  { id: "jwt", label: "Inspect JWT, signature unverified" },
  { id: "hash-hints", label: "Identify hash format candidates" },
  { id: "sort-lines", label: "Sort lines" },
  { id: "unique-lines", label: "Unique lines" },
] satisfies { id: string; label: string }[];

function fromBase64(input: string): Uint8Array {
  const normalized = input.trim().replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) || normalized.length % 4 === 1)
    throw new Error("Invalid Base64 text");
  return Uint8Array.from(atob(normalized), (character) =>
    character.charCodeAt(0),
  );
}

function hex(input: Uint8Array): string {
  return Array.from(input, (value) => value.toString(16).padStart(2, "0")).join(
    "",
  );
}

async function applyOperation(
  operation: string,
  input: string,
): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const decoder = new TextDecoder("utf-8", { fatal: true });
  switch (operation) {
    case "to-base64": {
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary);
    }
    case "from-base64":
      return decoder.decode(fromBase64(input));
    case "to-hex":
      return hex(bytes);
    case "from-hex": {
      const value = input.replace(/\s/g, "");
      if (value.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(value))
        throw new Error("Use complete hexadecimal byte pairs");
      return decoder.decode(
        Uint8Array.from(value.match(/../g) ?? [], (pair) =>
          Number.parseInt(pair, 16),
        ),
      );
    }
    case "url-encode":
      return encodeURIComponent(input);
    case "url-decode":
      return decodeURIComponent(input);
    case "json-format": {
      const parsed: unknown = JSON.parse(input);
      return JSON.stringify(parsed, null, 2);
    }
    case "json-minify": {
      const parsed: unknown = JSON.parse(input);
      return JSON.stringify(parsed);
    }
    case "sha256":
      return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
    case "sha384":
      return hex(new Uint8Array(await crypto.subtle.digest("SHA-384", bytes)));
    case "sha512":
      return hex(new Uint8Array(await crypto.subtle.digest("SHA-512", bytes)));
    case "entropy":
      return `${shannonEntropy(bytes).toFixed(6)} bits/byte\n${bytes.length} bytes\nCompression and encryption can both produce high entropy.`;
    case "defang":
      return defangURL(input);
    case "rot13":
      return input.replace(/[A-Za-z]/g, (character) => {
        const base = character <= "Z" ? 65 : 97;
        return String.fromCharCode(
          ((character.charCodeAt(0) - base + 13) % 26) + base,
        );
      });
    case "jwt": {
      const parts = input.trim().split(".");
      if (parts.length !== 3 || !parts[0] || !parts[1])
        throw new Error("Expected a three-part JWT");
      const header: unknown = JSON.parse(decoder.decode(fromBase64(parts[0])));
      const payload: unknown = JSON.parse(decoder.decode(fromBase64(parts[1])));
      return JSON.stringify(
        {
          warning:
            "Signature and claims are NOT verified. Do not trust this token.",
          header,
          payload,
        },
        null,
        2,
      );
    }
    case "hash-hints": {
      const value = input.trim();
      const hints: string[] = [];
      if (/^[a-f0-9]{32}$/i.test(value))
        hints.push("32 hex characters: MD5, NTLM or another 128-bit value");
      if (/^[a-f0-9]{40}$/i.test(value))
        hints.push("40 hex characters: SHA-1 or another 160-bit value");
      if (/^[a-f0-9]{64}$/i.test(value))
        hints.push("64 hex characters: SHA-256 or another 256-bit value");
      if (/^[a-f0-9]{128}$/i.test(value))
        hints.push("128 hex characters: SHA-512 or another 512-bit value");
      if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(value))
        hints.push("bcrypt modular crypt format");
      if (/^\$argon2(?:id|i|d)\$/.test(value))
        hints.push("Argon2 encoded format prefix");
      if (/^\$6\$/.test(value)) hints.push("SHA-512 crypt format prefix");
      return `${hints.length ? hints.join("\n") : "No supported format hint"}\n\nFormat hints do not identify a hash algorithm conclusively or assess a password.`;
    }
    case "sort-lines":
      return input.split(/\r?\n/).sort().join("\n");
    case "unique-lines":
      return Array.from(new Set(input.split(/\r?\n/))).join("\n");
    default:
      throw new Error("Unknown recipe operation");
  }
}

export async function bake(input: string, recipe: string[]): Promise<string> {
  if (new TextEncoder().encode(input).length > 65536)
    throw new Error("Recipe input is limited to 64 KiB");
  if (recipe.length < 1 || recipe.length > 10)
    throw new Error("Choose 1 to 10 operations");
  let output = input;
  for (const operation of recipe) {
    output = await applyOperation(operation, output);
    if (new TextEncoder().encode(output).length > 262144)
      throw new Error("Recipe output exceeded 256 KiB");
  }
  return output;
}

export function profileLinks(username: string) {
  if (!/^[A-Za-z0-9_-]{1,39}$/.test(username))
    throw new Error(
      "Use a username with 1 to 39 letters, digits, hyphens or underscores",
    );
  return profileTemplates
    .filter(
      (site) => site.regex === null || new RegExp(site.regex).test(username),
    )
    .map((site) => ({
      name: site.name,
      url: site.url.replace("{}", encodeURIComponent(username)),
    }));
}
