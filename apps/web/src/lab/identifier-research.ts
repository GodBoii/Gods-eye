// SPDX-License-Identifier: Apache-2.0
import { parsePhoneNumberFromString } from "libphonenumber-js/max";
import { profileLinks } from "./recipes";

export type ResearchKind = "email" | "phone" | "username" | "person";
export type Research = {
  facts: { label: string; value: string }[];
  notes: string[];
  links: { label: string; url: string }[];
};

const emailPattern =
  /^[a-z\d.!#$%&'*+/=?^_`{|}~-]+@(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z]{2,63}$/i;

export function validateIdentifier(
  kind: ResearchKind,
  raw: string,
): string | null {
  const value = raw.trim();
  if (kind === "email") {
    const local = value.split("@")[0] ?? "";
    if (
      value.length > 254 ||
      local.length > 64 ||
      !emailPattern.test(value) ||
      local.startsWith(".") ||
      local.endsWith(".") ||
      local.includes("..")
    )
      return "Enter a valid email address such as name@example.com, up to 254 characters.";
  }
  if (kind === "phone") {
    if (!/^\+[\d\s().-]{6,40}$/.test(value))
      return "Include the international country code, such as +44 20 7946 0018. Extensions and local-only numbers are not supported.";
    const phone = parsePhoneNumberFromString(value, { extract: false });
    if (!phone?.isPossible())
      return "This number has an unsupported calling code or length. Check the international format.";
  }
  if (kind === "username" && !/^@?[a-z\d_.-]{1,80}$/i.test(value))
    return "Use 1 to 80 letters, digits, dots, underscores or hyphens, with an optional leading @. Use Profile URL for a link.";
  if (
    kind === "person" &&
    (value.length < 2 || value.length > 200 || /[\p{Cc}\p{Cf}]/u.test(value))
  )
    return "Enter a person name with 2 to 200 characters and no hidden control characters.";
  return null;
}

function searchLinks(value: string) {
  // Keep embedded quotes from terminating the exact phrase.
  const query = `"${value.replaceAll('"', " ")}"`;
  return [
    {
      label: "Search Google for this exact identifier",
      url: `https://www.google.com/search?q=${encodeURIComponent(query)}`,
    },
    {
      label: "Search Bing for this exact identifier",
      url: `https://www.bing.com/search?q=${encodeURIComponent(query)}`,
    },
  ];
}

export function researchIdentifier(kind: ResearchKind, raw: string): Research {
  const value = raw.trim();
  const error = validateIdentifier(kind, value);
  if (error) throw new Error(error);
  switch (kind) {
    case "email": {
      const separator = value.lastIndexOf("@");
      const local = value.slice(0, separator);
      const domain = value.slice(separator + 1).toLowerCase();
      return {
        facts: [
          { label: "Mailbox label", value: local },
          { label: "Mail domain", value: domain },
          { label: "Domain-normalized address", value: `${local}@${domain}` },
        ],
        notes: [
          "Local parsing only. This does not confirm mailbox existence, deliverability or ownership.",
          "Local-part casing, dots and plus tags are preserved. Provider-specific aliases are not assumed to be the same mailbox.",
          "The separate optional breach step sends this address to XposedOrNot. Have I Been Pwned is available for manual comparison.",
        ],
        links: [
          ...searchLinks(value),
          {
            label: "Have I Been Pwned manual check",
            url: "https://haveibeenpwned.com/",
          },
          {
            label: "XposedOrNot coverage and API",
            url: "https://xposedornot.com/api_doc",
          },
        ],
      };
    }
    case "phone": {
      const phone = parsePhoneNumberFromString(value, { extract: false });
      if (!phone) throw new Error("Could not parse this phone number.");
      return {
        facts: [
          { label: "E.164 number", value: phone.number },
          { label: "International format", value: phone.formatInternational() },
          { label: "National format", value: phone.formatNational() },
          { label: "Calling code", value: `+${phone.countryCallingCode}` },
          {
            label: "Numbering-plan region",
            value:
              phone.country ??
              (phone.isNonGeographic()
                ? "Non-geographic service"
                : "Shared calling code; region undetermined"),
          },
          {
            label: "Number type in metadata",
            value: phone.getType()?.replaceAll("_", " ") ?? "Unknown",
          },
          {
            label: "Numbering-plan pattern",
            value: phone.isValid()
              ? "Matches bundled numbering metadata"
              : "Possible length; does not match bundled number patterns",
          },
        ],
        notes: [
          "Computed locally with libphonenumber-js metadata. No call, SMS, carrier request or reverse-owner lookup was made.",
          "A region or number type describes a numbering plan, not the owner's location, current carrier or identity. Numbers can be ported or reassigned.",
          "No phone breach database is connected. Public search results require independent review.",
        ],
        links: searchLinks(phone.number),
      };
    }
    case "username": {
      const username = value.replace(/^@/, "");
      // Pinned templates support a narrower handle alphabet than general IDs.
      const profiles = /^[a-z\d_-]{1,39}$/i.test(username)
        ? profileLinks(username).map((link) => ({
            label: `Review ${link.name} candidate`,
            url: link.url,
          }))
        : [];
      return {
        facts: [
          { label: "Public handle / ID", value: username },
          { label: "Candidate profile links", value: String(profiles.length) },
        ],
        notes: [
          "Links are generated locally. No account existence check or sign-in attempt was made.",
          "Matching handles and numeric IDs on different services do not prove shared ownership. Use a confirmed platform or profile URL to narrow the research.",
          ...(profiles.length
            ? []
            : [
                "Pinned profile templates do not support this handle's punctuation or length. Use exact-identifier searches or a confirmed platform instead.",
              ]),
          "No username breach database is connected.",
        ],
        links: [...profiles, ...searchLinks(username)],
      };
    }
    case "person":
      return {
        facts: [
          { label: "Supplied name", value },
          { label: "Identity status", value: "Unverified research context" },
        ],
        notes: [
          "Search links use the exact supplied name. No external search runs until you open one.",
          "Names are not unique. Compare public role, organization, dates and source URLs before associating a record with this person.",
          "No name breach database is connected. Other investigation inputs are not assumed to belong to this person.",
        ],
        links: searchLinks(value),
      };
  }
}
