// SPDX-License-Identifier: Apache-2.0
export const inputKinds = [
  { id: "website", label: "Website / API URL" },
  { id: "domain", label: "Domain" },
  { id: "source", label: "Codebase directory" },
  { id: "email", label: "Email address" },
  { id: "phone", label: "Phone number" },
  { id: "person", label: "Person name" },
  { id: "address", label: "Street address" },
  { id: "instagram", label: "Instagram username" },
  { id: "facebook", label: "Facebook username" },
  { id: "threads", label: "Threads username" },
  { id: "twitter", label: "X / Twitter username" },
  { id: "username", label: "Other username / ID" },
  { id: "profile", label: "Profile URL" },
  { id: "company", label: "Company name" },
  { id: "app", label: "App name" },
  { id: "details", label: "Other personal details / context" },
] as const;
export type InputKind = (typeof inputKinds)[number]["id"] | "file" | "photo";
export type InvestigationInput = {
  id: string;
  value: string;
  kind: InputKind;
  included: boolean;
  file: File | null;
};
export type Operation =
  | { kind: "check"; target: string; checkKind: "source" | "website" }
  | { kind: "dns"; target: string }
  | { kind: "assessment"; target: string; tool: "nuclei" | "skipfish" }
  | { kind: "file"; file: File }
  | { kind: "manual"; links: { label: string; url: string }[] }
  | { kind: "context" };
export type PlanItem = {
  id: string;
  inputId: string;
  title: string;
  detail: string;
  selected: boolean;
  operation: Operation;
};

const socialHosts = new Map<string, InputKind>([
  ["instagram.com", "instagram"],
  ["facebook.com", "facebook"],
  ["threads.net", "threads"],
  ["threads.com", "threads"],
  ["twitter.com", "twitter"],
  ["x.com", "twitter"],
]);
const domainPattern = /^(?:[a-z\d](?:[a-z\d-]*[a-z\d])?\.)+[a-z]{2,63}$/i;
function webURL(value: string): URL | null {
  try {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) ? url : null;
  } catch {
    return null;
  }
}
export function suggestKind(value: string): InputKind {
  const url = webURL(value);
  if (url)
    return socialHosts.has(url.hostname.replace(/^www\./, "")) &&
      url.pathname !== "/"
      ? "profile"
      : "website";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "email";
  if (/^[+\d][\d\s().-]{6,24}$/.test(value)) return "phone";
  if (/^(?:[a-z]:[\\/]|\.\.?[\\/]|\/)/i.test(value) || value === ".")
    return "source";
  if (domainPattern.test(value)) return "domain";
  if (/^@[\w.-]+$/.test(value)) return "username";
  return "details";
}
export function parseInputs(text: string): InvestigationInput[] {
  const lines = [
    ...new Set(
      text
        .split(/\r?\n/)
        .map((value) => value.trim())
        .filter(Boolean),
    ),
  ];
  if (lines.length > 20)
    throw new Error("Use up to 20 text inputs per investigation.");
  return lines.map((value, index) => ({
    id: `text-${index}`,
    value,
    kind: suggestKind(value),
    included: true,
    file: null,
  }));
}
export function validateInput(input: InvestigationInput): string | null {
  const value = input.value.trim();
  if (!value) return "Enter a value.";
  if (value.length > 4096) return "Use at most 4,096 characters per input.";
  if (input.kind === "website" || input.kind === "profile") {
    const url = webURL(value);
    if (!url || url.username || url.password)
      return "Enter a full HTTP or HTTPS URL without embedded credentials.";
    if (input.kind === "website" && url.protocol !== "https:")
      return "Website checks require HTTPS. Use a full https:// URL.";
  }
  if (
    input.kind === "email" &&
    (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) ||
      !domainPattern.test(value.slice(value.lastIndexOf("@") + 1)))
  )
    return "Enter an email address such as name@example.com.";
  if (input.kind === "domain" && !domainPattern.test(value))
    return "Enter a domain without a URL path, such as example.com.";
  if (
    ["instagram", "facebook", "threads", "twitter"].includes(input.kind) &&
    !/^@?[a-z\d_.-]{1,80}$/i.test(value)
  )
    return "Enter a username, or change the type to Profile URL for a full link.";
  if ((input.kind === "photo" || input.kind === "file") && !input.file)
    return "Attach a file for this input type.";
  if (
    input.file &&
    (input.file.size === 0 || input.file.size > 8 * 1024 * 1024)
  )
    return "Choose a non-empty file up to 8 MiB.";
  return null;
}

export function buildPlan(inputs: InvestigationInput[]): PlanItem[] {
  const plan: PlanItem[] = [];
  for (const input of inputs.filter((item) => item.included)) {
    const error = validateInput(input);
    if (error) throw new Error(`${input.value}: ${error}`);
    const add = (
      suffix: string,
      title: string,
      detail: string,
      operation: Operation,
      selected = true,
    ) =>
      plan.push({
        id: `${input.id}-${suffix}`,
        inputId: input.id,
        title,
        detail,
        operation,
        selected,
      });
    const value = input.value.trim();
    switch (input.kind) {
      case "website": {
        add(
          "https",
          "HTTPS & response headers",
          "One HEAD request, TLS and response configuration. No redirects.",
          { kind: "check", target: value, checkKind: "website" },
        );
        add(
          "exposure",
          "Page exposure review",
          "Native Nuclei-related rules for directory listings, tracebacks, source maps and cookies. Fetches this URL.",
          { kind: "assessment", target: value, tool: "nuclei" },
        );
        add(
          "crawl",
          "Explore linked pages",
          "Native Skipfish-related crawler. Up to eight same-origin pages, depth two. Sends additional requests.",
          { kind: "assessment", target: value, tool: "skipfish" },
          false,
        );
        break;
      }
      case "source":
        add(
          "source",
          "Scan source for credential patterns",
          "Three supported patterns in a directory inside the server workspace. Does not clone a repository or run the code.",
          { kind: "check", target: value, checkKind: "source" },
        );
        break;
      case "email":
      case "domain": {
        const domain =
          input.kind === "email"
            ? value.slice(value.lastIndexOf("@") + 1)
            : value;
        add(
          "dns",
          input.kind === "email"
            ? "Review email domain configuration"
            : "Review DNS & mail policies",
          `Queries ${domain} for A/AAAA, NS, MX, SPF and DMARC. Does not verify a mailbox, its owner or deliverability.`,
          { kind: "dns", target: domain },
        );
        break;
      }
      case "file":
      case "photo":
        if (input.file)
          add(
            "file",
            "Inspect file bytes",
            "Local-server SHA-256, MIME, entropy and file signature candidates. No face recognition, reverse image search or EXIF location extraction.",
            { kind: "file", file: input.file },
          );
        break;
      case "profile":
        add(
          "review",
          "Review the supplied profile",
          "Open the exact supplied link manually. Account existence and identity remain unverified.",
          {
            kind: "manual",
            links: [{ label: "Open supplied profile", url: value }],
          },
        );
        break;
      case "instagram":
      case "facebook":
      case "threads":
      case "twitter": {
        const bases = {
          instagram: "https://www.instagram.com/",
          facebook: "https://www.facebook.com/",
          threads: "https://www.threads.net/@",
          twitter: "https://x.com/",
        };
        add(
          "review",
          "Review a public profile link",
          "A link built from your confirmed platform and username. No lookup has run; matching usernames do not prove identity.",
          {
            kind: "manual",
            links: [
              {
                label: `Open ${inputKinds.find((kind) => kind.id === input.kind)?.label ?? "profile"}`,
                url:
                  bases[input.kind] +
                  encodeURIComponent(value.replace(/^@/, "")),
              },
            ],
          },
        );
        break;
      }
      case "phone":
      case "person":
      case "address":
      case "company":
      case "app":
      case "details":
      case "username":
        add(
          "context",
          "Keep as investigation context",
          "No automated lookup is available for this input type. Add a confirmed website, domain, platform username, profile URL or evidence file to investigate further.",
          { kind: "context" },
        );
        break;
    }
  }
  return plan;
}
