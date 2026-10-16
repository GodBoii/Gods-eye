// SPDX-License-Identifier: Apache-2.0
import { useState } from "react";
import type { FormEvent } from "react";
import { categories, categoryLabel, message, request } from "./api";
import type { Asset } from "./api";

export function Assets({
  assets,
  refresh,
  inspect,
}: {
  assets: Asset[];
  refresh: () => void;
  inspect: (asset: Asset) => void;
}) {
  const [kind, setKind] = useState("website");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState("");
  const [removing, setRemoving] = useState<string | null>(null);
  async function add(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    setBusy(true);
    setError("");
    try {
      await request("/api/assets", {
        method: "POST",
        body: JSON.stringify({
          name: data.get("name"),
          target: data.get("target"),
          owner: data.get("owner"),
          kind,
        }),
      });
      form.reset();
      refresh();
    } catch (error) {
      setError(message(error));
    } finally {
      setBusy(false);
    }
  }
  async function remove(id: string) {
    setBusy(true);
    setError("");
    try {
      await request(`/api/assets/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      setRemoving(null);
      refresh();
    } catch (error) {
      setError(message(error));
    } finally {
      setBusy(false);
    }
  }
  const visible = assets.filter((asset) =>
    `${asset.name} ${asset.target} ${asset.owner}`
      .toLowerCase()
      .includes(filter.toLowerCase()),
  );
  return (
    <div className="asset-layout">
      <section className="panel">
        <div className="panel-title">
          <h2>Register an asset</h2>
          <span className="eyebrow">01 / scope</span>
        </div>
        <p className="muted">
          Keep the systems you own in one inventory. Registration alone does not
          verify security.
        </p>
        <form onSubmit={add} className="form-stack">
          <label>
            Name
            <input
              name="name"
              required
              maxLength={100}
              placeholder="Production API"
            />
          </label>
          <label>
            Category
            <select
              value={kind}
              onChange={(event) => setKind(event.target.value)}
            >
              {categories.map((item) => (
                <option value={item.id} key={item.id}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Target
            <input
              name="target"
              required
              maxLength={1024}
              placeholder={
                kind === "source"
                  ? "services/api"
                  : "https://api.your-domain.com"
              }
            />
          </label>
          <label>
            Owner <span className="muted">optional</span>
            <input name="owner" maxLength={100} placeholder="Platform team" />
          </label>
          <button className="primary" disabled={busy}>
            {busy ? "Saving…" : "+ Add asset"}
          </button>
        </form>
        {error && (
          <p role="alert" className="error">
            {error}
          </p>
        )}
      </section>
      <section className="panel inventory">
        <div className="panel-title">
          <h2>
            Asset inventory <span className="count">{assets.length}</span>
          </h2>
        </div>
        <label className="search-label">
          Filter assets
          <input
            type="search"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            placeholder="Search name, target or owner"
          />
        </label>
        {visible.length === 0 ? (
          <div className="empty">
            <span className="empty-mark">◎</span>
            <h3>
              {assets.length ? "No matching assets" : "Your scope starts here"}
            </h3>
            <p>
              {assets.length
                ? "Try a different search."
                : "Add a site, repository or service to make its coverage visible."}
            </p>
          </div>
        ) : (
          <div className="asset-list">
            {visible.map((asset) => (
              <article key={asset.id} className="asset-row">
                <div>
                  <span className="eyebrow">{categoryLabel(asset.kind)}</span>
                  <h3>{asset.name}</h3>
                  <code>{asset.target}</code>
                  <p className="muted">{asset.owner || "No owner assigned"}</p>
                </div>
                <div className="row-actions">
                  <span className="badge neutral">Registered</span>
                  {categories.find((item) => item.id === asset.kind)
                    ?.available ? (
                    <button onClick={() => inspect(asset)}>
                      Prepare check ↗
                    </button>
                  ) : (
                    <span className="muted small">Inventory only</span>
                  )}
                  {removing === asset.id ? (
                    <span className="inline-actions">
                      <button
                        className="danger"
                        disabled={busy}
                        onClick={() => void remove(asset.id)}
                      >
                        Confirm removal
                      </button>
                      <button onClick={() => setRemoving(null)}>Keep</button>
                    </span>
                  ) : (
                    <button
                      className="text-button"
                      onClick={() => setRemoving(asset.id)}
                    >
                      Remove
                    </button>
                  )}
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
