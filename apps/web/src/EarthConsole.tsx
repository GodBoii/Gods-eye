// SPDX-License-Identifier: Apache-2.0
export function EarthConsole() {
  return (
    <section className="earth-entry">
      <div className="earth-entry-intro">
        <span className="eyebrow">GOD'S EYE VIEW / KEYLESS EDITION</span>
        <h2>The whole Earth.<br />A little less noise.</h2>
        <p>The complete upstream source now lives in this workspace. Explore its 3D globe and public data layers in a separate console, with a new black interface and no provider-key setup.</p>
        <a className="primary button" href="http://127.0.0.1:4173/">Open Earth console <span aria-hidden="true">↗</span></a>
        <small>Runs locally on port 4173. Start both workspaces with scripts/start.ps1.</small>
      </div>
      <div className="earth-entry-orbit" aria-hidden="true"><div /><span>◉</span><small>PUBLIC SOURCES / YOUR PERSPECTIVE</small></div>
      <div className="earth-entry-features">
        <article><span>01</span><h3>Observe</h3><p>Aircraft, satellites, earthquakes, cameras, weather, transit and geographic infrastructure. Coverage depends on each source.</p></article>
        <article><span>02</span><h3>Make it yours</h3><p>Save camera views, place pins, import map files, draw annotations and export your workspace. Search places and layers with Ctrl K.</p></article>
        <article><span>03</span><h3>See what was removed</h3><p>The Excluded section lists Google APIs, AI voice, token-based imagery, live traffic and other disconnected providers with their free alternatives.</p></article>
      </div>
      <p className="earth-entry-note">The original compact World view remains available. The security scanner, assets and check reports continue in this workspace. Third-party data keeps its attribution and usage terms.</p>
    </section>
  );
}
