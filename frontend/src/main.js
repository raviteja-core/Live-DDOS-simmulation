import Globe from "globe.gl";
import "./styles.css";

const queryParams = new URLSearchParams(window.location.search);
const defaultApiBaseUrl = `${window.location.protocol}//${window.location.hostname}:8000`;
const API_BASE_URL =
  queryParams.get("api") ||
  import.meta.env.VITE_API_BASE_URL ||
  defaultApiBaseUrl;
const THREATS_URL = `${API_BASE_URL}/threats?limit=250`;
const ABUSEIPDB_BASE_URL = `${API_BASE_URL}/abuseipdb`;
const REFRESH_INTERVAL_MS = Number(import.meta.env.VITE_REFRESH_INTERVAL_MS || 300000);
const FAILURE_RETRY_BASE_MS = Number(import.meta.env.VITE_FAILURE_RETRY_BASE_MS || 10000);
const MAX_REFRESH_INTERVAL_MS = Number(
  import.meta.env.VITE_MAX_REFRESH_INTERVAL_MS || REFRESH_INTERVAL_MS * 4
);
const TARGET_HUBS = [
  { name: "Virginia Scrubbing Center", lat: 38.8951, lng: -77.0364 },
  { name: "Frankfurt Edge Gateway", lat: 50.1109, lng: 8.6821 },
  { name: "Singapore Core Relay", lat: 1.3521, lng: 103.8198 },
  { name: "Sydney Traffic Sink", lat: -33.8688, lng: 151.2093 },
];
const THREAT_LEVELS = {
  critical: { label: "Critical", color: "#ff5d73" },
  elevated: { label: "Elevated", color: "#ffb347" },
  observed: { label: "Observed", color: "#6ee7b7" },
};
const FEED_CHANNELS = [
  { key: "critical", label: "CTI", description: "Critical threat intelligence" },
  { key: "elevated", label: "NET", description: "Elevated network abuse" },
  { key: "observed", label: "OBS", description: "Observed low-confidence abuse" },
];
const VIEW_CONFIG = {
  map: {
    title: "Global Threat Feed",
    intro: "Approximate GeoIP visualization of malicious infrastructure and suspicious networks, animated as incoming hostile traffic flows.",
    overlayMode: "full",
    autoRotate: true,
  },
  statistics: {
    title: "Threat Statistics",
    intro: "Score distribution, critical concentration, and current severity mix derived from the latest scored threat batch.",
    overlayMode: "points",
    autoRotate: false,
  },
  sources: {
    title: "Data Sources",
    intro: "Operational context for AbuseIPDB ingestion, GeoLite2 geolocation, and the backend scoring pipeline powering this map.",
    overlayMode: "points",
    autoRotate: true,
  },
  signals: {
    title: "Signal Lanes",
    intro: "High-signal routing view that emphasizes the most suspicious paths and protected hub destinations.",
    overlayMode: "signals",
    autoRotate: false,
  },
};

document.querySelector("#app").innerHTML = `
  <div class="app-shell">
    <header class="top-bar">
      <div class="brand-lockup">
        <span class="brand-main">DDoS Sentinel</span>
        <span class="brand-sub">Attack Map</span>
        <span class="brand-pill">Live DDoS Visualization</span>
      </div>
      <nav class="top-nav">
        <button class="top-nav-item top-nav-item-active" type="button" data-view="map">Map</button>
        <button class="top-nav-item" type="button" data-view="statistics">Statistics</button>
        <button class="top-nav-item" type="button" data-view="sources">Sources</button>
        <button class="top-nav-item" type="button" data-view="signals">Signals</button>
      </nav>
      <div class="top-actions">
        <div class="backend-badge">
          <span>Backend</span>
          <code id="api-base-url"></code>
        </div>
        <button class="action-button" id="shield-button" type="button">Shield Network</button>
      </div>
    </header>

    <main class="dashboard-shell">
      <section class="visual-stage">
        <div class="scene-frame">
          <div id="globe-container" aria-label="3D globe visualization"></div>
          <div class="scene-vignette"></div>
          <div class="glow glow-one"></div>
          <div class="glow glow-two"></div>
          <div class="starfield"></div>

          <aside class="overlay-panel overlay-panel-left intel-panel">
            <section class="intel-card intel-card-primary">
              <div class="intel-heading-row">
                <span class="radar-icon"></span>
                <p class="eyebrow">Iteration 5</p>
              </div>
              <h1 id="view-title">Global Threat Feed</h1>
              <p class="intro" id="view-intro">
                Approximate GeoIP visualization of malicious infrastructure and
                suspicious networks, animated as incoming hostile traffic flows.
              </p>
              <div class="focus-callout">
                <span class="focus-label">Current Focus</span>
                <strong id="focus-title">Scanning live telemetry...</strong>
                <p id="focus-subtitle">Waiting for mapped threat intelligence.</p>
              </div>
              <div class="refresh-meta">
                <div>
                  <span class="focus-label">Last Refresh</span>
                  <strong id="last-refresh">Pending</strong>
                </div>
                <div>
                  <span class="focus-label">Next Poll</span>
                  <strong id="next-refresh">--</strong>
                </div>
              </div>
            </section>

            <section class="intel-card" id="context-panel">
              <div class="section-title-row">
                <h2 id="context-title">Mission Context</h2>
                <span class="section-tag" id="context-tag">Live Feed</span>
              </div>
              <div class="context-list" id="context-list"></div>
            </section>

            <section class="intel-card">
              <div class="metric-grid">
                <div class="metric-box">
                  <span class="label">Visible Points</span>
                  <strong id="threat-count">0</strong>
                </div>
                <div class="metric-box">
                  <span class="label">Animated Arcs</span>
                  <strong id="arc-count">0</strong>
                </div>
                <div class="metric-box">
                  <span class="label">Critical Threats</span>
                  <strong id="critical-count">0</strong>
                </div>
                <div class="metric-box">
                  <span class="label">Status</span>
                  <strong id="status-text">Loading threat feed...</strong>
                </div>
              </div>
            </section>
          </aside>

          <aside class="overlay-panel overlay-panel-right intel-panel">
            <section class="intel-card">
              <div class="section-title-row">
                <h2>Heuristic Scoring</h2>
                <span class="section-tag">Engine Status</span>
              </div>
              <div class="score-overview">
                <div class="score-pill">
                  <span class="label">Mode</span>
                  <strong id="scoring-mode">Loading...</strong>
                </div>
                <div class="score-pill">
                  <span class="label">Avg Score</span>
                  <strong id="avg-score">0</strong>
                </div>
                <div class="score-pill">
                  <span class="label">Top Score</span>
                  <strong id="top-score">0</strong>
                </div>
              </div>
              <div class="distribution-list">
                <div class="distribution-row">
                  <span class="distribution-label">Critical</span>
                  <div class="distribution-track"><span class="distribution-fill distribution-fill-critical" id="critical-distribution"></span></div>
                  <strong id="critical-distribution-count">0</strong>
                </div>
                <div class="distribution-row">
                  <span class="distribution-label">Elevated</span>
                  <div class="distribution-track"><span class="distribution-fill distribution-fill-elevated" id="elevated-distribution"></span></div>
                  <strong id="elevated-distribution-count">0</strong>
                </div>
                <div class="distribution-row">
                  <span class="distribution-label">Observed</span>
                  <div class="distribution-track"><span class="distribution-fill distribution-fill-observed" id="observed-distribution"></span></div>
                  <strong id="observed-distribution-count">0</strong>
                </div>
              </div>
            </section>

            <section class="intel-card">
              <div class="section-title-row">
                <h2>Threat Scale</h2>
                <span class="section-tag">Score Bands</span>
              </div>
              <div class="legend-row">
                <span class="swatch swatch-high"></span>
                <span>Critical score 90+</span>
              </div>
              <div class="legend-row">
                <span class="swatch swatch-medium"></span>
                <span>Elevated score 70-89</span>
              </div>
              <div class="legend-row">
                <span class="swatch swatch-low"></span>
                <span>Observed score below 70</span>
              </div>
            </section>

            <section class="intel-card">
              <div class="section-title-row">
                <h2>Channel Totals</h2>
                <span class="section-tag">Live Mix</span>
              </div>
              <div class="channel-list">
                <div class="channel-row">
                  <span class="channel-code channel-code-critical">CTI</span>
                  <span class="channel-name">Critical threat intelligence</span>
                  <strong id="critical-feed-count">0</strong>
                </div>
                <div class="channel-row">
                  <span class="channel-code channel-code-elevated">NET</span>
                  <span class="channel-name">Elevated network abuse</span>
                  <strong id="elevated-feed-count">0</strong>
                </div>
                <div class="channel-row">
                  <span class="channel-code channel-code-observed">OBS</span>
                  <span class="channel-name">Observed low-confidence abuse</span>
                  <strong id="observed-feed-count">0</strong>
                </div>
              </div>
            </section>

          </aside>

          <div class="right-controls">
            <button class="control-button" id="reset-view-button" type="button" aria-label="Reset globe view">◎</button>
            <button class="control-button" id="overlay-mode-button" type="button" aria-label="Toggle overlay mode">◫</button>
            <button class="control-button" id="zoom-in-button" type="button" aria-label="Zoom in">+</button>
            <button class="control-button" id="zoom-out-button" type="button" aria-label="Zoom out">−</button>
          </div>

          <div class="bottom-dock">
            <div class="floating-note">
              <span class="floating-note-label" id="floating-note-label">Simulation</span>
              <p id="floating-note-text">
                Attack arcs are synthetic flows routed into protected hubs for
                visualization. Geo-location remains approximate.
              </p>
            </div>

            <div class="bottom-strip" id="bottom-strip"></div>
          </div>
        </div>
      </section>
    </main>
  </div>
`;

const globeContainer = document.getElementById("globe-container");
const threatCountElement = document.getElementById("threat-count");
const arcCountElement = document.getElementById("arc-count");
const criticalCountElement = document.getElementById("critical-count");
const statusTextElement = document.getElementById("status-text");
const apiBaseUrlElement = document.getElementById("api-base-url");
const focusTitleElement = document.getElementById("focus-title");
const focusSubtitleElement = document.getElementById("focus-subtitle");
const bottomStripElement = document.getElementById("bottom-strip");
const criticalFeedCountElement = document.getElementById("critical-feed-count");
const elevatedFeedCountElement = document.getElementById("elevated-feed-count");
const observedFeedCountElement = document.getElementById("observed-feed-count");
const scoringModeElement = document.getElementById("scoring-mode");
const avgScoreElement = document.getElementById("avg-score");
const topScoreElement = document.getElementById("top-score");
const criticalDistributionElement = document.getElementById("critical-distribution");
const elevatedDistributionElement = document.getElementById("elevated-distribution");
const observedDistributionElement = document.getElementById("observed-distribution");
const criticalDistributionCountElement = document.getElementById("critical-distribution-count");
const elevatedDistributionCountElement = document.getElementById("elevated-distribution-count");
const observedDistributionCountElement = document.getElementById("observed-distribution-count");
const lastRefreshElement = document.getElementById("last-refresh");
const nextRefreshElement = document.getElementById("next-refresh");
const viewTitleElement = document.getElementById("view-title");
const viewIntroElement = document.getElementById("view-intro");
const contextTitleElement = document.getElementById("context-title");
const contextTagElement = document.getElementById("context-tag");
const contextListElement = document.getElementById("context-list");
const floatingNoteLabelElement = document.getElementById("floating-note-label");
const floatingNoteTextElement = document.getElementById("floating-note-text");
const shieldButtonElement = document.getElementById("shield-button");
const resetViewButtonElement = document.getElementById("reset-view-button");
const overlayModeButtonElement = document.getElementById("overlay-mode-button");
const zoomInButtonElement = document.getElementById("zoom-in-button");
const zoomOutButtonElement = document.getElementById("zoom-out-button");
const navButtonElements = Array.from(document.querySelectorAll(".top-nav-item"));

let isRefreshing = false;
let pollingAttempt = 0;
let refreshTimerId = null;
let nextRefreshAt = Date.now() + REFRESH_INTERVAL_MS;
let currentGlobeAltitude = 1.75;
const appState = {
  activeView: "map",
  overlayMode: "full",
  shieldMode: false,
  threats: [],
  feedMeta: null,
  lastErrorMessage: "",
};

apiBaseUrlElement.textContent = API_BASE_URL;

const globe = Globe()(globeContainer)
  .globeImageUrl("//unpkg.com/three-globe/example/img/earth-night.jpg")
  .bumpImageUrl("//unpkg.com/three-globe/example/img/earth-topology.png")
  .backgroundColor("rgba(0,0,0,0)")
  .showAtmosphere(true)
  .atmosphereColor("#7ce2ff")
  .atmosphereAltitude(0.17)
  .pointsMerge(false)
  .pointAltitude("altitude")
  .pointRadius("radius")
  .pointColor("color")
  .pointResolution(12)
  .pointLabel(
    (point) => `
      <div class="tooltip">
        <strong>${escapeHtml(point.ip)}</strong><br />
        Threat level: ${escapeHtml(point.levelLabel)}<br />
        Threat score: ${getThreatScore(point)}<br />
        Scoring: ${escapeHtml(point.scoring_method || "heuristic_v1")}<br />
        Category: ${escapeHtml(point.category)}<br />
        Coordinates: ${point.latitude.toFixed(2)}, ${point.longitude.toFixed(2)}
      </div>
    `
  );

globe.controls().autoRotate = true;
globe.controls().autoRotateSpeed = 0.32;
globe.pointOfView({ lat: 26, lng: 18, altitude: currentGlobeAltitude }, 1200);

function getThreatColor(score) {
  return THREAT_LEVELS[getThreatLevel(score)].color;
}

function getThreatLevel(score) {
  if (score >= 90) {
    return "critical";
  }
  if (score >= 70) {
    return "elevated";
  }
  return "observed";
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => {
    const replacements = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    return replacements[character];
  });
}

function clearElement(element) {
  element.replaceChildren();
}

function appendStripCard({ code, codeClass, title, caption }) {
  const cardElement = document.createElement("div");
  cardElement.className = "strip-card";

  const codeElement = document.createElement("span");
  codeElement.className = `channel-code ${codeClass}`;
  codeElement.textContent = code;

  const titleElement = document.createElement("strong");
  titleElement.textContent = title;

  const captionElement = document.createElement("span");
  captionElement.className = "strip-caption";
  captionElement.textContent = caption;

  cardElement.append(codeElement, titleElement, captionElement);
  bottomStripElement.append(cardElement);
}

function appendContextRow(label, value) {
  const rowElement = document.createElement("div");
  rowElement.className = "context-row";

  const labelElement = document.createElement("span");
  labelElement.textContent = label;

  const valueElement = document.createElement("strong");
  valueElement.textContent = value;

  rowElement.append(labelElement, valueElement);
  contextListElement.append(rowElement);
}

function getThreatScore(threat) {
  if (Number.isFinite(threat.risk_score)) {
    return threat.risk_score;
  }
  if (Number.isFinite(threat.threat_score)) {
    return threat.threat_score;
  }
  return threat.abuse_confidence_score;
}

function getEffectiveThreatLevel(threat) {
  if (typeof threat.threat_level === "string" && THREAT_LEVELS[threat.threat_level]) {
    return threat.threat_level;
  }
  return getThreatLevel(getThreatScore(threat));
}

function mapThreatToPoint(threat) {
  const score = getThreatScore(threat);
  const level = getEffectiveThreatLevel(threat);
  return {
    ...threat,
    level,
    levelLabel: THREAT_LEVELS[level].label,
    lat: threat.latitude,
    lng: threat.longitude,
    altitude: 0.008 + score / 8000,
    radius: 0.05 + score / 4000,
    color: THREAT_LEVELS[level].color,
  };
}

function createArc(threat, index) {
  const target = TARGET_HUBS[index % TARGET_HUBS.length];
  const score = getThreatScore(threat);
  const level = getEffectiveThreatLevel(threat);
  const color = THREAT_LEVELS[level].color;

  return {
    startLat: threat.latitude,
    startLng: threat.longitude,
    endLat: target.lat,
    endLng: target.lng,
    color,
    stroke: level === "critical" ? 0.85 : level === "elevated" ? 0.55 : 0.35,
    altitude: 0.17 + score / 260,
    dashInitialGap: index * 0.08,
    label: `
      <div class="tooltip">
        <strong>${escapeHtml(threat.ip)}</strong><br />
        Threat level: ${escapeHtml(THREAT_LEVELS[level].label)}<br />
        Route: ${escapeHtml(target.name)}
      </div>
    `,
  };
}

function createRing(threat) {
  const score = getThreatScore(threat);
  const level = getEffectiveThreatLevel(threat);
  return {
    lat: threat.latitude,
    lng: threat.longitude,
    color: THREAT_LEVELS[level].color,
    maxR: 3.2 + score / 35,
    propagationSpeed: 1.6 + score / 120,
    repeatPeriod: 900 + (100 - score) * 12,
  };
}

function renderBottomStrip(counts) {
  const threats = getRenderableThreats();
  clearElement(bottomStripElement);

  if (appState.activeView === "statistics") {
    FEED_CHANNELS.forEach((channel) => {
      const level = channel.key;
      appendStripCard({
        code: channel.label,
        codeClass: `channel-code-${level}`,
        title: String(counts[level]),
        caption: channel.description,
      });
    });
    return;
  }

  if (appState.activeView === "sources") {
    appendStripCard({
      code: "API",
      codeClass: "channel-code-critical",
      title: appState.feedMeta?.source || "Threat Feeds",
      caption: "Combined blacklist ingestion from AbuseIPDB and blocklist.de with backend caching.",
    });
    appendStripCard({
      code: "GEO",
      codeClass: "channel-code-elevated",
      title: "GeoLite2",
      caption: "Approximate coordinate mapping for public IP addresses only.",
    });
    appendStripCard({
      code: "ML",
      codeClass: "channel-code-observed",
      title: appState.threats[0]?.scoring_method || "heuristic_v1",
      caption: "Threat scores are calculated server-side and cached for polling safety.",
    });
    return;
  }

  if (appState.activeView === "signals") {
    TARGET_HUBS.slice(0, 3).forEach((hub, index) => {
      appendStripCard({
        code: "HUB",
        codeClass:
          index === 0
            ? "channel-code-critical"
            : index === 1
              ? "channel-code-elevated"
              : "channel-code-observed",
        title: hub.name,
        caption: "Protected endpoint for routed hostile traffic simulation.",
      });
    });
    return;
  }

  threats.slice(0, 3).forEach((threat) => {
    const level = getEffectiveThreatLevel(threat);
    appendStripCard({
      code: level.slice(0, 3).toUpperCase(),
      codeClass: `channel-code-${level}`,
      title: threat.ip,
      caption: `Score ${getThreatScore(threat)} via ${threat.scoring_method || "heuristic_v1"} scoring.`,
    });
  });
}

function renderContextPanel(stats) {
  const threats = getRenderableThreats();
  const focusThreat = threats[0];
  const scoringMode = stats.scoringMode;
  clearElement(contextListElement);

  if (appState.activeView === "statistics") {
    contextTitleElement.textContent = "Score Spread";
    contextTagElement.textContent = "Statistics";
    appendContextRow("Average score", String(stats.averageScore));
    appendContextRow("Top score", String(stats.topScore));
    appendContextRow(
      "Critical share",
      `${stats.totalThreats ? Math.round((stats.criticalCount / stats.totalThreats) * 100) : 0}%`
    );
    return;
  }

  if (appState.activeView === "sources") {
    contextTitleElement.textContent = "Pipeline";
    contextTagElement.textContent = "Sources";
    appendContextRow("Threat feed", appState.feedMeta?.source || "AbuseIPDB + blocklist.de");
    appendContextRow("Geo mapping", "GeoLite2 City");
    appendContextRow("Scoring mode", scoringMode);
    return;
  }

  if (appState.activeView === "signals") {
    contextTitleElement.textContent = "Signal Routing";
    contextTagElement.textContent = "Priority";
    appendContextRow("Rendered lanes", String(stats.arcCount));
    appendContextRow("Protected hubs", String(TARGET_HUBS.length));
    appendContextRow("Overlay mode", appState.overlayMode);
    return;
  }

  contextTitleElement.textContent = "Mission Context";
  contextTagElement.textContent = "Live Feed";
  if (focusThreat) {
    appendContextRow("Focus threat", focusThreat.ip);
    appendContextRow("Threat level", getEffectiveThreatLevel(focusThreat));
    appendContextRow("Score", String(getThreatScore(focusThreat)));
    return;
  }

  appendContextRow("Mapped threats", "0");
  appendContextRow("Status", "Waiting for GeoIP hits");
  appendContextRow("Scoring mode", scoringMode);
}

function setGlobeView(pointOfView, duration = 1200) {
  currentGlobeAltitude = pointOfView.altitude;
  globe.pointOfView(pointOfView, duration);
}

function getRenderableThreats() {
  let threats = appState.threats
    .filter((threat) => Number.isFinite(threat.latitude) && Number.isFinite(threat.longitude))
    .sort((left, right) => getThreatScore(right) - getThreatScore(left));

  if (appState.activeView === "signals") {
    threats = threats.filter((threat) => getEffectiveThreatLevel(threat) !== "observed");
  }

  if (appState.activeView === "statistics") {
    threats = threats.slice(0, 120);
  }

  if (appState.shieldMode) {
    const criticalThreats = threats.filter((threat) => getEffectiveThreatLevel(threat) === "critical");
    threats = criticalThreats.length ? criticalThreats : threats.slice(0, 50);
  }

  return threats;
}

function selectThreatsForVisualLayer(threats, limit) {
  if (threats.length <= limit) {
    return threats;
  }

  const byLevel = {
    critical: threats.filter((threat) => getEffectiveThreatLevel(threat) === "critical"),
    elevated: threats.filter((threat) => getEffectiveThreatLevel(threat) === "elevated"),
    observed: threats.filter((threat) => getEffectiveThreatLevel(threat) === "observed"),
  };

  const selected = [];
  const levelOrder = ["critical", "elevated", "observed"];
  let cursor = 0;

  while (selected.length < limit) {
    const level = levelOrder[cursor % levelOrder.length];
    const candidate = byLevel[level].shift();
    if (candidate) {
      selected.push(candidate);
    }

    cursor += 1;
    if (!byLevel.critical.length && !byLevel.elevated.length && !byLevel.observed.length) {
      break;
    }
  }

  return selected;
}

function updateControlsUi() {
  navButtonElements.forEach((button) => {
    button.classList.toggle("top-nav-item-active", button.dataset.view === appState.activeView);
  });

  shieldButtonElement.classList.toggle("action-button-active", appState.shieldMode);
  shieldButtonElement.textContent = appState.shieldMode ? "Resume Global View" : "Shield Network";

  overlayModeButtonElement.classList.toggle("control-button-active", appState.overlayMode !== "full");
  overlayModeButtonElement.textContent = appState.overlayMode === "full" ? "◫" : appState.overlayMode === "points" ? "•" : "≈";
  overlayModeButtonElement.title =
    appState.overlayMode === "full"
      ? "Overlay mode: full"
      : appState.overlayMode === "points"
        ? "Overlay mode: points only"
        : "Overlay mode: signal emphasis";
}

function updateFloatingNote(renderableThreats, stats) {
  if (appState.activeView === "statistics") {
    floatingNoteLabelElement.textContent = "Statistics";
    floatingNoteTextElement.textContent = `Average threat score ${stats.averageScore}, top score ${stats.topScore}, and ${stats.criticalCount} critical threats visible in the current sample.`;
    return;
  }

  if (appState.activeView === "sources") {
    floatingNoteLabelElement.textContent = "Sources";
    floatingNoteTextElement.textContent = `Feed combines AbuseIPDB blacklist data, GeoLite2 geolocation, and ${stats.scoringMode} scoring. Cached backend refresh protects the API from excessive polling.`;
    return;
  }

  if (appState.activeView === "signals") {
    floatingNoteLabelElement.textContent = "Signals";
    floatingNoteTextElement.textContent = `Signal view emphasizes critical and elevated traffic lanes. Overlay mode "${appState.overlayMode}" is active across ${renderableThreats.length} mapped threats.`;
    return;
  }

  if (appState.shieldMode) {
    floatingNoteLabelElement.textContent = "Defense Mode";
    floatingNoteTextElement.textContent = `Shield mode filters the globe toward critical infrastructure threats and keeps the focus on the most dangerous hostile paths.`;
    return;
  }

  floatingNoteLabelElement.textContent = "Simulation";
  floatingNoteTextElement.textContent = "Attack arcs are synthetic flows routed into protected hubs for visualization. Geo-location remains approximate.";
}

function updateViewCamera(renderableThreats) {
  if (appState.activeView === "statistics") {
    setGlobeView({ lat: 12, lng: 10, altitude: 2.3 }, 900);
    return;
  }

  if (appState.activeView === "sources") {
    setGlobeView({ lat: 34, lng: -24, altitude: 2.45 }, 900);
    return;
  }

  if (appState.activeView === "signals") {
    const focusThreat = renderableThreats[0];
    if (focusThreat) {
      setGlobeView({ lat: focusThreat.latitude, lng: focusThreat.longitude, altitude: 1.45 }, 900);
      return;
    }
  }

  setGlobeView({ lat: 26, lng: 18, altitude: 1.75 }, 900);
}

function updateDistributionBar(element, count, total) {
  const width = total > 0 ? Math.max(6, Math.round((count / total) * 100)) : 0;
  element.style.width = `${width}%`;
}

function formatTime(timestamp) {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(timestamp);
}

function getNextPollIntervalMs() {
  if (pollingAttempt === 0) {
    return REFRESH_INTERVAL_MS;
  }

  const multiplier = 2 ** Math.max(pollingAttempt - 1, 0);
  return Math.min(FAILURE_RETRY_BASE_MS * multiplier, MAX_REFRESH_INTERVAL_MS);
}

function scheduleNextPoll() {
  if (refreshTimerId !== null) {
    window.clearTimeout(refreshTimerId);
  }

  const nextInterval = getNextPollIntervalMs();
  nextRefreshAt = Date.now() + nextInterval;
  updateRefreshClock();
  refreshTimerId = window.setTimeout(loadThreats, nextInterval);
}

function normalizeThreatFeed(payload) {
  if (Array.isArray(payload)) {
    const mappedCount = payload.filter(
      (threat) => Number.isFinite(threat.latitude) && Number.isFinite(threat.longitude)
    ).length;
    return {
      data: payload,
      meta: {
        source: "unknown",
        cached: false,
        generated_at: new Date().toISOString(),
        count_total: payload.length,
        count_mapped: mappedCount,
      },
    };
  }

  return {
    data: Array.isArray(payload?.data) ? payload.data : [],
    meta: {
      source: payload?.meta?.source || "unknown",
      cached: Boolean(payload?.meta?.cached),
      generated_at: payload?.meta?.generated_at || new Date().toISOString(),
      count_total: Number.isFinite(payload?.meta?.count_total) ? payload.meta.count_total : 0,
      count_mapped: Number.isFinite(payload?.meta?.count_mapped) ? payload.meta.count_mapped : 0,
    },
  };
}

function updateRefreshClock() {
  const remainingMs = Math.max(nextRefreshAt - Date.now(), 0);
  nextRefreshElement.textContent = `${Math.ceil(remainingMs / 1000)}s`;
}

function renderDashboard() {
  const mappedThreats = getRenderableThreats();
  const points = mappedThreats.map(mapThreatToPoint);
  const focusThreat = points[0];
  const overlayMode = appState.overlayMode;
  const criticalThreats = mappedThreats.filter(
    (threat) => getEffectiveThreatLevel(threat) === "critical"
  );
  const elevatedThreats = mappedThreats.filter(
    (threat) => getEffectiveThreatLevel(threat) === "elevated"
  );
  const observedThreats = mappedThreats.filter(
    (threat) => getEffectiveThreatLevel(threat) === "observed"
  );
  const showcaseThreats = selectThreatsForVisualLayer(mappedThreats, 36);
  const ringThreats = selectThreatsForVisualLayer(mappedThreats, 24);
  const arcs =
    overlayMode === "points"
      ? []
      : overlayMode === "signals"
        ? showcaseThreats
            .filter((threat) => getEffectiveThreatLevel(threat) !== "observed")
            .map(createArc)
        : showcaseThreats.map(createArc);
  const rings =
    overlayMode === "points"
      ? []
      : overlayMode === "signals"
        ? ringThreats
            .filter((threat) => getEffectiveThreatLevel(threat) !== "observed")
            .map(createRing)
        : ringThreats.map(createRing);
  const scoreTotal = mappedThreats.reduce((sum, threat) => sum + getThreatScore(threat), 0);
  const averageScore = mappedThreats.length ? Math.round(scoreTotal / mappedThreats.length) : 0;
  const scoringModes = new Set(appState.threats.map((threat) => threat.scoring_method || "heuristic_v1"));
  const feedMeta = appState.feedMeta;
  const scoringModeLabel =
    scoringModes.size === 0
      ? appState.lastErrorMessage
        ? "offline"
        : "heuristic_v1"
      : scoringModes.size === 1
        ? Array.from(scoringModes)[0]
        : "mixed";

  globe.pointsData(points).pointLat("lat").pointLng("lng");
  globe
    .arcsData(arcs)
    .arcColor("color")
    .arcStroke("stroke")
    .arcAltitude("altitude")
    .arcLabel("label")
    .arcDashLength(0.28)
    .arcDashGap(0.45)
    .arcDashInitialGap("dashInitialGap")
    .arcDashAnimateTime(appState.activeView === "signals" ? 900 : 1400);
  globe
    .ringsData(rings)
    .ringColor("color")
    .ringMaxRadius("maxR")
    .ringPropagationSpeed("propagationSpeed")
    .ringRepeatPeriod("repeatPeriod");
  globe.controls().autoRotate = VIEW_CONFIG[appState.activeView].autoRotate;

  threatCountElement.textContent = String(points.length);
  arcCountElement.textContent = String(arcs.length);
  criticalCountElement.textContent = String(criticalThreats.length);
  criticalFeedCountElement.textContent = String(criticalThreats.length);
  elevatedFeedCountElement.textContent = String(elevatedThreats.length);
  observedFeedCountElement.textContent = String(observedThreats.length);
  scoringModeElement.textContent = scoringModeLabel;
  avgScoreElement.textContent = String(averageScore);
  topScoreElement.textContent = mappedThreats.length ? String(getThreatScore(mappedThreats[0])) : "0";
  criticalDistributionCountElement.textContent = String(criticalThreats.length);
  elevatedDistributionCountElement.textContent = String(elevatedThreats.length);
  observedDistributionCountElement.textContent = String(observedThreats.length);
  updateDistributionBar(criticalDistributionElement, criticalThreats.length, mappedThreats.length);
  updateDistributionBar(elevatedDistributionElement, elevatedThreats.length, mappedThreats.length);
  updateDistributionBar(observedDistributionElement, observedThreats.length, mappedThreats.length);
  renderBottomStrip({
    critical: criticalThreats.length,
    elevated: elevatedThreats.length,
    observed: observedThreats.length,
  });

  const stats = {
    averageScore,
    topScore: mappedThreats.length ? getThreatScore(mappedThreats[0]) : 0,
    criticalCount: criticalThreats.length,
    scoringMode: scoringModeLabel,
    arcCount: arcs.length,
    totalThreats: mappedThreats.length,
  };

  const viewConfig = VIEW_CONFIG[appState.activeView];
  viewTitleElement.textContent = viewConfig.title;
  viewIntroElement.textContent = viewConfig.intro;

  if (focusThreat) {
    focusTitleElement.textContent = `${focusThreat.ip} • ${focusThreat.levelLabel}`;
    focusSubtitleElement.textContent = `${focusThreat.category} at ${focusThreat.latitude.toFixed(2)}, ${focusThreat.longitude.toFixed(2)} with score ${getThreatScore(focusThreat)} via ${focusThreat.scoring_method || "heuristic_v1"} scoring.`;
  } else {
    focusTitleElement.textContent = appState.lastErrorMessage ? "Threat feed unavailable" : "No mapped threats available";
    focusSubtitleElement.textContent = appState.lastErrorMessage
      ? appState.lastErrorMessage
      : "GeoLite2 coordinates are required before threats can be staged on the globe.";
  }

  updateFloatingNote(mappedThreats, stats);
  renderContextPanel(stats);
  updateControlsUi();

  statusTextElement.textContent = points.length
    ? `${feedMeta?.cached ? "Cached" : "Live"} ${feedMeta?.source || "threat"} points loaded in ${appState.activeView} view.`
    : appState.lastErrorMessage || "No mapped threats available in the current feed.";
}

async function loadThreats() {
  if (isRefreshing) {
    return;
  }

  isRefreshing = true;
  statusTextElement.textContent = "Loading threat feed...";

  try {
    const response = await fetch(THREATS_URL);
    if (!response.ok) {
      let errorDetail = `Backend responded with ${response.status}`;
      try {
        const errorPayload = await response.json();
        if (typeof errorPayload?.detail === "string" && errorPayload.detail) {
          errorDetail = errorPayload.detail;
        }
      } catch {
        // Ignore JSON parsing failures for error responses.
      }
      throw new Error(errorDetail);
    }

    const payload = normalizeThreatFeed(await response.json());
    appState.threats = payload.data;
    appState.feedMeta = payload.meta;
    appState.lastErrorMessage = "";
    pollingAttempt = 0;
    renderDashboard();
    lastRefreshElement.textContent = formatTime(new Date());
  } catch (error) {
    console.error(error);
    pollingAttempt += 1;
    appState.threats = [];
    appState.feedMeta = null;
    appState.lastErrorMessage =
      error instanceof Error && error.message
        ? `Backend error: ${error.message}`
        : "The frontend could not reach the backend threat endpoint.";
    renderDashboard();
    threatCountElement.textContent = "0";
    arcCountElement.textContent = "0";
    criticalCountElement.textContent = "0";
    criticalFeedCountElement.textContent = "0";
    elevatedFeedCountElement.textContent = "0";
    observedFeedCountElement.textContent = "0";
    scoringModeElement.textContent = "offline";
    avgScoreElement.textContent = "0";
    topScoreElement.textContent = "0";
    criticalDistributionCountElement.textContent = "0";
    elevatedDistributionCountElement.textContent = "0";
    observedDistributionCountElement.textContent = "0";
    updateDistributionBar(criticalDistributionElement, 0, 1);
    updateDistributionBar(elevatedDistributionElement, 0, 1);
    updateDistributionBar(observedDistributionElement, 0, 1);
    floatingNoteLabelElement.textContent = "Offline";
    floatingNoteTextElement.textContent = `${appState.lastErrorMessage} Retrying automatically until the backend becomes reachable again.`;
    renderBottomStrip({ critical: 0, elevated: 0, observed: 0 });
    statusTextElement.textContent = appState.lastErrorMessage;
    lastRefreshElement.textContent = "Failed";
  } finally {
    isRefreshing = false;
    scheduleNextPoll();
  }
}

navButtonElements.forEach((button) => {
  button.addEventListener("click", () => {
    appState.activeView = button.dataset.view || "map";
    appState.overlayMode = VIEW_CONFIG[appState.activeView].overlayMode;
    updateViewCamera(getRenderableThreats());
    renderDashboard();
  });
});

shieldButtonElement.addEventListener("click", () => {
  appState.shieldMode = !appState.shieldMode;
  updateViewCamera(getRenderableThreats());
  renderDashboard();
});

resetViewButtonElement.addEventListener("click", () => {
  globe.controls().autoRotate = true;
  appState.overlayMode = "full";
  updateViewCamera(getRenderableThreats());
  renderDashboard();
});

overlayModeButtonElement.addEventListener("click", () => {
  appState.overlayMode =
    appState.overlayMode === "full"
      ? "points"
      : appState.overlayMode === "points"
        ? "signals"
        : "full";
  globe.controls().autoRotate = appState.overlayMode !== "signals";
  renderDashboard();
});

zoomInButtonElement.addEventListener("click", () => {
  const nextAltitude = Math.max(1.05, currentGlobeAltitude - 0.18);
  setGlobeView({ ...globe.pointOfView(), altitude: nextAltitude }, 450);
});

zoomOutButtonElement.addEventListener("click", () => {
  const nextAltitude = Math.min(2.8, currentGlobeAltitude + 0.18);
  setGlobeView({ ...globe.pointOfView(), altitude: nextAltitude }, 450);
});

updateControlsUi();
loadThreats();
updateRefreshClock();
window.setInterval(updateRefreshClock, 1000);
