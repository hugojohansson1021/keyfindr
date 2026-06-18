const state = {
  tools: [],
  selected: null,
  currentRunId: null,
  eventSource: null,
};

const els = {
  toolList: document.getElementById("tool-list"),
  runList: document.getElementById("run-list"),
  reportList: document.getElementById("report-list"),
  toolTitle: document.getElementById("tool-title"),
  toolDesc: document.getElementById("tool-description"),
  form: document.getElementById("tool-form"),
  runBtn: document.getElementById("run-btn"),
  stopBtn: document.getElementById("stop-btn"),
  runMeta: document.getElementById("run-meta"),
  terminal: document.getElementById("terminal"),
  clearBtn: document.getElementById("clear-btn"),
  copyBtn: document.getElementById("copy-btn"),
  graphPanel: document.getElementById("graph-panel"),
  graphSvg: document.getElementById("graph-svg"),
  graphView: document.getElementById("graph-view"),
  graphEdges: document.getElementById("graph-edges"),
  graphNodes: document.getElementById("graph-nodes"),
  graphLabels: document.getElementById("graph-labels"),
  graphCount: document.getElementById("graph-count"),
  graphZoomIn: document.getElementById("graph-zoom-in"),
  graphZoomOut: document.getElementById("graph-zoom-out"),
  graphZoomLevel: document.getElementById("graph-zoom-level"),
  graphReset: document.getElementById("graph-reset"),
  graphDetail: document.getElementById("graph-detail"),
  graphDetailHost: document.getElementById("graph-detail-host"),
  graphDetailStatus: document.getElementById("graph-detail-status"),
  graphDetailBody: document.getElementById("graph-detail-body"),
  graphDetailClose: document.getElementById("graph-detail-close"),
  endpointPanel: document.getElementById("endpoint-panel"),
  endpointBody: document.getElementById("endpoint-body"),
  endpointExposedCount: document.getElementById("endpoint-exposed-count"),
  endpointReachableCount: document.getElementById("endpoint-reachable-count"),
  endpointSafeCount: document.getElementById("endpoint-safe-count"),
  endpointTestedLabel: document.getElementById("endpoint-tested-label"),
  downloadBtn: document.getElementById("download-btn"),
  refreshReports: document.getElementById("refresh-reports"),
};

async function loadTools() {
  const res = await fetch("/api/tools");
  const data = await res.json();
  state.tools = data.tools || [];
  renderToolList();
  if (state.tools.length > 0) selectTool(state.tools[0].id);
}

function renderToolList() {
  els.toolList.innerHTML = "";
  for (const tool of state.tools) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.className = "tool-item";
    btn.textContent = tool.name;
    btn.addEventListener("click", () => selectTool(tool.id));
    if (state.selected && state.selected.id === tool.id) btn.classList.add("active");
    li.appendChild(btn);
    els.toolList.appendChild(li);
  }
}

function selectTool(toolId) {
  const tool = state.tools.find((t) => t.id === toolId);
  if (!tool) return;
  state.selected = tool;
  renderToolList();
  els.toolTitle.textContent = `> ${tool.name}`;
  els.toolDesc.textContent = tool.description || "";
  renderForm(tool);
  els.runBtn.disabled = false;
  Graph.setVisible(tool.id === "subdomain_spider");
  EndpointGrid.setVisible(tool.id === "wp_scanner");
  KeyTree.setVisible(tool.id === "keyfinder");
}

function renderForm(tool) {
  els.form.innerHTML = "";
  if (!tool.fields || tool.fields.length === 0) {
    const note = document.createElement("p");
    note.className = "notice";
    note.textContent = "This script takes no GUI arguments. Configure it inside the file before running.";
    els.form.appendChild(note);
    return;
  }
  for (const field of tool.fields) {
    const wrap = document.createElement("div");
    wrap.className = "field" + (field.type === "bool" ? " bool" : "");

    if (field.type === "bool") {
      const input = document.createElement("input");
      input.type = "checkbox";
      input.id = `f-${field.name}`;
      input.dataset.name = field.name;
      input.dataset.type = "bool";
      const label = document.createElement("label");
      label.htmlFor = input.id;
      label.textContent = field.label || field.name;
      wrap.appendChild(input);
      wrap.appendChild(label);
    } else {
      const label = document.createElement("label");
      label.htmlFor = `f-${field.name}`;
      label.textContent = (field.label || field.name) + (field.required ? " *" : "");
      const input = document.createElement("input");
      input.id = `f-${field.name}`;
      input.dataset.name = field.name;
      input.dataset.type = field.type;
      input.type = field.type === "int" ? "number" : "text";
      if (field.placeholder) input.placeholder = field.placeholder;
      if (field.default !== undefined && field.default !== null) input.value = field.default;
      if (field.min !== undefined) input.min = field.min;
      if (field.required) input.required = true;
      wrap.appendChild(label);
      wrap.appendChild(input);
    }
    els.form.appendChild(wrap);
  }
}

function collectValues() {
  const values = {};
  for (const input of els.form.querySelectorAll("input")) {
    const name = input.dataset.name;
    const type = input.dataset.type;
    if (type === "bool") {
      values[name] = input.checked;
    } else if (type === "int") {
      if (input.value !== "") values[name] = Number(input.value);
    } else {
      if (input.value !== "") values[name] = input.value;
    }
  }
  return values;
}

async function startRun() {
  if (!state.selected) return;
  els.runBtn.disabled = true;
  if (state.selected.id === "subdomain_spider") {
    Graph.reset();
  } else if (state.selected.id === "wp_scanner") {
    EndpointGrid.reset();
  } else if (state.selected.id === "keyfinder") {
    KeyTree.reset();
  }
  appendLine(`$ run ${state.selected.id}\n`);
  try {
    const res = await fetch("/api/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool_id: state.selected.id, values: collectValues() }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      appendLine(`[error] ${err.error || res.statusText}\n`);
      els.runBtn.disabled = false;
      return;
    }
    const run = await res.json();
    state.currentRunId = run.id;
    els.runMeta.textContent = `run ${run.id.slice(0, 8)} · ${run.argv.join(" ")}`;
    els.stopBtn.disabled = false;
    attachStream(run.id);
    refreshRuns();
  } catch (error) {
    appendLine(`[error] ${error.message}\n`);
    els.runBtn.disabled = false;
  }
}

function attachStream(runId) {
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }
  const es = new EventSource(`/api/runs/${runId}/stream`);
  state.eventSource = es;
  es.addEventListener("line", (e) => {
    if (e.data.startsWith("__EVENT__ ")) {
      try {
        const payload = JSON.parse(e.data.slice("__EVENT__ ".length));
        const toolId = state.selected && state.selected.id;
        if (toolId === "subdomain_spider") Graph.enqueue(payload);
        else if (toolId === "wp_scanner") EndpointGrid.enqueue(payload);
        else if (toolId === "keyfinder") KeyTree.enqueue(payload);
      } catch (err) {
        appendLine(`[event parse error] ${err.message}\n`);
      }
      return;
    }
    appendLine(e.data + (e.data.endsWith("\n") ? "" : "\n"));
  });
  es.addEventListener("end", (e) => {
    let info;
    try { info = JSON.parse(e.data); } catch { info = null; }
    if (info) {
      const tag = info.status === "exited" ? `exit ${info.exit_code}` : info.status;
      appendLine(`\n[${tag}]\n`);
    }
    es.close();
    state.eventSource = null;
    state.currentRunId = null;
    els.runBtn.disabled = false;
    els.stopBtn.disabled = true;
    refreshRuns();
    refreshReports();
  });
  es.onerror = () => {
    appendLine("[stream] connection lost\n");
    es.close();
    state.eventSource = null;
    els.runBtn.disabled = false;
    els.stopBtn.disabled = true;
  };
}

async function stopRun() {
  if (!state.currentRunId) return;
  els.stopBtn.disabled = true;
  await fetch(`/api/runs/${state.currentRunId}/stop`, { method: "POST" });
}

function appendLine(text) {
  const atBottom =
    els.terminal.scrollTop + els.terminal.clientHeight >= els.terminal.scrollHeight - 4;
  els.terminal.textContent += text;
  if (atBottom) els.terminal.scrollTop = els.terminal.scrollHeight;
}

async function refreshRuns() {
  const res = await fetch("/api/runs");
  const data = await res.json();
  els.runList.innerHTML = "";
  if (!data.runs || data.runs.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "no runs yet";
    els.runList.appendChild(li);
    return;
  }
  for (const run of data.runs.slice(0, 10)) {
    const li = document.createElement("li");
    li.className = run.status;
    const tag = run.status === "exited" ? `exit ${run.exit_code ?? "?"}` : run.status;
    li.innerHTML = `<span class="run-status">${tag}</span>${run.tool_id} · ${new Date(run.started_at * 1000).toLocaleTimeString()}`;
    els.runList.appendChild(li);
  }
}

async function refreshReports() {
  const res = await fetch("/api/reports");
  const data = await res.json();
  els.reportList.innerHTML = "";
  if (!data.reports || data.reports.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "no reports yet";
    els.reportList.appendChild(li);
    return;
  }

  const groups = new Map();
  for (const file of data.reports) {
    const rel = file.path.replace(/^reports\//, "");
    const slash = rel.lastIndexOf("/");
    const folder = slash === -1 ? "(root)" : rel.slice(0, slash);
    const name = slash === -1 ? rel : rel.slice(slash + 1);
    if (!groups.has(folder)) groups.set(folder, []);
    groups.get(folder).push({ ...file, name });
  }

  const folders = [...groups.keys()].sort((a, b) => {
    const aCache = a.includes("cache");
    const bCache = b.includes("cache");
    if (aCache !== bCache) return aCache ? 1 : -1;
    return a.localeCompare(b);
  });

  for (const folder of folders) {
    const files = groups.get(folder);
    const li = document.createElement("li");
    li.className = "report-group";

    const details = document.createElement("details");

    const summary = document.createElement("summary");
    summary.innerHTML = `<span class="folder-name">${folder}/</span><span class="folder-count">${files.length}</span>`;
    details.appendChild(summary);

    const inner = document.createElement("ul");
    inner.className = "report-files";
    for (const file of files.slice(0, 40)) {
      const fli = document.createElement("li");
      const link = document.createElement("a");
      link.href = "/" + file.path;
      link.textContent = file.name;
      link.title = `${(file.size / 1024).toFixed(1)} KB`;
      link.target = "_blank";
      fli.appendChild(link);
      inner.appendChild(fli);
    }
    details.appendChild(inner);
    li.appendChild(details);
    els.reportList.appendChild(li);
  }
}

function clearTerminal() {
  els.terminal.textContent = "";
}

async function copyTerminal() {
  try {
    await navigator.clipboard.writeText(els.terminal.textContent);
    flash(els.copyBtn, "copied");
  } catch {
    flash(els.copyBtn, "failed");
  }
}

function downloadTerminal() {
  const blob = new Blob([els.terminal.textContent], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  a.href = url;
  a.download = `keyfindr-${ts}.log`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function flash(btn, text) {
  const original = btn.textContent;
  btn.textContent = text;
  setTimeout(() => (btn.textContent = original), 1200);
}

const Graph = (() => {
  const SVG_NS = "http://www.w3.org/2000/svg";
  const STEP_MS = 260;
  const COL_GAP = 165; // horizontal distance between tree depths (left -> right)
  const ROW_GAP = 44; // vertical distance between stacked leaves
  const DEFAULT_ZOOM = 1.0;
  const DEFAULT_PAN = { x: -360, y: 0 }; // pin root near the left edge
  const ZOOM_STEP = 1.25;
  const MIN_ZOOM = 0.4;
  const MAX_ZOOM = 6;

  const state = {
    visible: false,
    root: null,
    rootNode: null,
    nodes: new Map(),
    hosts: new Map(),
    queue: [],
    timer: null,
    zoom: DEFAULT_ZOOM,
    pan: { ...DEFAULT_PAN },
    drag: null,
    selected: null,
  };

  function setVisible(visible) {
    state.visible = visible;
    els.graphPanel.hidden = !visible;
  }

  function reset() {
    state.root = null;
    state.rootNode = null;
    state.nodes.clear();
    state.hosts.clear();
    state.queue.length = 0;
    state.selected = null;
    if (state.timer) {
      clearInterval(state.timer);
      state.timer = null;
    }
    els.graphEdges.innerHTML = "";
    els.graphNodes.innerHTML = "";
    els.graphLabels.innerHTML = "";
    hideDetail();
    resetView();
    updateCount();
  }

  function applyTransform(smooth) {
    els.graphView.style.transition = smooth
      ? "transform 280ms cubic-bezier(0.2, 0.7, 0.2, 1)"
      : "none";
    els.graphView.setAttribute(
      "transform",
      `translate(${state.pan.x} ${state.pan.y}) scale(${state.zoom})`
    );
    els.graphZoomLevel.textContent = `${Math.round(state.zoom * 100)}%`;
  }

  function resetView() {
    state.zoom = DEFAULT_ZOOM;
    state.pan = { ...DEFAULT_PAN };
    applyTransform(true);
  }

  function zoomBy(factor) {
    const next = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, state.zoom * factor));
    if (next === state.zoom) return;
    state.zoom = next;
    applyTransform(true);
  }

  function svgPointPerPixel() {
    const rect = els.graphSvg.getBoundingClientRect();
    if (!rect.width) return 1;
    const viewBox = els.graphSvg.viewBox.baseVal;
    return viewBox.width / rect.width;
  }

  function onPointerDown(event) {
    if (event.button !== 0 && event.pointerType !== "touch") return;
    const hitNode = event.target.closest("[data-host]");
    state.drag = {
      startX: event.clientX,
      startY: event.clientY,
      panX: state.pan.x,
      panY: state.pan.y,
      scale: svgPointPerPixel(),
      pointerId: event.pointerId,
      moved: 0,
      hostHit: hitNode ? hitNode.getAttribute("data-host") : null,
    };
    els.graphSvg.setPointerCapture(event.pointerId);
    els.graphSvg.classList.add("dragging");
  }

  function onPointerMove(event) {
    if (!state.drag) return;
    const dxRaw = event.clientX - state.drag.startX;
    const dyRaw = event.clientY - state.drag.startY;
    state.drag.moved = Math.hypot(dxRaw, dyRaw);
    const scale = state.drag.scale;
    state.pan.x = state.drag.panX + dxRaw * scale;
    state.pan.y = state.drag.panY + dyRaw * scale;
    applyTransform(false);
  }

  function onPointerUp() {
    if (!state.drag) return;
    const { pointerId, moved, hostHit } = state.drag;
    try { els.graphSvg.releasePointerCapture(pointerId); } catch {}
    state.drag = null;
    els.graphSvg.classList.remove("dragging");
    if (hostHit && moved < 4) {
      showDetail(hostHit);
    } else if (!hostHit && moved < 4) {
      hideDetail();
    }
  }

  function showDetail(host) {
    state.selected = host;
    const isRoot = host === state.root;
    const data = isRoot ? { host, isRoot: true } : state.hosts.get(host);
    if (!data) return;

    const kind = isRoot ? "root" : classifyKind(data);
    els.graphDetailStatus.className = `graph-detail-status status-${kind}`;
    els.graphDetailStatus.textContent = isRoot
      ? "ROOT"
      : (data.status != null ? data.status : (data.reachable ? "?" : "—"));
    els.graphDetailHost.textContent = host;

    const rows = [];
    if (isRoot) {
      rows.push(["role", "scan target"]);
      rows.push(["nodes", String(state.nodes.size)]);
    } else {
      rows.push(["status", data.status != null ? data.status : "no response"]);
      rows.push(["reachable", data.reachable ? "yes" : "no"]);
      if (data.title)     rows.push(["title", data.title]);
      if (data.server)    rows.push(["server", data.server]);
      if (data.final_url) rows.push(["final url", data.final_url, { link: true }]);
      if (data.addresses && data.addresses.length) {
        rows.push(["addresses", data.addresses.join("\n")]);
      }
      if (data.skipped) rows.push(["skipped", data.skipped]);
      if (data.error)   rows.push(["error", data.error]);
    }

    els.graphDetailBody.innerHTML = "";
    for (const [label, value, opts] of rows) {
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      if (opts && opts.link) {
        const a = document.createElement("a");
        a.href = value;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.textContent = value;
        dd.appendChild(a);
      } else {
        dd.textContent = value;
      }
      els.graphDetailBody.appendChild(dt);
      els.graphDetailBody.appendChild(dd);
    }

    els.graphDetail.hidden = false;
    highlightSelected(host);
  }

  function hideDetail() {
    state.selected = null;
    els.graphDetail.hidden = true;
    highlightSelected(null);
  }

  function highlightSelected(host) {
    for (const el of els.graphNodes.querySelectorAll("[data-host]")) {
      el.classList.toggle("selected", el.getAttribute("data-host") === host);
    }
  }

  els.graphZoomIn.addEventListener("click", () => zoomBy(ZOOM_STEP));
  els.graphZoomOut.addEventListener("click", () => zoomBy(1 / ZOOM_STEP));
  els.graphReset.addEventListener("click", () => resetView());
  els.graphDetailClose.addEventListener("click", hideDetail);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !els.graphDetail.hidden) hideDetail();
  });
  els.graphSvg.addEventListener("pointerdown", onPointerDown);
  els.graphSvg.addEventListener("pointermove", onPointerMove);
  els.graphSvg.addEventListener("pointerup", onPointerUp);
  els.graphSvg.addEventListener("pointercancel", onPointerUp);
  els.graphSvg.addEventListener("contextmenu", (e) => e.preventDefault());
  applyTransform(false);

  function enqueue(payload) {
    if (!payload || !payload.type) return;
    state.queue.push(payload);
    ensurePump();
  }

  function ensurePump() {
    if (state.timer) return;
    state.timer = setInterval(() => {
      const next = state.queue.shift();
      if (!next) {
        clearInterval(state.timer);
        state.timer = null;
        return;
      }
      handleEvent(next);
    }, STEP_MS);
  }

  function handleEvent(ev) {
    if (ev.type === "root") {
      setRoot(ev.host);
    } else if (ev.type === "host") {
      addHost(ev);
    }
  }

  function setRoot(host) {
    if (!host) return;
    state.root = host;
    const node = makeTreeNode(host, null);
    node.kind = "root";
    node.synthetic = false;
    state.rootNode = node;
    state.nodes.set(host, node);

    // root pulse ring (decorative, separate from data nodes)
    const pulse = svgEl("circle", { cx: 0, cy: 0, r: 14, class: "node-root-pulse" });
    els.graphNodes.appendChild(pulse);

    ensureDom(node);
    layoutTree();
    syncDom(false);
  }

  function makeTreeNode(host, parent) {
    return {
      host,
      label: parent ? labelFor(host, parent.host) : host,
      parent,
      children: [],
      kind: "synthetic",
      synthetic: true,
      data: null,
      depth: parent ? parent.depth + 1 : 0,
      pos: { x: 0, y: 0 },
      angle: 0,
      els: {},
    };
  }

  function labelFor(host, parentHost) {
    if (!host.endsWith("." + parentHost)) return host;
    return host.slice(0, host.length - parentHost.length - 1);
  }

  function addHost(ev) {
    if (!state.root) setRoot(deriveRootFrom(ev.host));

    // Walk from root toward the leaf, creating intermediate nodes as needed.
    // For "stage.wp-mail.example.com" with root "example.com",
    // the prefix is "stage.wp-mail" and the path from root is
    // [wp-mail.example.com, stage.wp-mail.example.com].
    const root = state.root;
    if (!ev.host.endsWith(root)) return;
    const prefix = ev.host === root ? "" : ev.host.slice(0, -root.length - 1);
    if (!prefix) {
      // event for the root itself; merge data and move on
      const rootNode = state.rootNode;
      rootNode.data = ev;
      state.hosts.set(ev.host, ev);
      return;
    }
    const parts = prefix.split(".").reverse(); // outer-to-inner

    let parentNode = state.rootNode;
    let parentHost = root;
    let lastCreated = null;
    for (let i = 0; i < parts.length; i++) {
      const childHost = parts[i] + "." + parentHost;
      let childNode = state.nodes.get(childHost);
      const isLeaf = i === parts.length - 1;
      if (!childNode) {
        childNode = makeTreeNode(childHost, parentNode);
        parentNode.children.push(childNode);
        state.nodes.set(childHost, childNode);
        lastCreated = childNode;
      }
      if (isLeaf) {
        childNode.synthetic = false;
        childNode.data = ev;
        childNode.kind = classifyKind(ev);
      }
      parentNode = childNode;
      parentHost = childHost;
    }
    state.hosts.set(ev.host, ev);

    layoutTree();
    // Ensure DOM exists for any new nodes, then animate everything to its new spot.
    for (const node of state.nodes.values()) {
      if (!node.els.circle && node !== state.rootNode) {
        ensureDom(node);
        // start new nodes near their parent so the reflow looks like growth
        const p = node.parent ? node.parent.pos : { x: 0, y: 0 };
        node.els.circle.setAttribute("cx", p.x);
        node.els.circle.setAttribute("cy", p.y);
      }
    }
    syncDom(true);

    // Cinematic per-event animation, only for the newly inserted leaf
    if (lastCreated && lastCreated === parentNode) {
      animateArrival(lastCreated);
    } else if (parentNode && parentNode !== state.rootNode) {
      // host event upgraded an existing synthetic node
      pulseExisting(parentNode);
    }

    updateCount();
  }

  function classifyKind(ev) {
    if (ev.status === 200) return "ok";
    if (ev.status != null && ev.reachable) return "bad";
    return "dead";
  }

  // ---- Layout ----

  // Relevance rank: lower = pulled toward the vertical center. A live 200 is
  // the most relevant; an internal branch inherits the best rank below it so
  // any branch leading to a 200 also drifts toward the middle.
  function nodeRank(node) {
    if (node.children.length === 0) {
      if (node.synthetic) return 3;
      if (node.kind === "ok") return 0;
      if (node.kind === "bad") return 1;
      return 3; // dead / unreachable
    }
    let best = 4;
    for (const child of node.children) best = Math.min(best, nodeRank(child));
    return best;
  }

  // Reorder siblings so the most relevant sits on the center line and the
  // rest fan outward alternately (worst toward the top/bottom edges).
  function arrangeCenterOut(children) {
    const sorted = [...children].sort((a, b) => {
      const r = nodeRank(a) - nodeRank(b);
      return r !== 0 ? r : a.host.localeCompare(b.host);
    });
    const top = [];
    const bottom = [];
    sorted.forEach((node, i) => {
      if (i === 0) return; // best stays at the center
      if (i % 2 === 1) bottom.push(node);
      else top.unshift(node);
    });
    return [...top, sorted[0], ...bottom];
  }

  // Horizontal "tidy tree": root on the left, every depth is a column to the
  // right, leaves stacked top-to-bottom. Internal nodes center on their kids,
  // and the most relevant (200) branches are pulled toward the center line.
  function layoutTree() {
    if (!state.rootNode) return;

    let leafCursor = 0;
    (function assign(node) {
      if (node.children.length > 1) {
        node.children = arrangeCenterOut(node.children);
      }
      node.pos.x = node.depth * COL_GAP;
      if (node.children.length === 0) {
        node.pos.y = leafCursor * ROW_GAP;
        leafCursor++;
      } else {
        node.children.forEach(assign);
        const kids = node.children;
        node.pos.y = (kids[0].pos.y + kids[kids.length - 1].pos.y) / 2;
      }
    })(state.rootNode);

    // center the whole tree vertically around y = 0
    let min = Infinity;
    let max = -Infinity;
    for (const node of state.nodes.values()) {
      if (node.pos.y < min) min = node.pos.y;
      if (node.pos.y > max) max = node.pos.y;
    }
    const mid = (min + max) / 2;
    for (const node of state.nodes.values()) node.pos.y -= mid;
  }

  // ---- DOM creation + sync ----

  function ensureDom(node) {
    if (node.els.circle) return;
    if (node === state.rootNode) {
      const circle = svgEl("circle", {
        cx: 0, cy: 0, r: 14,
        class: "node-root",
        "data-host": node.host,
      });
      els.graphNodes.appendChild(circle);
      node.els.circle = circle;

      const label = svgEl("text", {
        x: 0, y: 34,
        class: "label-root",
        "text-anchor": "middle",
      });
      label.textContent = node.host;
      els.graphLabels.appendChild(label);
      node.els.label = label;
      return;
    }

    // edge first so it renders behind the node
    const edge = svgEl("path", {
      d: branchPath(node.parent.pos, node.parent.pos),
      class: "edge edge-probing",
      "stroke-dasharray": "3 5",
    });
    els.graphEdges.appendChild(edge);
    node.els.edge = edge;

    const circle = svgEl("circle", {
      cx: node.parent.pos.x,
      cy: node.parent.pos.y,
      r: 0,
      class: `node node-${node.synthetic ? "synthetic" : node.kind}`,
      "data-host": node.host,
    });
    const title = svgEl("title");
    title.textContent = node.host;
    circle.appendChild(title);
    els.graphNodes.appendChild(circle);
    node.els.circle = circle;

    const label = svgEl("text", {
      x: node.pos.x, y: node.pos.y,
      class: `label label-${node.synthetic ? "synthetic" : node.kind}`,
      "text-anchor": "middle",
    });
    label.textContent = node.label;
    label.style.opacity = "0";
    els.graphLabels.appendChild(label);
    node.els.label = label;

    // For synthetic intermediates, grow a small dot — the leaf gets
    // the full cinematic treatment via animateArrival().
    if (node.synthetic) {
      setTimeout(() => {
        if (node.synthetic && node.els.circle) {
          node.els.circle.setAttribute("r", 3);
          node.els.label.style.opacity = "0.6";
        }
      }, 240);
    }
  }

  function syncDom(animate) {
    if (!animate) {
      els.graphView.style.setProperty("--reflow-ms", "0ms");
    } else {
      els.graphView.style.setProperty("--reflow-ms", "700ms");
    }
    for (const node of state.nodes.values()) {
      if (!node.els.circle) continue;
      node.els.circle.setAttribute("cx", node.pos.x);
      node.els.circle.setAttribute("cy", node.pos.y);
      if (node.els.edge && node.parent) {
        node.els.edge.setAttribute("d", branchPath(node.parent.pos, node.pos));
      }
      if (node.els.label) {
        const offset = labelOffset(node);
        node.els.label.setAttribute("x", node.pos.x + offset.x);
        node.els.label.setAttribute("y", node.pos.y + offset.y);
        node.els.label.setAttribute("text-anchor", offset.anchor);
      }
      const kindClass = node === state.rootNode
        ? "node-root"
        : `node node-${node.synthetic ? "synthetic" : node.kind}`;
      if (node !== state.rootNode) {
        node.els.circle.setAttribute("class",
          kindClass + (node === state.rootNode ? "" : "") +
          (state.selected === node.host ? " selected" : "")
        );
        if (node.els.edge) {
          node.els.edge.setAttribute("class",
            `edge edge-${node.synthetic ? "probing" : node.kind}`
          );
        }
        if (node.els.label) {
          node.els.label.setAttribute("class",
            `label label-${node.synthetic ? "synthetic" : node.kind}`
          );
        }
      }
    }
  }

  function labelOffset(node) {
    // root: label sits below the root marker
    if (node === state.rootNode) return { x: 0, y: 30, anchor: "middle" };
    // leaf: label to the right of the node, in line with it
    if (node.children.length === 0) {
      return { x: 12, y: 4, anchor: "start" };
    }
    // internal node: label above so it doesn't collide with outgoing branches
    return { x: 0, y: -12, anchor: "middle" };
  }

  function branchPath(from, to) {
    // Horizontal S-curve: leaves the parent flowing right, eases into the
    // child. Control points share each end's y, so branches "spray" rightward.
    const midX = (from.x + to.x) / 2;
    return (
      `M${from.x.toFixed(2)},${from.y.toFixed(2)} ` +
      `C${midX.toFixed(2)},${from.y.toFixed(2)} ` +
      `${midX.toFixed(2)},${to.y.toFixed(2)} ` +
      `${to.x.toFixed(2)},${to.y.toFixed(2)}`
    );
  }

  // ---- Per-event cinematic animation ----

  function animateArrival(node) {
    const parent = node.parent;
    if (!parent) return;
    const { circle, edge } = node.els;

    // probe head travels from parent to node
    const probe = svgEl("circle", {
      cx: parent.pos.x, cy: parent.pos.y, r: 2.5,
      class: "probe-head",
    });
    els.graphNodes.appendChild(probe);

    const TRAVEL_MS = 520;
    const t0 = performance.now();
    function travel(now) {
      const t = Math.min(1, (now - t0) / TRAVEL_MS);
      const e = 1 - Math.pow(1 - t, 3);
      const x = parent.pos.x + (node.pos.x - parent.pos.x) * e;
      const y = parent.pos.y + (node.pos.y - parent.pos.y) * e;
      if (probe.isConnected) {
        probe.setAttribute("cx", x.toFixed(2));
        probe.setAttribute("cy", y.toFixed(2));
      }
      if (t < 1 && probe.isConnected) requestAnimationFrame(travel);
      else {
        probe.remove();
        onArrival();
      }
    }
    requestAnimationFrame(travel);

    function onArrival() {
      // upgrade edge: remove probing dashed style
      if (edge) {
        edge.removeAttribute("stroke-dasharray");
      }
      // impact ring
      const ring = svgEl("circle", {
        cx: node.pos.x, cy: node.pos.y, r: 4,
        class: `impact-ring impact-${node.kind}`,
      });
      els.graphNodes.appendChild(ring);
      setTimeout(() => ring.remove(), 800);
      // status flash
      const ev = node.data || {};
      const flashText = ev.status != null ? String(ev.status)
        : ev.reachable ? "?" : "×";
      const flash = svgEl("text", {
        x: node.pos.x, y: node.pos.y - 14,
        class: `status-flash status-flash-${node.kind}`,
        "text-anchor": "middle",
      });
      flash.textContent = flashText;
      els.graphLabels.appendChild(flash);
      setTimeout(() => flash.classList.add("status-flash-out"), 480);
      setTimeout(() => flash.remove(), 1400);
      // pop node in
      if (circle) {
        requestAnimationFrame(() => circle.setAttribute("r", 6));
      }
      // fade in label
      if (node.els.label) {
        setTimeout(() => (node.els.label.style.opacity = "1"), 220);
      }
    }
  }

  function pulseExisting(node) {
    const ring = svgEl("circle", {
      cx: node.pos.x, cy: node.pos.y, r: 4,
      class: `impact-ring impact-${node.kind}`,
    });
    els.graphNodes.appendChild(ring);
    setTimeout(() => ring.remove(), 800);
  }

  function svgEl(tag, attrs = {}) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    return node;
  }

  function deriveRootFrom(host) {
    if (!host) return "target";
    const parts = host.split(".");
    return parts.slice(-2).join(".");
  }

  function updateCount() {
    let n = 0;
    for (const node of state.nodes.values()) {
      if (node === state.rootNode) continue;
      if (node.synthetic) continue;
      n++;
    }
    els.graphCount.textContent = `${n} node${n === 1 ? "" : "s"}`;
  }

  return { setVisible, reset, enqueue };
})();

// Live "phase tree" for keyFinder.py: root -> scan phase -> work item
// (crawled page / JS file / endpoint) -> finding (a secret, coloured by
// severity). Mirrors the subdomain graph's horizontal tidy-tree engine but
// drives nodes off explicit id/parent ids from the event stream.
const KeyTree = (() => {
  const SVG_NS = "http://www.w3.org/2000/svg";
  const STEP_MS = 170;
  const COL_GAP = 150;
  const ROW_GAP = 30;
  const DEFAULT_ZOOM = 1.0;
  const DEFAULT_PAN = { x: -390, y: 0 };
  const ZOOM_STEP = 1.25;
  const MIN_ZOOM = 0.3;
  const MAX_ZOOM = 6;

  // Live code-rain terminal config.
  const TERM_W = 208;
  const TERM_H = 116;
  const TERM_MAX_LINES = 7;
  const TERM_TICK_MS = 130;
  const MAX_OPEN_TERMS = 2;

  // A pool of real-world secret signatures the rain "tests" against, so the
  // stream reads like an actual scanner walking its pattern set.
  const PATTERN_POOL = [
    "AIza[0-9A-Za-z\\-_]{35}",
    "sk_live_[0-9a-zA-Z]{24,}",
    "ghp_[A-Za-z0-9]{36}",
    "AKIA[0-9A-Z]{16}",
    "xox[baprs]-[0-9A-Za-z-]+",
    "eyJ[A-Za-z0-9_-]{10,}\\.",
    "glpat-[0-9A-Za-z\\-_]{20}",
    "SG\\.[\\w-]{22}\\.[\\w-]{43}",
    "rk_live_[0-9a-zA-Z]{24}",
    "-----BEGIN (RSA|EC) PRIVATE KEY-----",
    "ya29\\.[0-9A-Za-z\\-_]+",
    "hooks\\.slack\\.com/services/T\\w+",
  ];

  const $ = (id) => document.getElementById(id);
  const els = {
    panel: $("keytree-panel"),
    svg: $("kt-svg"),
    view: $("kt-view"),
    edges: $("kt-edges"),
    nodes: $("kt-nodes"),
    labels: $("kt-labels"),
    count: $("kt-count"),
    zoomIn: $("kt-zoom-in"),
    zoomOut: $("kt-zoom-out"),
    zoomLevel: $("kt-zoom-level"),
    reset: $("kt-reset"),
  };

  const state = {
    visible: false,
    root: null,
    nodes: new Map(),
    queue: [],
    timer: null,
    secrets: 0,
    zoom: DEFAULT_ZOOM,
    pan: { ...DEFAULT_PAN },
    drag: null,
    terminals: new Map(),
    detail: null, // pinned, click-opened detail terminal
    homepageIds: new Set(), // item ids whose URL is the site root ("/")
    catchUp: false, // draining a backlog fast — skip per-node animation
  };

  function setVisible(visible) {
    state.visible = visible;
    els.panel.hidden = !visible;
  }

  function reset() {
    state.root = null;
    state.nodes.clear();
    state.queue.length = 0;
    state.secrets = 0;
    if (state.timer) {
      clearInterval(state.timer);
      state.timer = null;
    }
    for (const term of state.terminals.values()) destroyTerminal(term);
    state.terminals.clear();
    state.homepageIds.clear();
    closeDetail();
    els.edges.innerHTML = "";
    els.nodes.innerHTML = "";
    els.labels.innerHTML = "";
    resetView();
    updateCount();
  }

  // ---- pan / zoom ----
  function applyTransform(smooth) {
    els.view.style.transition = smooth
      ? "transform 280ms cubic-bezier(0.2, 0.7, 0.2, 1)"
      : "none";
    els.view.setAttribute(
      "transform",
      `translate(${state.pan.x} ${state.pan.y}) scale(${state.zoom})`
    );
    els.zoomLevel.textContent = `${Math.round(state.zoom * 100)}%`;
  }

  function resetView() {
    state.zoom = DEFAULT_ZOOM;
    state.pan = { ...DEFAULT_PAN };
    applyTransform(true);
  }

  function zoomBy(factor) {
    const next = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, state.zoom * factor));
    if (next === state.zoom) return;
    state.zoom = next;
    applyTransform(true);
  }

  function clientToView(event) {
    const rect = els.svg.getBoundingClientRect();
    const vb = els.svg.viewBox.baseVal;
    return {
      x: vb.x + (event.clientX - rect.left) * (vb.width / rect.width),
      y: vb.y + (event.clientY - rect.top) * (vb.height / rect.height),
    };
  }

  function onPointerDown(event) {
    const p = clientToView(event);
    const hit = event.target.closest("[data-id]");
    state.drag = {
      x: p.x, y: p.y, panX: state.pan.x, panY: state.pan.y,
      sx: event.clientX, sy: event.clientY,
      hitId: hit ? hit.getAttribute("data-id") : null,
      moved: false,
    };
    els.svg.setPointerCapture(event.pointerId);
    els.svg.classList.add("dragging");
  }

  function onPointerMove(event) {
    if (!state.drag) return;
    if (Math.hypot(event.clientX - state.drag.sx, event.clientY - state.drag.sy) > 4) {
      state.drag.moved = true;
    }
    const p = clientToView(event);
    state.pan.x = state.drag.panX + (p.x - state.drag.x);
    state.pan.y = state.drag.panY + (p.y - state.drag.y);
    applyTransform(false);
  }

  function onPointerUp(event) {
    const drag = state.drag;
    state.drag = null;
    try { els.svg.releasePointerCapture(event.pointerId); } catch {}
    els.svg.classList.remove("dragging");
    // a click (no real drag) on a node toggles its detail terminal
    if (drag && !drag.moved && drag.hitId) {
      const node = state.nodes.get(drag.hitId);
      if (node) toggleDetail(node);
    }
  }

  els.zoomIn.addEventListener("click", () => zoomBy(ZOOM_STEP));
  els.zoomOut.addEventListener("click", () => zoomBy(1 / ZOOM_STEP));
  els.reset.addEventListener("click", resetView);
  els.svg.addEventListener("pointerdown", onPointerDown);
  els.svg.addEventListener("pointermove", onPointerMove);
  els.svg.addEventListener("pointerup", onPointerUp);
  els.svg.addEventListener("pointercancel", onPointerUp);
  els.svg.addEventListener("contextmenu", (e) => e.preventDefault());
  applyTransform(false);

  // ---- event intake (paced so the tree visibly grows) ----
  function enqueue(payload) {
    if (!payload || !payload.type) return;
    state.queue.push(payload);
    ensurePump();
  }

  function ensurePump() {
    if (state.timer) return;
    state.timer = setInterval(() => {
      if (!state.queue.length) {
        clearInterval(state.timer);
        state.timer = null;
        state.catchUp = false;
        return;
      }
      // The scanner emits faster than the cinematic 1-per-tick pace, so a
      // backlog builds and the tree lags the terminal. When behind, drain in
      // proportionally larger batches (without per-node animation) to catch up.
      const backlog = state.queue.length;
      state.catchUp = backlog > 40;
      const batch = state.catchUp ? Math.ceil(backlog / 25) : 1;
      for (let i = 0; i < batch && state.queue.length; i++) {
        handleEvent(state.queue.shift());
      }
    }, STEP_MS);
  }

  function handleEvent(ev) {
    switch (ev.type) {
      case "root": setRoot(ev.label); break;
      case "phase": addNode(ev.id, ev.parent, "phase", ev); break;
      case "item": addItem(ev.id, ev.parent, ev); break;
      case "item_done": markItemDone(ev.id, ev.found); break;
      case "finding": addFinding(ev); break;
      default: break;
    }
  }

  // ---- model ----
  function makeNode(id, parent, kind, label) {
    return {
      id, parent, kind,
      baseLabel: label || id,
      label: label || id,
      url: urlFromId(id), // real page/source URL, recovered from the event id
      children: [],
      depth: parent ? parent.depth + 1 : 0,
      findings: [], // secrets aggregated here (for colour/count/detail)
      worst: null, // worst severity among findings
      found: 0, // count of secrets on this node
      severity: null, // for a "secret" leaf: its own severity
      source: "", // for a "secret" leaf: where it was seen (JS/HTML/...)
      active: false,
      pos: { x: 0, y: 0 },
      els: {},
    };
  }

  function urlFromId(id) {
    const m = /^(?:crawl:|js:|special:)(.+)$/.exec(id || "");
    return m ? m[1] : "";
  }

  const SEV_RANK = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  function worseSeverity(a, b) {
    if (!a) return b;
    if (!b) return a;
    return SEV_RANK[b] < SEV_RANK[a] ? b : a;
  }

  function setRoot(label) {
    if (state.root) return;
    const node = makeNode("root", null, "root", label || "target");
    state.root = node;
    state.nodes.set("root", node);
    ensureDom(node);
    layoutTree();
    syncDom(false);
  }

  function addNode(id, parentId, kind, ev) {
    if (!id || state.nodes.has(id)) return;
    if (!state.root) setRoot("target");
    const parent = state.nodes.get(parentId) || state.root;
    const node = makeNode(id, parent, kind, ev.label);
    parent.children.push(node);
    state.nodes.set(id, node);
    grow();
  }

  // Split a URL into decoded path segments (no host, no trailing slash).
  function urlSegments(url) {
    try {
      const u = new URL(url);
      return u.pathname
        .split("/")
        .filter(Boolean)
        .map((s) => {
          try { return decodeURIComponent(s); } catch { return s; }
        });
    } catch {
      return [];
    }
  }

  // The site homepage ("/") IS the base URL, which is already the root node —
  // so its findings belong on the root, not on a stray "/" leaf. Resolve any
  // homepage item id back to the root.
  function resolveNode(nodeId) {
    if (state.homepageIds.has(nodeId)) return state.root;
    return state.nodes.get(nodeId);
  }

  // A crawled page is placed by its URL path, so the tree shows real depth:
  // phase -> /article -> <slug> -> secrets, instead of every URL hanging flat
  // off the base. Intermediate path segments become reusable "path" nodes.
  function addItem(id, phaseId, ev) {
    if (!id || state.nodes.has(id) || state.homepageIds.has(id)) return;
    if (!state.root) setRoot("target");
    const phase = state.nodes.get(phaseId) || state.root;
    const url = urlFromId(id) || ev.label || "";
    const segs = urlSegments(url);

    // homepage: fold into the root node instead of spawning a "/" node
    if (segs.length === 0) {
      state.homepageIds.add(id);
      state.root.active = true;
      refreshNode(state.root);
      if (!state.catchUp) openTerminal(state.root);
      return;
    }

    // walk/create the path chain for all but the final segment
    let parent = phase;
    let prefix = phaseId;
    for (let i = 0; i < segs.length - 1; i++) {
      prefix += "/" + segs[i];
      const segId = "seg:" + prefix;
      let seg = state.nodes.get(segId);
      if (!seg) {
        seg = makeNode(segId, parent, "path", segs[i]);
        parent.children.push(seg);
        state.nodes.set(segId, seg);
      }
      parent = seg;
    }

    // the page itself keeps the original event id so findings resolve to it
    const pageLabel = segs.length ? segs[segs.length - 1] : "/";
    const node = makeNode(id, parent, "item", pageLabel);
    node.active = true;
    parent.children.push(node);
    state.nodes.set(id, node);
    grow();
    if (!state.catchUp) openTerminal(node);
  }

  // A secret fans out as its own leaf under the page it was found on
  // (URL -> arrows -> secrets), and also aggregates onto the page so the page
  // node carries colour/count and the detail terminal can list everything.
  function addFinding(ev) {
    if (!state.root) setRoot("target");
    const parent = resolveNode(ev.parent);
    if (!parent) return;
    const sev = (ev.severity || "LOW").toUpperCase();

    // the scanner reports every occurrence (HTML, rendered, input, base64…) —
    // collapse repeats of the same secret on the same page into one node
    const key = `${ev.label}|${ev.source || ""}`;
    parent._seen = parent._seen || new Map();
    const term = state.terminals.get(parent.id);
    if (parent._seen.has(key)) {
      parent._seen.set(key, parent._seen.get(key) + 1);
      return; // duplicate occurrence — already shown
    }
    parent._seen.set(key, 1);

    parent.findings.push({ label: ev.label, severity: sev, source: ev.source || "" });
    parent.found = parent.findings.length;
    parent.worst = worseSeverity(parent.worst, sev);
    state.secrets += 1;
    updateCount();

    // fan-out leaf node for this unique secret
    const id = `${parent.id}#${key}`;
    if (!state.nodes.has(id)) {
      const node = makeNode(id, parent, "secret", ev.label);
      node.severity = sev;
      node.source = ev.source || "";
      parent.children.push(node);
      state.nodes.set(id, node);
      grow();
    }
    refreshNode(parent);
    // bubble the running count/colour up through /article, the phase, etc.
    for (let a = parent.parent; a; a = a.parent) refreshNode(a);

    // surface the hit in the node's live terminal, if open
    if (term) termLine(term, `MATCH ${ev.label} · ${sev}`, "match");
    // keep a pinned detail terminal in sync if the user has it open
    if (state.detail && state.detail.node === parent) renderDetail();
  }

  function markItemDone(id, found) {
    const node = resolveNode(id);
    if (!node) return;
    node.active = false;
    if (!node.found && found) node.found = found; // fallback if a finding event was missed
    refreshNode(node);
    // a page that finished clean is no longer "active" — relayout so it
    // collapses out of the results view and the tree recentres
    layoutTree();
    syncDom(!state.catchUp);
    closeTerminal(node.id, node.found);
  }

  // Update a node's colour + label to reflect the secrets aggregated on it.
  function refreshNode(node) {
    if (node.els.circle) {
      node.els.circle.setAttribute("class", nodeClass(node));
      node.els.circle.setAttribute("r", radiusFor(node));
      const title = node.els.circle.querySelector("title");
      if (title) title.textContent = titleFor(node);
    }
    if (node.els.label) {
      node.els.label.textContent = displayLabel(node);
      node.els.label.setAttribute("class", labelClass(node));
    }
    if (node.els.edge) node.els.edge.setAttribute("class", edgeClass(node));
  }

  function displayLabel(node) {
    if (node.kind === "secret") return node.baseLabel;
    if (node.kind === "root") {
      return node.found ? `${node.baseLabel} · ${node.found}` : node.baseLabel;
    }
    if (node.kind === "path" || node.kind === "phase") {
      const n = subtreeSecrets(node);
      return n ? `${node.baseLabel} · ${n}` : node.baseLabel;
    }
    return node.found ? `${node.baseLabel} · ${node.found}` : node.baseLabel;
  }

  // Recompute layout, create DOM for any new nodes near their parent, then
  // animate every freshly-created node into place (a single event can add a
  // whole chain of path nodes at once).
  function grow() {
    layoutTree();
    const fresh = [];
    for (const n of state.nodes.values()) {
      if (!n.els.circle && n !== state.root) {
        ensureDom(n);
        const p = n.parent ? n.parent.pos : { x: 0, y: 0 };
        n.els.circle.setAttribute("cx", p.x);
        n.els.circle.setAttribute("cy", p.y);
        fresh.push(n);
      }
    }
    syncDom(!state.catchUp);
    for (const n of fresh) {
      if (state.catchUp) revealInstant(n);
      else animateArrival(n);
    }
  }

  // place a node immediately (no probe/impact), used when catching up
  function revealInstant(node) {
    if (node.els.circle) node.els.circle.setAttribute("r", radiusFor(node));
    if (node.els.edge) node.els.edge.removeAttribute("stroke-dasharray");
    if (node.els.label) node.els.label.style.opacity = "1";
  }

  // ---- layout: horizontal tidy tree, results pulled to the center line ----
  function ownRank(node) {
    if (node.kind === "secret") return SEV_RANK[node.severity] ?? 2;
    if (!node.found) return 5; // no secrets here
    return SEV_RANK[node.worst];
  }
  function nodeRank(node) {
    let best = ownRank(node);
    for (const c of node.children) best = Math.min(best, nodeRank(c));
    return best;
  }

  function arrangeCenterOut(children) {
    const sorted = [...children].sort((a, b) => {
      const r = nodeRank(a) - nodeRank(b);
      return r !== 0 ? r : a.id.localeCompare(b.id);
    });
    const top = [];
    const bottom = [];
    sorted.forEach((node, i) => {
      if (i === 0) return;
      if (i % 2 === 1) bottom.push(node);
      else top.unshift(node);
    });
    return [...top, sorted[0], ...bottom];
  }

  // A node earns a place in the tree if a secret was found anywhere in its
  // subtree, or the page being scanned lives under it, or it's the root.
  // Empty crawled pages stay out of the way so the view is "URL -> secrets".
  function subtreeVisible(node) {
    if (node.found || node.active) return true;
    for (const c of node.children) if (subtreeVisible(c)) return true;
    return false;
  }
  function isVisible(node) {
    return node === state.root || subtreeVisible(node);
  }

  function layoutTree() {
    if (!state.root) return;
    for (const n of state.nodes.values()) n._vis = isVisible(n);

    let leaf = 0;
    (function assign(node) {
      const kids = node.children.filter((c) => c._vis);
      const ordered = kids.length > 1 ? arrangeCenterOut(kids) : kids;
      node.pos.x = node.depth * COL_GAP;
      if (ordered.length === 0) {
        node.pos.y = leaf * ROW_GAP;
        leaf++;
      } else {
        ordered.forEach(assign);
        node.pos.y = (ordered[0].pos.y + ordered[ordered.length - 1].pos.y) / 2;
      }
    })(state.root);

    let min = Infinity;
    let max = -Infinity;
    for (const n of state.nodes.values()) {
      if (!n._vis) continue;
      if (n.pos.y < min) min = n.pos.y;
      if (n.pos.y > max) max = n.pos.y;
    }
    const mid = (min + max) / 2;
    for (const n of state.nodes.values()) if (n._vis) n.pos.y -= mid;
  }

  // ---- DOM ----
  function sevKey(sev) {
    return sev === "HIGH" ? "high" : sev === "MEDIUM" ? "med" : "low";
  }

  function nodeClass(node) {
    if (node.kind === "root") return "kt-node kt-root";
    if (node.kind === "secret") return `kt-node kt-secret sev-${sevKey(node.severity)}`;
    if (node.kind === "path") return "kt-node kt-path"; // neutral grouping hub
    const hit = node.found ? ` kt-hit sev-${sevKey(node.worst)}` : "";
    if (node.kind === "phase") return "kt-node kt-phase" + hit;
    return "kt-node kt-item" + hit + (node.active ? " working" : "");
  }

  function edgeClass(node) {
    // colour the branch by the worst secret found beyond it (incl. this node)
    const r = nodeRank(node);
    if (r <= 2) return `kt-edge sev-${r === 0 ? "high" : r === 1 ? "med" : "low"}`;
    return "kt-edge kt-edge-struct";
  }

  function labelClass(node) {
    if (node.kind === "root") return "kt-label kt-label-root";
    if (node.kind === "secret") return `kt-label sev-${sevKey(node.severity)}`;
    if (node.kind === "path") return "kt-label kt-label-path";
    const hit = node.found ? ` sev-${sevKey(node.worst)}` : "";
    if (node.kind === "phase") return "kt-label kt-label-phase" + hit;
    return "kt-label kt-label-item" + hit;
  }

  function radiusFor(node) {
    if (node.kind === "root") return 12;
    if (node.kind === "secret") return 5;
    if (node.kind === "phase") return 7;
    if (node.kind === "path") return 5;
    // page/source node grows a little with the number of secrets on it
    if (node.found) return Math.min(11, 5 + Math.log2(node.found + 1));
    return 4;
  }

  // total secrets in a node's subtree (a page counts its own; secrets are 0)
  function subtreeSecrets(node) {
    let n = node.found || 0;
    for (const c of node.children) n += subtreeSecrets(c);
    return n;
  }

  function titleFor(node) {
    if (node.kind === "root") {
      return node.found ? `${node.label} — ${node.found} secret(s) on homepage` : node.label;
    }
    if (node.kind === "secret") {
      return `[${node.severity}] ${node.source} ${node.label}`.trim();
    }
    if (node.kind === "path" || node.kind === "phase") {
      const n = subtreeSecrets(node);
      return `${node.baseLabel}${n ? ` — ${n} secret(s)` : ""}`;
    }
    const where = node.url || node.label;
    if (node.found) return `${where} — ${node.found} secret(s), worst ${node.worst}`;
    return where;
  }

  function ensureDom(node) {
    if (node.els.circle) return;
    if (node !== state.root) {
      const edge = svgEl("path", {
        d: branchPath(node.parent.pos, node.parent.pos),
        class: edgeClass(node),
        "stroke-dasharray": "3 5",
      });
      els.edges.appendChild(edge);
      node.els.edge = edge;
    }

    const circle = svgEl("circle", {
      cx: node.pos.x, cy: node.pos.y,
      r: node === state.root ? radiusFor(node) : 0,
      class: nodeClass(node),
      "data-id": node.id,
    });
    const title = svgEl("title");
    title.textContent = titleFor(node);
    circle.appendChild(title);
    els.nodes.appendChild(circle);
    node.els.circle = circle;

    const label = svgEl("text", {
      x: node.pos.x, y: node.pos.y,
      class: labelClass(node),
      "text-anchor": "start",
    });
    label.textContent = displayLabel(node);
    if (node !== state.root) label.style.opacity = "0";
    els.labels.appendChild(label);
    node.els.label = label;
  }

  function syncDom(animate) {
    els.view.style.setProperty("--reflow-ms", animate ? "650ms" : "0ms");
    for (const node of state.nodes.values()) {
      if (!node.els.circle) continue;
      const shown = node._vis !== false;
      const disp = shown ? "" : "none";
      node.els.circle.style.display = disp;
      if (node.els.edge) node.els.edge.style.display = disp;
      if (node.els.label) node.els.label.style.display = disp;
      if (!shown) continue;
      node.els.circle.setAttribute("cx", node.pos.x);
      node.els.circle.setAttribute("cy", node.pos.y);
      node.els.circle.setAttribute("class", nodeClass(node));
      if (node.els.edge && node.parent) {
        node.els.edge.setAttribute("d", branchPath(node.parent.pos, node.pos, radiusFor(node) + 3));
        node.els.edge.setAttribute("class", edgeClass(node));
      }
      if (node.els.label) {
        const off = labelOffset(node);
        node.els.label.setAttribute("x", node.pos.x + off.x);
        node.els.label.setAttribute("y", node.pos.y + off.y);
        node.els.label.setAttribute("text-anchor", off.anchor);
      }
    }
    repositionTerminals();
  }

  function labelOffset(node) {
    if (node === state.root) return { x: 0, y: 28, anchor: "middle" };
    if (node.children.length === 0) return { x: 10, y: 3.5, anchor: "start" };
    return { x: 0, y: -11, anchor: "middle" };
  }

  function branchPath(from, to, trim) {
    let tx = to.x;
    let ty = to.y;
    if (trim) {
      const dx = to.x - from.x;
      const dy = to.y - from.y;
      const len = Math.hypot(dx, dy) || 1;
      tx = to.x - (dx / len) * trim; // stop short so the arrowhead sits outside the node
      ty = to.y - (dy / len) * trim;
    }
    const midX = (from.x + tx) / 2;
    return (
      `M${from.x.toFixed(2)},${from.y.toFixed(2)} ` +
      `C${midX.toFixed(2)},${from.y.toFixed(2)} ` +
      `${midX.toFixed(2)},${ty.toFixed(2)} ` +
      `${tx.toFixed(2)},${ty.toFixed(2)}`
    );
  }

  function animateArrival(node) {
    const parent = node.parent;
    if (!parent) return;
    const { circle, edge, label } = node.els;

    const probe = svgEl("circle", {
      cx: parent.pos.x, cy: parent.pos.y, r: 2.5, class: "kt-probe",
    });
    els.nodes.appendChild(probe);

    const TRAVEL = 420;
    const t0 = performance.now();
    (function travel(now) {
      const t = Math.min(1, (now - t0) / TRAVEL);
      const e = 1 - Math.pow(1 - t, 3);
      if (probe.isConnected) {
        probe.setAttribute("cx", (parent.pos.x + (node.pos.x - parent.pos.x) * e).toFixed(2));
        probe.setAttribute("cy", (parent.pos.y + (node.pos.y - parent.pos.y) * e).toFixed(2));
      }
      if (t < 1 && probe.isConnected) requestAnimationFrame(travel);
      else { probe.remove(); arrive(); }
    })(t0);

    function arrive() {
      if (edge) edge.removeAttribute("stroke-dasharray");
      const sev = node.kind === "secret" ? node.severity : node.found ? node.worst : null;
      const ring = svgEl("circle", {
        cx: node.pos.x, cy: node.pos.y, r: 4,
        class: "kt-impact" + (sev ? ` sev-${sevKey(sev)}` : ""),
      });
      els.nodes.appendChild(ring);
      setTimeout(() => ring.remove(), 760);
      if (circle) requestAnimationFrame(() => circle.setAttribute("r", radiusFor(node)));
      if (label) setTimeout(() => (label.style.opacity = "1"), 200);
    }
  }

  // ---- live "code rain" terminal anchored to the active node ----

  // Anchor the window up-and-right of the node, with a connector back to it.
  function termAnchor(node) {
    return { x: node.pos.x + 24, y: node.pos.y - TERM_H - 18 };
  }

  function openTerminal(node) {
    // keep the view readable: retire the oldest terminal past the cap
    if (state.terminals.size >= MAX_OPEN_TERMS) {
      const oldest = state.terminals.keys().next().value;
      destroyTerminal(state.terminals.get(oldest));
      state.terminals.delete(oldest);
    }
    if (state.terminals.has(node.id)) return;

    const anchor = termAnchor(node);

    const connector = svgEl("path", {
      d: connectorPath(node, anchor),
      class: "kt-term-link",
    });
    els.edges.appendChild(connector);

    const fo = svgEl("foreignObject", {
      x: anchor.x, y: anchor.y, width: TERM_W, height: TERM_H,
      class: "kt-term-fo",
    });
    const box = document.createElement("div");
    box.className = "kt-term";
    const head = document.createElement("div");
    head.className = "kt-term-head";
    const dot = document.createElement("span");
    dot.className = "kt-term-dot";
    const title = document.createElement("span");
    title.className = "kt-term-title";
    title.textContent = scanLabel(node);
    head.appendChild(dot);
    head.appendChild(title);
    const body = document.createElement("div");
    body.className = "kt-term-body";
    box.appendChild(head);
    box.appendChild(body);
    fo.appendChild(box);
    els.view.appendChild(fo);

    const term = {
      node, fo, body, connector,
      lines: [],
      vidx: 0, pidx: Math.floor(Math.random() * PATTERN_POOL.length),
      tick: 0, timer: null, closed: false,
    };
    state.terminals.set(node.id, term);

    termLine(term, `→ GET ${node.url || node.label}`, "info");
    term.timer = setInterval(() => streamTick(term), TERM_TICK_MS);
  }

  function scanLabel(node) {
    return (node.id.startsWith("js:") ? "scan.js · " : "scan · ") + (node.url || node.label);
  }

  // synthesize the next scrolling line: alternate an action and a pattern test
  function streamTick(term) {
    if (term.closed) return;
    term.tick += 1;
    const isJs = term.node.id.startsWith("js:");
    const actions = isJs
      ? ["parse ast", "eval window.*", "decode b64", "walk strings", "sourcemap?"]
      : ["render dom", "scan html", "scan inputs", "decode b64", "read storage"];
    if (term.tick % 2 === 0) {
      const p = PATTERN_POOL[term.pidx++ % PATTERN_POOL.length];
      termLine(term, `test /${p.slice(0, 22)}/`, "scan");
    } else {
      termLine(term, actions[term.vidx++ % actions.length], "info");
    }
  }

  function termLine(term, text, cls) {
    term.lines.push({ text, cls });
    if (term.lines.length > TERM_MAX_LINES) term.lines.shift();
    renderTerm(term);
  }

  // newest line brightest at the bottom; older ones fade upward (rain)
  function renderTerm(term) {
    term.body.innerHTML = "";
    const n = term.lines.length;
    term.lines.forEach((line, i) => {
      const row = document.createElement("div");
      row.className = "kt-term-line kt-term-" + line.cls;
      row.textContent = line.text;
      row.style.opacity = (0.32 + 0.68 * ((i + 1) / n)).toFixed(2);
      term.body.appendChild(row);
    });
  }

  function closeTerminal(nodeId, found) {
    const term = state.terminals.get(nodeId);
    if (!term) return;
    if (term.timer) { clearInterval(term.timer); term.timer = null; }
    term.closed = true;
    termLine(
      term,
      found ? `✓ done · ${found} secret${found === 1 ? "" : "s"}` : "✓ done · clean",
      found ? "match" : "ok"
    );
    term.fo.classList.add("kt-term-closing");
    setTimeout(() => {
      destroyTerminal(term);
      state.terminals.delete(nodeId);
    }, 1400);
  }

  function destroyTerminal(term) {
    if (!term) return;
    if (term.timer) { clearInterval(term.timer); term.timer = null; }
    if (term.fo && term.fo.parentNode) term.fo.remove();
    if (term.connector && term.connector.parentNode) term.connector.remove();
  }

  // keep open terminals glued to their (possibly reflowing) nodes
  function repositionTerminals() {
    for (const term of state.terminals.values()) {
      const anchor = termAnchor(term.node);
      term.fo.setAttribute("x", anchor.x);
      term.fo.setAttribute("y", anchor.y);
      term.connector.setAttribute("d", connectorPath(term.node, anchor, TERM_H));
    }
    if (state.detail) {
      const d = state.detail;
      const anchor = { x: d.node.pos.x + 24, y: d.node.pos.y - DETAIL_H - 18 };
      d.fo.setAttribute("x", anchor.x);
      d.fo.setAttribute("y", anchor.y);
      d.connector.setAttribute("d", connectorPath(d.node, anchor, DETAIL_H));
    }
  }

  function connectorPath(node, anchor, h) {
    const tx = anchor.x;
    const ty = anchor.y + h;
    const midY = (node.pos.y + ty) / 2;
    return (
      `M${node.pos.x.toFixed(2)},${node.pos.y.toFixed(2)} ` +
      `C${node.pos.x.toFixed(2)},${midY.toFixed(2)} ` +
      `${tx.toFixed(2)},${midY.toFixed(2)} ` +
      `${tx.toFixed(2)},${ty.toFixed(2)}`
    );
  }

  // ---- pinned detail terminal: click a node to see which page held what ----
  const DETAIL_W = 248;
  const DETAIL_H = 152;

  function toggleDetail(node) {
    if (node.kind === "root") return; // root has no per-page secrets to list
    if (state.detail && state.detail.node === node) { closeDetail(); return; }
    openDetail(node);
  }

  function openDetail(node) {
    closeDetail();
    const anchor = { x: node.pos.x + 24, y: node.pos.y - DETAIL_H - 18 };
    const connector = svgEl("path", {
      d: connectorPath(node, anchor, DETAIL_H),
      class: "kt-term-link kt-detail-link",
    });
    els.edges.appendChild(connector);

    const fo = svgEl("foreignObject", {
      x: anchor.x, y: anchor.y, width: DETAIL_W, height: DETAIL_H,
      class: "kt-term-fo",
    });
    const box = document.createElement("div");
    box.className = "kt-term kt-detail";
    const head = document.createElement("div");
    head.className = "kt-term-head";
    const title = document.createElement("span");
    title.className = "kt-term-title";
    title.textContent = node.url || node.label;
    const close = document.createElement("button");
    close.className = "kt-term-close";
    close.textContent = "×";
    close.addEventListener("click", (e) => { e.stopPropagation(); closeDetail(); });
    head.appendChild(title);
    head.appendChild(close);
    const body = document.createElement("div");
    body.className = "kt-term-body kt-detail-body";
    box.appendChild(head);
    box.appendChild(body);
    fo.appendChild(box);
    els.view.appendChild(fo);

    state.detail = { node, fo, body, connector };
    renderDetail();
  }

  function renderDetail() {
    const d = state.detail;
    if (!d) return;
    d.body.innerHTML = "";
    const findings = d.node.findings;
    if (!findings.length) {
      const row = document.createElement("div");
      row.className = "kt-term-line kt-term-ok";
      row.textContent = "no secrets on this page";
      d.body.appendChild(row);
      return;
    }
    findings.forEach((f) => {
      const row = document.createElement("div");
      row.className = "kt-term-line kt-detail-row sev-" + sevKey(f.severity);
      const tag = document.createElement("span");
      tag.className = "kt-detail-sev";
      tag.textContent = f.severity[0];
      const val = document.createElement("span");
      val.textContent = f.label + (f.source ? " · " + f.source : "");
      row.appendChild(tag);
      row.appendChild(val);
      d.body.appendChild(row);
    });
  }

  function closeDetail() {
    const d = state.detail;
    if (!d) return;
    if (d.fo.parentNode) d.fo.remove();
    if (d.connector.parentNode) d.connector.remove();
    state.detail = null;
  }

  function updateCount() {
    els.count.textContent = `${state.secrets} secret${state.secrets === 1 ? "" : "s"}`;
  }

  function svgEl(tag, attrs = {}) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    return node;
  }

  return { setVisible, reset, enqueue };
})();

const EndpointGrid = (() => {
  const GROUP_NAMES = {
    exposure: "Config & backup files",
    listing: "Directory listing",
    xmlrpc: "XML-RPC",
    user_enum: "User enumeration",
    xss: "Reflected XSS",
  };
  const GROUP_ORDER = ["exposure", "listing", "xmlrpc", "user_enum", "xss"];

  const state = {
    visible: false,
    groups: new Map(),
    counts: { exposed: 0, reachable: 0, safe: 0, tested: 0 },
  };

  function setVisible(visible) {
    state.visible = visible;
    els.endpointPanel.hidden = !visible;
  }

  function reset() {
    state.groups.clear();
    state.counts = { exposed: 0, reachable: 0, safe: 0, tested: 0 };
    els.endpointBody.innerHTML = "";
    renderCounts();
  }

  function enqueue(payload) {
    if (!payload || !payload.type) return;
    if (payload.type === "probe") {
      addProbe(payload);
    }
    // phase / scan_start currently no-ops; kept for future use.
  }

  function ensureGroup(groupId) {
    if (state.groups.has(groupId)) return state.groups.get(groupId);

    const section = document.createElement("section");
    section.className = "endpoint-group";
    section.dataset.group = groupId;

    const header = document.createElement("header");
    const name = document.createElement("span");
    name.className = "group-name";
    name.textContent = GROUP_NAMES[groupId] || groupId;
    const counter = document.createElement("span");
    counter.className = "group-count";
    counter.textContent = "0";
    header.appendChild(name);
    header.appendChild(counter);
    section.appendChild(header);

    const list = document.createElement("ul");
    list.className = "endpoint-list";
    section.appendChild(list);

    insertGroupSorted(section, groupId);

    const entry = { section, list, counter, exposed: 0, total: 0 };
    state.groups.set(groupId, entry);
    return entry;
  }

  function insertGroupSorted(section, groupId) {
    const desiredIdx = GROUP_ORDER.indexOf(groupId);
    const existing = els.endpointBody.children;
    for (const child of existing) {
      const childIdx = GROUP_ORDER.indexOf(child.dataset.group);
      if (desiredIdx !== -1 && (childIdx === -1 || childIdx > desiredIdx)) {
        els.endpointBody.insertBefore(section, child);
        return;
      }
    }
    els.endpointBody.appendChild(section);
  }

  function addProbe(probe) {
    const group = ensureGroup(probe.group);

    const item = document.createElement("li");
    item.className = "endpoint-item " + classifyState(probe);

    const status = document.createElement("span");
    status.className = "endpoint-status";
    status.textContent = probe.status != null ? probe.status : "—";

    const label = document.createElement("span");
    label.className = "endpoint-path";
    label.textContent = probe.label || probe.url || "—";

    const right = document.createElement("span");
    right.className = "endpoint-meta";
    if (probe.exposed && probe.severity) {
      const sev = document.createElement("span");
      sev.className = `endpoint-severity sev-${probe.severity.toLowerCase()}`;
      sev.textContent = probe.severity;
      right.appendChild(sev);
    }
    if (probe.note) {
      const note = document.createElement("span");
      note.className = "endpoint-note";
      note.textContent = probe.note;
      right.appendChild(note);
    }
    if (probe.url) {
      const link = document.createElement("a");
      link.href = probe.url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.className = "endpoint-link";
      link.textContent = "↗";
      link.title = probe.url;
      right.appendChild(link);
    }

    item.appendChild(status);
    item.appendChild(label);
    item.appendChild(right);
    group.list.appendChild(item);

    group.total += 1;
    if (probe.exposed) group.exposed += 1;
    group.counter.textContent = group.exposed
      ? `${group.exposed} / ${group.total}`
      : `${group.total}`;
    group.counter.classList.toggle("has-exposed", group.exposed > 0);

    state.counts.tested += 1;
    if (probe.exposed) state.counts.exposed += 1;
    else if (probe.reachable) state.counts.reachable += 1;
    else state.counts.safe += 1;
    renderCounts();
  }

  function classifyState(probe) {
    if (probe.exposed) return "state-exposed";
    if (probe.reachable) return "state-reachable";
    return "state-safe";
  }

  function renderCounts() {
    els.endpointExposedCount.textContent = state.counts.exposed;
    els.endpointReachableCount.textContent = state.counts.reachable;
    els.endpointSafeCount.textContent = state.counts.safe;
    els.endpointTestedLabel.textContent = `${state.counts.tested} tested`;
  }

  return { setVisible, reset, enqueue };
})();

els.runBtn.addEventListener("click", startRun);
els.stopBtn.addEventListener("click", stopRun);
els.clearBtn.addEventListener("click", clearTerminal);
els.copyBtn.addEventListener("click", copyTerminal);
els.downloadBtn.addEventListener("click", downloadTerminal);
els.refreshReports.addEventListener("click", refreshReports);

loadTools();
refreshRuns();
refreshReports();
