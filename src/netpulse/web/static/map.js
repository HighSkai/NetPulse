// The topology map (plan section 19), drawn with Cytoscape.js. The list beside
// it holds the same tree as HTML, with the same JSON in the page for this
// script, so the page still works without it.
(function () {
  var POSITIONS = "netpulse.map.positions";
  // The tree's grid: one column per step from this PC, one row per device.
  var COLUMN = 190;
  var ROW = 34;
  // Below this zoom labels are too small to read, so a large map starts at
  // this zoom on This PC instead of shrinking to fit. Fit shows all of it.
  var READABLE_ZOOM = 0.8;
  // The same glyphs as the dashboard's states (_macros.html); tests compare them.
  var GLYPHS = { up: "●", degraded: "▲", down: "✕", unchecked: "○", paused: "‖" };
  var STATE_TOKENS = { up: "--up", degraded: "--warn", down: "--down", unchecked: "--unknown", paused: "--unknown" };
  var cy = null;
  var selectedId = null;
  var fitted = false;

  function token(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function control(name) {
    return document.querySelector('[data-map="' + name + '"]');
  }

  function readElements() {
    var data = document.getElementById("map-data");
    return data ? JSON.parse(data.textContent) : [];
  }

  // Positions the user dragged nodes to, in this browser only. Storage can be
  // missing or blocked; the map then just lays itself out each time.
  function savedPositions() {
    try {
      return JSON.parse(localStorage.getItem(POSITIONS)) || {};
    } catch (e) {
      return {};
    }
  }

  function savePosition(node) {
    var all = savedPositions();
    all[node.id()] = node.position();
    try {
      localStorage.setItem(POSITIONS, JSON.stringify(all));
    } catch (e) {
      /* the position lasts until the page is reloaded */
    }
  }

  function forgetPositions() {
    try {
      localStorage.removeItem(POSITIONS);
    } catch (e) {
      /* nothing was saved */
    }
  }

  // A device's state is a glyph as well as a colour, never colour alone.
  function caption(node) {
    var state = node.data("state");
    var text = state ? GLYPHS[state] + " " + node.data("label") : node.data("label");
    if (node.data("kind") !== "device" && node.data("detail")) text += "\n" + node.data("detail");
    return text;
  }

  function stateColour(node) {
    return token(STATE_TOKENS[node.data("state")]);
  }

  // Colours come from the page's tokens, so the map follows the light or dark theme.
  function style() {
    return [
      {
        selector: "node",
        style: {
          label: caption,
          "font-family": getComputedStyle(document.body).fontFamily,
          "font-size": 12,
          color: token("--ink"),
          "text-valign": "center",
          "text-halign": "right",
          "text-margin-x": 6,
          "text-wrap": "wrap",
          "text-max-width": "160px",
          "text-background-color": token("--panel"),
          "text-background-opacity": 0.85,
          "text-background-padding": "2px",
          width: 16,
          height: 16,
          "background-color": token("--panel"),
          "border-width": 2,
          "border-color": token("--control"),
        },
      },
      // Plan section 32: a device's name is one line, cut to fit; the tooltip has all of it.
      { selector: 'node[kind = "device"]', style: { "text-wrap": "ellipsis" } },
      { selector: 'node[kind = "pc"]', style: { shape: "round-rectangle", width: 34, height: 22, "border-color": token("--accent") } },
      { selector: 'node[kind = "subnet"]', style: { shape: "hexagon", width: 22, height: 20, "background-color": token("--head") } },
      { selector: 'node[kind = "gateway"]', style: { shape: "diamond", width: 26, height: 26 } },
      { selector: 'node[kind = "other"]', style: { shape: "round-octagon", width: 24, height: 24, "border-style": "dashed" } },
      { selector: "node[state]", style: { "background-color": stateColour, "border-color": stateColour } },
      // Paused: hollow, like a node nobody monitors, but dashed.
      { selector: 'node[state = "paused"]', style: { "background-color": token("--panel"), "border-style": "dashed" } },
      {
        selector: "edge",
        style: { width: 1.5, "line-color": token("--control"), "curve-style": "straight" },
      },
      { selector: 'edge[evidence = "inferred"]', style: { "line-style": "dashed", "line-dash-pattern": [6, 4] } },
      { selector: 'edge[evidence = "declared"]', style: { "line-style": "dotted", width: 2 } },
      { selector: "node:selected", style: { "border-width": 4, "border-color": token("--select"), "overlay-opacity": 0 } },
      { selector: "node.match", style: { "border-width": 4, "border-color": token("--accent") } },
      { selector: ".faded", style: { opacity: 0.25 } },
    ];
  }

  // A tree from left to right: This PC in the first column, each step from it
  // in the next. Every node without children gets a row of its own, and a
  // parent sits level with the middle of its children, so no lines cross.
  // Children keep the list's order, so the gateway comes first. Devices that
  // could not be placed follow in rows underneath. Then nodes the user moved go
  // back where they were put.
  function layOut() {
    var order = {};
    readElements().forEach(function (element, index) { order[element.data.id] = index; });
    var byOrder = function (a, b) { return order[a.id()] - order[b.id()]; };
    var positions = {};
    var row = 0;

    function place(node, column) {
      var children = node.outgoers("node").sort(byOrder);
      var y;
      if (children.length === 0) {
        y = row++ * ROW;
      } else {
        var rows = children.map(function (child) { return place(child, column + 1); });
        y = (rows[0] + rows[rows.length - 1]) / 2;
      }
      positions[node.id()] = { x: column * COLUMN, y: y };
      return y;
    }

    var roots = cy.nodes().filter(function (node) { return node.indegree() === 0; }).sort(byOrder);
    var gap = false;
    roots.forEach(function (root) {
      if (root.data("kind") === "device" && !gap) {
        row += 1; // one empty row before the devices that are not placed
        gap = true;
      }
      place(root, 0);
    });
    var saved = savedPositions();
    cy.nodes().positions(function (node) { return saved[node.id()] || positions[node.id()]; });
  }

  // A page can load before it has a size, for example in a background tab.
  // Fitting then does nothing, so the first fit waits until the map has one.
  // Call it outside a batch: inside one, the new positions are not measured yet.
  function fitWhenShown() {
    if (fitted || cy.width() === 0 || cy.height() === 0) return;
    fitted = true;
    cy.fit(undefined, 30);
    if (cy.zoom() >= READABLE_ZOOM) return;
    var pc = cy.getElementById("pc");
    var box = cy.elements().boundingBox();
    cy.zoom(READABLE_ZOOM);
    cy.pan({
      x: 30 - box.x1 * READABLE_ZOOM,
      y: cy.height() / 2 - (pc.nonempty() ? pc.position("y") : box.y1) * READABLE_ZOOM,
    });
  }

  // Updates the drawing from the page's JSON. Only a device added or removed
  // lays the map out again, and even then moved nodes stay where they were put.
  // The view itself never moves on a refresh.
  function update() {
    var elements = readElements();
    var wanted = {};
    var changed = false;
    cy.batch(function () {
      elements.forEach(function (element) {
        wanted[element.data.id] = true;
        var existing = cy.getElementById(element.data.id);
        if (existing.nonempty()) {
          existing.removeData("state");
          existing.data(element.data);
        } else {
          cy.add(element);
          changed = true;
        }
      });
      cy.elements().forEach(function (element) {
        if (!wanted[element.id()]) {
          cy.remove(element);
          changed = true;
        }
      });
    });
    if (changed) layOut();
    if (selectedId) select(selectedId, {}); // marks it again in the new list, without scrolling
    search();
  }

  function listItem(id) {
    return document.getElementById("map-item-" + id);
  }

  // Selecting a node marks it in the list, and the other way round. Only a
  // click moves anything: options.centre centres the map on the node, and
  // options.scroll scrolls the list to it. id null clears the selection.
  function select(id, options) {
    selectedId = id;
    cy.nodes(":selected").unselect();
    document.querySelectorAll(".map-tree li.selected").forEach(function (li) {
      li.classList.remove("selected");
    });
    if (!id) return;
    var node = cy.getElementById(id);
    if (node.nonempty()) {
      node.select();
      if (options.centre) cy.center(node); // no animation: the design is still (plan section 14)
    }
    var item = listItem(id);
    if (item) {
      item.classList.add("selected");
      if (options.scroll) item.scrollIntoView({ block: "nearest" });
    }
  }

  function search() {
    var input = control("search");
    var query = input.value.trim().toLowerCase();
    var hits = cy.collection();
    cy.batch(function () {
      cy.elements().removeClass("match faded");
      if (!query) return;
      hits = cy.nodes().filter(function (node) {
        var text = (node.data("label") + " " + (node.data("detail") || "")).toLowerCase();
        return text.indexOf(query) !== -1;
      });
      cy.elements().not(hits).addClass("faded");
      hits.addClass("match");
    });
    control("found").textContent = query ? hits.length + " found" : "";
    return hits;
  }

  // Tooltips: a node says what the list says about it; a line, its evidence.
  function showTip(text, position) {
    var tip = document.querySelector(".map-tip");
    tip.textContent = text;
    tip.hidden = false;
    var box = document.querySelector(".map-canvas");
    tip.style.left = box.offsetLeft + Math.max(0, Math.min(position.x + 12, box.clientWidth - tip.offsetWidth - 4)) + "px";
    tip.style.top = box.offsetTop + position.y + 12 + "px";
  }

  function hideTip() {
    document.querySelector(".map-tip").hidden = true;
  }

  function nodeText(node) {
    var item = listItem(node.id());
    var line = item && item.querySelector(".map-node");
    return line ? line.textContent.replace(/\s+/g, " ").trim() : caption(node);
  }

  function start() {
    var drawing = document.querySelector(".map-drawing");
    if (!drawing || typeof cytoscape !== "function") return;
    drawing.hidden = false;
    var canvas = document.querySelector(".map-canvas");
    cy = cytoscape({
      container: canvas,
      style: style(),
      minZoom: 0.2,
      maxZoom: 3,
      boxSelectionEnabled: false,
      selectionType: "single",
    });
    // Added and placed in one batch, so nothing is drawn while every node is at 0,0.
    cy.batch(function () {
      cy.add(readElements());
      layOut();
    });
    fitWhenShown();
    new ResizeObserver(function () {
      cy.resize();
      fitWhenShown();
    }).observe(canvas);

    cy.on("tap", "node", function (event) { select(event.target.id(), { scroll: true }); });
    cy.on("tap", function (event) {
      if (event.target === cy) select(null, {});
    });
    cy.on("dbltap", "node[state]", function (event) {
      var link = document.getElementById("map-link-" + event.target.id());
      if (link) window.location.href = link.href;
    });
    cy.on("dragfree", "node", function (event) { savePosition(event.target); });
    cy.on("mouseover", "node", function (event) { showTip(nodeText(event.target), event.target.renderedPosition()); });
    cy.on("mouseover", "edge", function (event) {
      showTip(event.target.data("explanation"), event.target.renderedMidpoint());
    });
    cy.on("mouseout", "node, edge", hideTip);
    cy.on("pan zoom drag", hideTip);

    control("zoom-in").addEventListener("click", function () { zoomBy(1.25); });
    control("zoom-out").addEventListener("click", function () { zoomBy(0.8); });
    control("fit").addEventListener("click", function () { cy.fit(undefined, 30); });
    control("reset").addEventListener("click", function () {
      forgetPositions();
      layOut();
      fitted = false;
      fitWhenShown();
    });
    var input = control("search");
    input.addEventListener("input", search);
    input.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        var first = search().first();
        if (first.nonempty()) select(first.id(), { centre: true, scroll: true });
      } else if (event.key === "Escape") {
        input.value = "";
        search();
      }
    });

    // Clicking a line of the list (not its link) shows that node on the map.
    document.addEventListener("click", function (event) {
      var item = event.target.closest(".map-tree li");
      if (!item || event.target.closest("a")) return;
      select(item.dataset.node, { centre: true });
    });
    document.addEventListener("htmx:afterSettle", update);
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
      cy.style(style());
    });
  }

  function zoomBy(factor) {
    cy.zoom({
      level: cy.zoom() * factor,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
    });
  }

  document.addEventListener("DOMContentLoaded", start);
})();
