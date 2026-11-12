// The traffic pages (plan section 29): the rate graph, the filter presets,
// pausing the live packet list, and a flash on packets that just arrived.
// Without this script the pages still work: the numbers are in the page,
// a preset is sent with the form, and the list simply refreshes.
(function () {
  var HEIGHT = 180;
  var charts = {};

  function token(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function rateData() {
    var holder = document.getElementById("rate-data");
    return holder === null ? null : JSON.parse(holder.textContent);
  }

  function columns(data, kind) {
    return kind === "bytes"
      ? [data.t, data.bytes_in, data.bytes_out]
      : [data.t, data.packets_in, data.packets_out];
  }

  function amount(kind) {
    return function (chart, value) {
      if (value == null) return "–";
      if (kind === "packets") return value.toLocaleString() + " /s";
      if (value >= 1e6) return (value / 1e6).toFixed(1) + " MB/s";
      if (value >= 1e3) return (value / 1e3).toFixed(1) + " KB/s";
      return value + " B/s";
    };
  }

  // In is solid and out is dashed, so the lines differ by more than colour.
  function options(kind, width) {
    var axis = {
      stroke: token("--ink-2"),
      grid: { stroke: token("--rule"), width: 1 },
      ticks: { stroke: token("--rule"), width: 1 },
      font: "12px " + getComputedStyle(document.body).fontFamily,
    };
    var value = amount(kind);
    return {
      width: width,
      height: HEIGHT,
      scales: { y: { range: function (chart, min, max) { return [0, max > 0 ? Math.ceil(max * 1.1) : 10]; } } },
      series: [
        {},
        { label: "In", stroke: token("--accent"), width: 2, value: value, points: { show: false } },
        { label: "Out", stroke: token("--select"), width: 2, dash: [6, 4], value: value, points: { show: false } },
      ],
      axes: [
        // Whole seconds at least: the counts are per second, so finer ticks mean nothing.
        Object.assign({}, axis, { incrs: [1, 2, 5, 10, 15, 30, 60, 120, 300, 600] }),
        Object.assign({}, axis, {
          size: 88,
          values: function (chart, ticks) { return ticks.map(function (tick) { return value(chart, tick); }); },
        }),
      ],
    };
  }

  function drawCharts() {
    var data = rateData();
    if (data === null || typeof uPlot === "undefined") return;
    document.querySelectorAll("[data-rate-chart]").forEach(function (box) {
      var kind = box.dataset.rateChart;
      var known = charts[kind];
      if (known && known.box === box) {
        known.chart.setData(columns(data, kind));  // the preserved chart: new numbers only
        return;
      }
      if (known) known.chart.destroy();
      box.textContent = "";
      charts[kind] = { box: box, chart: new uPlot(options(kind, box.clientWidth), columns(data, kind), box) };
    });
  }

  function redraw() {
    Object.keys(charts).forEach(function (kind) { charts[kind].chart.destroy(); });
    charts = {};
    drawCharts();
  }

  // A preset fills the filter box, where it can still be edited.
  document.addEventListener("change", function (event) {
    if (event.target.id === "capture-preset") {
      var box = document.getElementById("field-filter");
      if (box !== null) box.value = event.target.value;
    }
  });

  // Pause: the packet list keeps its rows while the rest of the page refreshes.
  var paused = false;

  function showPause() {
    var button = document.getElementById("pause-packets");
    if (button === null) return;
    button.hidden = false;
    button.setAttribute("aria-pressed", paused ? "true" : "false");
    button.textContent = paused ? "Resume" : "Pause";
  }

  // HTMX keeps an element only when the incoming page marks it hx-preserve, so
  // while paused the list is marked in the response before it is swapped in.
  document.addEventListener("htmx:beforeSwap", function (event) {
    if (paused && typeof event.detail.serverResponse === "string") {
      event.detail.serverResponse = event.detail.serverResponse.replace(
        '<div id="packet-list">', '<div id="packet-list" hx-preserve="true">'
      );
    }
  });

  document.addEventListener("click", function (event) {
    if (event.target.id === "pause-packets") {
      paused = !paused;
      showPause();
    }
  });

  // Rows newer than any shown before flash once; the stylesheet decides whether that moves.
  var newest = null;

  function flashNewRows() {
    var rows = document.querySelectorAll("#packet-list tr[data-t]");
    var latest = newest;
    rows.forEach(function (row) {
      var t = BigInt(row.dataset.t);
      if (newest !== null && t > newest) row.classList.add("flash");
      if (latest === null || t > latest) latest = t;
    });
    newest = latest;
  }

  function refreshed() {
    drawCharts();
    showPause();
    if (!paused) flashNewRows();
  }

  document.addEventListener("DOMContentLoaded", refreshed);
  document.addEventListener("htmx:afterSettle", refreshed);
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", redraw);
  function fit() {
    Object.keys(charts).forEach(function (kind) {
      var width = charts[kind].box.clientWidth;
      if (width > 0 && width !== charts[kind].chart.width) charts[kind].chart.setSize({ width: width, height: HEIGHT });
    });
  }

  window.addEventListener("resize", fit);
  if (typeof ResizeObserver === "function") {
    new ResizeObserver(fit).observe(document.querySelector("main"));
  }
})();
