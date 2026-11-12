// Latency charts on the device page (plan section 17), drawn with uPlot.
// The numbers sit in the page as JSON next to each chart, and in its
// "Show data" table, so the page still works without this script.
(function () {
  var HEIGHT = 220;
  var drawn = [];

  function token(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function translucent(hex, alpha) {
    var n = parseInt(hex.slice(1), 16);
    return "rgba(" + (n >> 16) + "," + ((n >> 8) & 255) + "," + (n & 255) + "," + alpha + ")";
  }

  // idx is null until the pointer is over the chart; only then is a null value a gap.
  function ms(chart, value, series, idx) {
    if (value != null) return value + " ms";
    return idx == null ? "–" : "no data";
  }

  // Colours come from the page's tokens, so the chart follows the light or dark theme.
  function options(width) {
    var accent = token("--accent");
    var axis = {
      stroke: token("--ink-2"),
      grid: { stroke: token("--rule"), width: 1 },
      ticks: { stroke: token("--rule"), width: 1 },
      font: "12px " + getComputedStyle(document.body).fontFamily,
    };
    return {
      width: width,
      height: HEIGHT,
      scales: {
        y: {
          range: function (chart, min, max) {
            return [0, max > 0 ? Math.ceil(max * 1.1) : 10];
          },
        },
      },
      series: [
        {},
        // The band edges are context, not data to pick out: no point markers.
        { label: "Lowest", stroke: token("--control"), width: 1, points: { show: false }, value: ms },
        { label: "Average", stroke: accent, width: 2, value: ms },
        { label: "Highest", stroke: token("--control"), width: 1, points: { show: false }, value: ms },
      ],
      // Shade between highest (series 3) and lowest (series 1).
      bands: [{ series: [3, 1], fill: translucent(accent, 0.15) }],
      axes: [
        axis,
        Object.assign({}, axis, {
          size: 64,
          values: function (chart, ticks) {
            return ticks.map(function (tick) { return tick + " ms"; });
          },
        }),
      ],
    };
  }

  function draw(box) {
    var data = JSON.parse(document.getElementById(box.dataset.latencyChart).textContent);
    box.textContent = "";
    var chart = new uPlot(options(box.clientWidth), [data.t, data.min, data.avg, data.max], box);
    drawn.push({ box: box, chart: chart });
  }

  // Draws every chart not drawn yet, and forgets charts an HTMX swap removed.
  function drawAll() {
    drawn = drawn.filter(function (item) {
      if (item.box.isConnected) return true;
      item.chart.destroy();
      return false;
    });
    document.querySelectorAll("[data-latency-chart]").forEach(function (box) {
      var known = drawn.some(function (item) { return item.box === box; });
      if (!known) draw(box);
    });
  }

  function redrawAll() {
    drawn.forEach(function (item) { item.chart.destroy(); });
    drawn = [];
    drawAll();
  }

  document.addEventListener("DOMContentLoaded", drawAll);
  document.addEventListener("htmx:afterSettle", drawAll);
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", redrawAll);
  // The chart follows its box, whatever changed the box's width: the window,
  // a panel beside it, a phone turned on its side.
  function fit() {
    drawn.forEach(function (item) {
      var width = item.box.clientWidth;
      if (width > 0 && width !== item.chart.width) item.chart.setSize({ width: width, height: HEIGHT });
    });
  }

  window.addEventListener("resize", fit);
  if (typeof ResizeObserver === "function") {
    new ResizeObserver(fit).observe(document.querySelector("main"));
  }
})();
