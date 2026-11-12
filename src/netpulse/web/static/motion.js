// The Motion switch (plan section 25). The choice is kept in this browser only.
// This file runs in <head>, before the page is drawn, so a viewer who switched
// motion off never sees it start. The stylesheet runs animations only under
// prefers-reduced-motion: no-preference and without the motion-off class.
(function () {
  var KEY = "netpulse.motion";
  var root = document.documentElement;
  // Says that scripts run, before the page is drawn: the stylesheet floats the
  // messages about the last action only then (plan section 43).
  root.classList.add("js");

  function stored() {
    try {
      return window.localStorage.getItem(KEY);
    } catch (e) {
      return null; // storage blocked: motion follows the system setting only
    }
  }

  function store(value) {
    try {
      window.localStorage.setItem(KEY, value);
    } catch (e) {
      // Not kept, but still applies to this page.
    }
  }

  if (stored() === "off") {
    root.classList.add("motion-off");
  }

  var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)");

  function render(button) {
    var system = reduced && reduced.matches;
    var on = !system && !root.classList.contains("motion-off");
    button.setAttribute("aria-pressed", on ? "true" : "false");
    button.querySelector(".motion-state").textContent = on ? "on" : "off";
    button.disabled = system;
    button.title = system ? "Your system asks for reduced motion, so nothing moves" : "Keeps your choice in this browser";
    button.hidden = false;
  }

  document.addEventListener("DOMContentLoaded", function () {
    var button = document.getElementById("motion-toggle");
    if (button === null) {
      return;
    }
    render(button);
    button.addEventListener("click", function () {
      store(root.classList.toggle("motion-off") ? "off" : "on");
      render(button);
    });
    if (reduced && reduced.addEventListener) {
      reduced.addEventListener("change", function () {
        render(button);
      });
    }
  });
})();
