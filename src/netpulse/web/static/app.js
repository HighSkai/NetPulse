// HTMX does not swap failed responses, so a failed request would otherwise do
// nothing visible. Show a banner instead, and clear it on the next success.
(function () {
  function banner() {
    return document.getElementById("request-error");
  }

  function show(message) {
    banner().textContent = message;
    banner().hidden = false;
  }

  document.addEventListener("htmx:responseError", function (event) {
    var status = event.detail.xhr.status;
    show(
      status === 400
        ? "That request was rejected. Reload the page and try again."
        : status === 503
          ? "NetPulse cannot run ping on this PC, so nothing was checked or stored."
          : "NetPulse returned an error (" + status + ")."
    );
  });

  document.addEventListener("htmx:sendError", function () {
    show("Lost connection to NetPulse. Is it still running?");
  });

  // The status bar polls every few seconds. Its success must not hide an
  // error the user has not had time to read (plan section 13). Match on the
  // request path: after an outerHTML swap the event no longer comes from the bar.
  function isStatusPoll(event) {
    var bar = document.getElementById("monitor-status");
    return bar !== null && event.detail.pathInfo.requestPath === bar.getAttribute("hx-get");
  }

  document.addEventListener("htmx:afterRequest", function (event) {
    if (event.detail.successful && !isStatusPoll(event)) {
      banner().hidden = true;
    }
  });
})();

// Alt and a digit opens the tab with that number (plan section 25). Only the
// top-row digits: Alt with the number pad types characters on Windows.
(function () {
  // When the tabs are wider than the screen they scroll sideways: start with
  // the current one in view. Only the tab bar scrolls, never the page.
  var tabs = document.querySelector(".tabs");
  var current = tabs && tabs.querySelector('[aria-current="page"]');
  if (current !== null && tabs.scrollWidth > tabs.clientWidth) {
    var left = current.getBoundingClientRect().left - tabs.getBoundingClientRect().left + tabs.scrollLeft;
    tabs.scrollLeft = left - (tabs.clientWidth - current.offsetWidth) / 2;
  }

  document.addEventListener("keydown", function (event) {
    if (!event.altKey || event.ctrlKey || event.metaKey || event.shiftKey || !/^Digit\d$/.test(event.code)) {
      return;
    }
    var tab = document.querySelector('.tabs a[data-key="' + event.code.charAt(5) + '"]');
    if (tab !== null) {
      event.preventDefault();
      tab.click();
    }
  });
})();

// The status bar's clock: this PC's local time, with UTC on hover (plan
// section 25). The server draws it, and this keeps it ticking between polls.
(function () {
  function two(n) {
    return (n < 10 ? "0" : "") + n;
  }

  function tick() {
    var clock = document.getElementById("clock");
    if (clock === null) {
      return;
    }
    var now = new Date();
    var utc = now.toISOString();
    clock.textContent = two(now.getHours()) + ":" + two(now.getMinutes()) + ":" + two(now.getSeconds());
    clock.setAttribute("datetime", utc.slice(0, 19) + "Z");
    clock.title = utc.slice(0, 10) + " " + utc.slice(11, 19) + " UTC";
  }

  setInterval(tick, 1000);
})();
