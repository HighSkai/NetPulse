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

  var MESSAGES = {
    400: "That request was rejected. Reload the page and try again.",
    401: "You are signed out. Reload the page and sign in.",
    403: "Your account may not do that.",
    409: "Something else is already running. Wait for it to finish.",
    429: "Too many attempts. Wait a little and try again.",
    503: "NetPulse cannot do that on its PC right now, so nothing was checked or stored.",
  };

  document.addEventListener("htmx:responseError", function (event) {
    var status = event.detail.xhr.status;
    show(MESSAGES[status] || "NetPulse returned an error (" + status + ").");
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
  if (current && tabs.scrollWidth > tabs.clientWidth) {
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

// The status bar's clock: the local time of the device showing the page, with
// UTC on hover (plan section 25). The server draws it, and this keeps it ticking.
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

  tick();
  setInterval(tick, 1000);
})();

// Menus (plan section 43): a row's actions and the account menu are popovers,
// which the browser draws above everything and closes on a click elsewhere or
// Escape. This only puts an opened menu beside its button, inside the window.
(function () {
  var MARGIN = 8;

  function place(menu) {
    var button = document.querySelector('[popovertarget="' + menu.id + '"]');
    if (button === null) return;
    var box = button.getBoundingClientRect();
    var width = menu.offsetWidth;
    var height = menu.offsetHeight;
    var left = Math.min(Math.max(MARGIN, box.right - width), window.innerWidth - width - MARGIN);
    var top = box.bottom + 4;
    if (top + height > window.innerHeight - MARGIN) top = Math.max(MARGIN, box.top - height - 4);
    menu.style.left = left + "px";
    menu.style.top = top + "px";
  }

  function closeAll() {
    document.querySelectorAll(".menu:popover-open").forEach(function (menu) { menu.hidePopover(); });
  }

  // toggle does not bubble, so listen while it is captured.
  document.addEventListener("toggle", function (event) {
    var menu = event.target;
    if (menu.classList && menu.classList.contains("menu") && event.newState === "open") place(menu);
  }, true);
  // A menu is fixed to the window: when what is under it moves, it goes.
  window.addEventListener("resize", closeAll);
  window.addEventListener("scroll", closeAll, true);

  // The device table re-reads itself every 30 s. Not while one of its menus is
  // open: the menu would vanish under the pointer.
  document.addEventListener("htmx:beforeRequest", function (event) {
    var source = event.detail.elt;
    if (source && source.id === "device-rows" && source.querySelector(".menu:popover-open") !== null) {
      event.preventDefault();
    }
  });
})();

// One dialog for every "are you sure" (plan section 43): HTMX's hx-confirm, and
// any plain form with data-confirm. Cancel has the focus when it opens, so
// Enter never deletes anything by accident.
(function () {
  var dialog = document.getElementById("confirm");
  var supported = dialog !== null && typeof dialog.showModal === "function";

  function ask(question) {
    if (!supported) return Promise.resolve(window.confirm(question));
    return new Promise(function (resolve) {
      document.getElementById("confirm-text").textContent = question;
      dialog.returnValue = "cancel";
      dialog.addEventListener("close", function () { resolve(dialog.returnValue === "ok"); }, { once: true });
      dialog.showModal();
      dialog.querySelector(".dialog-cancel").focus();
    });
  }

  document.addEventListener("htmx:confirm", function (event) {
    if (!event.detail.question) return;
    event.preventDefault();
    ask(event.detail.question).then(function (yes) {
      if (yes) event.detail.issueRequest(true);
    });
  });

  document.addEventListener("submit", function (event) {
    var form = event.target;
    var question = form.getAttribute && form.getAttribute("data-confirm");
    if (!question || form.dataset.confirmed === "yes") return;
    event.preventDefault();
    ask(question).then(function (yes) {
      if (!yes) return;
      form.dataset.confirmed = "yes";
      if (typeof form.requestSubmit === "function") form.requestSubmit(); else form.submit();
    });
  });
})();

// Messages about the last action (plan section 43) float above the status bar.
// A success leaves by itself; an error stays until it is dismissed, and so does
// anything while the pointer or the keyboard is on it.
(function () {
  var STAY_MS = 6000;

  function remove(toast) {
    if (!toast.isConnected) return;
    toast.classList.add("leaving");
    // With motion off there is no animation to wait for.
    var gone = function () { toast.remove(); };
    toast.addEventListener("animationend", gone, { once: true });
    setTimeout(gone, 250);
  }

  document.querySelectorAll(".toast").forEach(function (toast) {
    var close = toast.querySelector(".toast-close");
    close.hidden = false;
    close.addEventListener("click", function () { remove(toast); });
    if (toast.classList.contains("toast-error")) return;
    var timer = setTimeout(function () { remove(toast); }, STAY_MS);
    toast.addEventListener("pointerenter", function () { clearTimeout(timer); });
    toast.addEventListener("focusin", function () { clearTimeout(timer); });
    toast.addEventListener("pointerleave", function () { timer = setTimeout(function () { remove(toast); }, STAY_MS / 2); });
  });
})();
