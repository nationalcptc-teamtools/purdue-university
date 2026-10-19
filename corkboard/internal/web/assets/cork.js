(function () {
  document.addEventListener("keydown", function (e) {
    if (e.key === "/" && !e.ctrlKey && !e.altKey && !e.metaKey && !e.isComposing && !document.activeElement.isContentEditable && !/input|textarea|select/i.test(document.activeElement.tagName)) {
      var box = document.querySelector("input[name=q], input[type=search]");
      if (box) { e.preventDefault(); box.focus(); }
    }
  });

  function copy(text, btn) {
    var done = function () {
      var old = btn.textContent;
      if (btn.dataset.copyTimer) clearTimeout(Number(btn.dataset.copyTimer));
      if (btn.dataset.copyLabel) old = btn.dataset.copyLabel;
      btn.dataset.copyLabel = old;
      btn.textContent = "Copied";
      notify("Copied to clipboard");
      btn.dataset.copyTimer = setTimeout(function () { btn.textContent = old; delete btn.dataset.copyLabel; delete btn.dataset.copyTimer; }, 900);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallback(); });
    } else { fallback(); }
    function fallback() {
      var ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta);
      ta.select();
      var copied = false;
      try { copied = document.execCommand("copy"); } catch (_) {}
      document.body.removeChild(ta);
      btn.focus({preventScroll: true});
      if (copied) done(); else notify("Copy failed. Select and copy the text manually.");
    }
  }

  document.addEventListener("click", function (e) {
    var el = e.target.closest(".copy");
    if (!el) return;
    e.preventDefault();
    copy(el.getAttribute("data-copy") || "", el);
  });

  var pending = false, refreshing = false, timer;
  function notify(message) {
    var toast = document.getElementById("toast");
    if (!toast) {
      toast = document.createElement("div");
      toast.id = "toast";
      toast.setAttribute("role", "status");
      toast.setAttribute("aria-live", "polite");
      document.body.appendChild(toast);
    }
    toast.textContent = message;
    clearTimeout(timer);
    timer = setTimeout(function () { toast.textContent = ""; }, 4000);
  }
  function refresh() {
    var main = document.querySelector("main[data-live]");
    if (!pending || refreshing || !main || !window.htmx || document.hidden ||
        main.querySelector("form:focus-within, form[data-dirty], details[open]")) return;
    pending = false;
    refreshing = true;
    htmx.ajax("GET", location.pathname + location.search, {
      target: main, select: "main", swap: "outerHTML"
    }).catch(function () { pending = true; }).finally(function () { refreshing = false; });
  }
  document.addEventListener("input", function (e) {
    if (e.target.form && e.target.form.method.toLowerCase() !== "get") e.target.form.dataset.dirty = "true";
  });
  document.addEventListener("htmx:configRequest", function (e) {
    e.detail.headers["X-CSRF-Token"] = document.body.dataset.csrf || "";
  });
  document.addEventListener("htmx:responseError", function (e) {
    notify("Request failed (" + e.detail.xhr.status + "). " + (e.detail.xhr.responseText || "Try again.").slice(0, 180));
  });
  document.addEventListener("htmx:sendError", function () { notify("Cannot reach Corkboard. Check your connection and try again."); });
  if (document.querySelector("main[data-live]") && window.EventSource) {
    var source = new EventSource("/events");
    var connected = false;
    function connectionStatus() {
      var status = document.getElementById("connection-status");
      if (status) { status.textContent = connected ? "Live" : "Reconnecting…"; status.dataset.state = connected ? "live" : "offline"; }
    }
    source.onopen = function () { connected = true; connectionStatus(); pending = true; };
    source.onerror = function () { connected = false; connectionStatus(); };
    document.addEventListener("htmx:afterSwap", connectionStatus);
    ["ingest", "host_new", "service_new", "claim", "release", "steal", "task_state", "note", "cred_new", "cred_access_admin", "compromise", "finding_state", "scope_alarm", "lock_change", "rules_reload", "stale", "purge", "bloodhound_sync", "bloodhound_target"].forEach(function (kind) {
      source.addEventListener(kind, function () { pending = true; });
    });
    setInterval(refresh, 2000);
    window.addEventListener("pagehide", function () { source.close(); });
  }
})();
