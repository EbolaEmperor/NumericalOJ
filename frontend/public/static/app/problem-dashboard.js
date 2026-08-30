(function () {
  "use strict";

  var ACTIVITY_CACHE_TTL_MS = 30_000;

  function setHidden(element, hidden) {
    if (element) element.hidden = hidden;
  }

  function formatMonthDay(day) {
    var parts = String(day || "").split("-");
    return parts.length === 3 ? parts[1] + "/" + parts[2] : "";
  }

  function initializeActivityCard(card) {
    var activityUrl = card.dataset.activityUrl;
    var loading = card.querySelector("[data-numoj-activity-loading]");
    var weekdays = card.querySelector("[data-numoj-activity-weekdays]");
    var grid = card.querySelector("[data-numoj-activity-grid]");
    var empty = card.querySelector("[data-numoj-activity-empty]");
    var error = card.querySelector("[data-numoj-activity-error]");
    var errorText = card.querySelector("[data-numoj-activity-error-text]");
    var retry = card.querySelector("[data-numoj-activity-retry]");
    var footer = card.querySelector("[data-numoj-activity-footer]");
    var start = card.querySelector("[data-numoj-activity-start]");
    var requestController = null;
    var idleRequest = null;
    var cacheKey = [
      "numoj.classActivity.v1",
      card.dataset.activityCacheKey || "anonymous",
      activityUrl || "missing",
    ].join(":");

    function showLoading() {
      setHidden(loading, false);
      setHidden(weekdays, true);
      setHidden(grid, true);
      setHidden(empty, true);
      setHidden(error, true);
      setHidden(footer, true);
    }

    function showError(message) {
      setHidden(loading, true);
      setHidden(weekdays, true);
      setHidden(grid, true);
      setHidden(empty, true);
      setHidden(error, false);
      setHidden(footer, true);
      if (errorText) errorText.textContent = message || "班级活跃度加载失败";
    }

    function renderActivity(payload) {
      var activity = Array.isArray(payload.activity) ? payload.activity : [];
      setHidden(loading, true);
      setHidden(error, true);

      if (!activity.length) {
        setHidden(weekdays, true);
        setHidden(grid, true);
        setHidden(empty, false);
        setHidden(footer, true);
        return;
      }

      var fragment = document.createDocumentFragment();
      activity.forEach(function (item) {
        var cell = document.createElement("span");
        var intensity = Math.max(0, Math.min(4, Number(item.intensity) || 0));
        cell.className = "level-" + intensity + (item.future ? " future" : "");
        cell.title = String(item.day || "") + "：" + (Number(item.count) || 0) + " 次提交";
        cell.setAttribute("aria-hidden", "true");
        fragment.appendChild(cell);
      });

      grid.replaceChildren(fragment);
      grid.setAttribute(
        "aria-label",
        (payload.class_cn || "当前班级") + "近十二周提交活跃度"
      );
      if (start) start.textContent = formatMonthDay(activity[0].day);
      setHidden(empty, true);
      setHidden(weekdays, false);
      setHidden(grid, false);
      setHidden(footer, false);
    }

    function readCache() {
      try {
        var entry = JSON.parse(window.sessionStorage.getItem(cacheKey) || "null");
        if (!entry || !entry.savedAt || !entry.payload || entry.payload.success === false) {
          return null;
        }
        return entry;
      } catch (_error) {
        return null;
      }
    }

    function writeCache(payload) {
      try {
        window.sessionStorage.setItem(cacheKey, JSON.stringify({
          savedAt: Date.now(),
          payload: payload,
        }));
      } catch (_error) {
        // sessionStorage 不可用时仍可直接请求，不阻断主页面。
      }
    }

    function fetchActivity(keepRenderedContent) {
      if (!activityUrl) {
        showError("班级活跃度地址不可用");
        return;
      }

      if (requestController) requestController.abort();
      requestController = new AbortController();
      if (!keepRenderedContent) showLoading();

      fetch(activityUrl, {
        headers: { Accept: "application/json" },
        credentials: "same-origin",
        signal: requestController.signal,
        mathCurveLoader: false,
      })
        .then(function (response) {
          return response.json().catch(function () {
            return {};
          }).then(function (payload) {
            if (!response.ok || payload.success === false) {
              throw new Error(payload.message || "班级活跃度加载失败");
            }
            return payload;
          });
        })
        .then(function (payload) {
          writeCache(payload);
          renderActivity(payload);
        })
        .catch(function (fetchError) {
          if (fetchError.name !== "AbortError" && !keepRenderedContent) {
            showError(fetchError.message);
          }
        });
    }

    function loadActivity() {
      var cached = readCache();
      if (cached) renderActivity(cached.payload);
      if (cached && Date.now() - cached.savedAt < ACTIVITY_CACHE_TTL_MS) return;
      if (!cached) showLoading();

      var refresh = function () {
        idleRequest = null;
        fetchActivity(Boolean(cached));
      };
      if (typeof window.requestIdleCallback === "function") {
        idleRequest = window.requestIdleCallback(refresh, { timeout: 800 });
      } else {
        idleRequest = window.setTimeout(refresh, 0);
      }
    }

    if (retry) retry.addEventListener("click", function () {
      fetchActivity(false);
    });
    window.addEventListener("pagehide", function () {
      if (requestController) {
        requestController.abort();
        requestController = null;
      }
      if (idleRequest !== null) {
        if (typeof window.cancelIdleCallback === "function") {
          window.cancelIdleCallback(idleRequest);
        } else {
          window.clearTimeout(idleRequest);
        }
        idleRequest = null;
      }
    });
    window.addEventListener("pageshow", function (event) {
      if (event.persisted && !requestController && idleRequest === null) {
        loadActivity();
      }
    });
    loadActivity();
  }

  document.querySelectorAll("[data-numoj-class-activity]").forEach(initializeActivityCard);
})();
