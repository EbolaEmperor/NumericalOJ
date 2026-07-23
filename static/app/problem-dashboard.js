(function () {
  "use strict";

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

    function loadActivity() {
      if (!activityUrl) {
        showError("班级活跃度地址不可用");
        return;
      }

      if (requestController) requestController.abort();
      requestController = new AbortController();
      showLoading();

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
        .then(renderActivity)
        .catch(function (fetchError) {
          if (fetchError.name !== "AbortError") showError(fetchError.message);
        });
    }

    if (retry) retry.addEventListener("click", loadActivity);
    window.addEventListener("pagehide", function () {
      if (requestController) requestController.abort();
    }, { once: true });
    loadActivity();
  }

  document.querySelectorAll("[data-numoj-class-activity]").forEach(initializeActivityCard);
})();
