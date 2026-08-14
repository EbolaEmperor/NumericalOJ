(function (global) {
  "use strict";

  if (global.NumOJProblemDetailLayout) return;

  var page = document.querySelector(".problem-detail-page");
  var row = page && page.querySelector(".problem-detail-row");
  var outerSplitter = page &&
    page.querySelector("[data-problem-detail-splitter]");
  if (!page || !row || !outerSplitter) return;

  var desktop = global.matchMedia("(min-width: 992px)");
  var isLeanWorkbench = page.classList.contains("is-lean-workbench");
  var layoutFrame = 0;

  function clamp(value, minimum, maximum) {
    return Math.min(maximum, Math.max(minimum, value));
  }

  function storedRatio(key, fallback) {
    var value = Number(global.localStorage.getItem(key));
    return value > 0 && value < 1 ? value : fallback;
  }

  function scheduleEditorLayout() {
    if (layoutFrame) global.cancelAnimationFrame(layoutFrame);
    layoutFrame = global.requestAnimationFrame(function () {
      layoutFrame = 0;
      if (global.editor && typeof global.editor.layout === "function") {
        global.editor.layout();
      }
      global.dispatchEvent(new CustomEvent("numoj:problem-detail-resize"));
    });
  }

  function bindSplitter(options) {
    var container = options.container;
    var splitter = options.splitter;
    var preferredRatio = storedRatio(options.storageKey, options.defaultRatio);
    var appliedWidth = 0;
    var pointerId = null;
    var pointerOffset = 0;

    function measurements() {
      var containerRect = container.getBoundingClientRect();
      var splitterWidth = Math.max(
        1,
        splitter.getBoundingClientRect().width || 7
      );
      var available = Math.max(1, containerRect.width - splitterWidth);
      var minimumFirst = Math.min(
        options.minimumFirst,
        available * 0.42
      );
      var minimumSecond = Math.min(
        options.minimumSecond,
        available * 0.48
      );
      return {
        containerRect: containerRect,
        available: available,
        minimum: minimumFirst,
        maximum: Math.max(minimumFirst, available - minimumSecond),
      };
    }

    function updateAria(width, bounds) {
      var minimum = Math.round(bounds.minimum / bounds.available * 100);
      var maximum = Math.round(bounds.maximum / bounds.available * 100);
      var current = Math.round(width / bounds.available * 100);
      splitter.setAttribute("aria-valuemin", String(minimum));
      splitter.setAttribute("aria-valuemax", String(maximum));
      splitter.setAttribute("aria-valuenow", String(current));
      splitter.setAttribute(
        "aria-valuetext",
        options.firstLabel + " " + current + "%，" +
          options.secondLabel + " " + (100 - current) + "%"
      );
    }

    function applyWidth(requestedWidth, updatePreference) {
      if (!desktop.matches) return;
      var bounds = measurements();
      appliedWidth = clamp(
        requestedWidth,
        bounds.minimum,
        bounds.maximum
      );
      if (updatePreference) {
        preferredRatio = appliedWidth / bounds.available;
      }
      container.style.setProperty(
        options.propertyName,
        appliedWidth.toFixed(2) + "px"
      );
      updateAria(appliedWidth, bounds);
      scheduleEditorLayout();
    }

    function applyPreferredRatio() {
      var bounds = measurements();
      applyWidth(preferredRatio * bounds.available, false);
    }

    function savePreference() {
      global.localStorage.setItem(
        options.storageKey,
        preferredRatio.toFixed(4)
      );
    }

    function finishDrag(event) {
      if (pointerId !== event.pointerId) return;
      pointerId = null;
      splitter.classList.remove("is-dragging");
      document.documentElement.classList.remove("is-problem-pane-resizing");
      savePreference();
    }

    splitter.addEventListener("pointerdown", function (event) {
      if (!desktop.matches || event.button !== 0) return;
      pointerId = event.pointerId;
      pointerOffset =
        event.clientX - splitter.getBoundingClientRect().left;
      splitter.setPointerCapture(pointerId);
      splitter.classList.add("is-dragging");
      document.documentElement.classList.add("is-problem-pane-resizing");
      event.preventDefault();
    });

    global.addEventListener("pointermove", function (event) {
      if (pointerId !== event.pointerId) return;
      var bounds = measurements();
      applyWidth(
        event.clientX - bounds.containerRect.left - pointerOffset,
        true
      );
      event.preventDefault();
    });

    global.addEventListener("pointerup", finishDrag);
    global.addEventListener("pointercancel", finishDrag);

    splitter.addEventListener("keydown", function (event) {
      var nextWidth = appliedWidth;
      var bounds = measurements();
      if (event.key === "ArrowLeft") {
        nextWidth -= event.shiftKey ? 48 : 16;
      } else if (event.key === "ArrowRight") {
        nextWidth += event.shiftKey ? 48 : 16;
      } else if (event.key === "Home") {
        nextWidth = bounds.minimum;
      } else if (event.key === "End") {
        nextWidth = bounds.maximum;
      } else {
        return;
      }
      event.preventDefault();
      applyWidth(nextWidth, true);
      savePreference();
    });

    splitter.addEventListener("dblclick", function () {
      preferredRatio = options.defaultRatio;
      applyPreferredRatio();
      savePreference();
    });

    var observer = new ResizeObserver(function () {
      if (desktop.matches) applyPreferredRatio();
    });
    observer.observe(container);

    desktop.addEventListener("change", function () {
      pointerId = null;
      splitter.classList.remove("is-dragging");
      document.documentElement.classList.remove("is-problem-pane-resizing");
      if (desktop.matches) {
        applyPreferredRatio();
      } else {
        container.style.removeProperty(options.propertyName);
      }
    });

    applyPreferredRatio();

    return {
      refresh: applyPreferredRatio,
    };
  }

  var outerLayout = bindSplitter({
    container: row,
    splitter: outerSplitter,
    propertyName: "--problem-detail-statement-width",
    storageKey: isLeanWorkbench
      ? "numoj.problemDetail.leanStatementRatio"
      : "numoj.problemDetail.statementRatio",
    defaultRatio: isLeanWorkbench ? 0.36 : 0.5,
    minimumFirst: 280,
    minimumSecond: isLeanWorkbench ? 480 : 340,
    firstLabel: "题面",
    secondLabel: "作答区",
  });

  var leanWorkbench = page.querySelector("#leanWorkbench");
  var leanSplitter = page.querySelector("[data-lean-workbench-splitter]");
  var leanLayout = leanWorkbench && leanSplitter
    ? bindSplitter({
        container: leanWorkbench,
        splitter: leanSplitter,
        propertyName: "--lean-source-width",
        storageKey: "numoj.problemDetail.leanSourceRatio",
        defaultRatio: 0.63,
        minimumFirst: 240,
        minimumSecond: 220,
        firstLabel: "代码",
        secondLabel: "证明状态",
      })
    : null;

  global.NumOJProblemDetailLayout = Object.freeze({
    refresh: function () {
      outerLayout.refresh();
      if (leanLayout) leanLayout.refresh();
    },
  });
})(window);
