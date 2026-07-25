(function () {
  "use strict";

  var page = document.querySelector("[data-submission-page]");
  if (!page) return;

  var desktopMedia = window.matchMedia("(min-width: 1200px)");
  var rows = Array.prototype.slice.call(
    page.querySelectorAll("[data-submission-row]")
  );
  var panel = page.querySelector("[data-submission-detail-panel]");
  var detailRequest = null;
  var detailStream = null;
  var activeRow = null;
  var activePayload = null;

  function setHidden(element, hidden) {
    if (element) element.hidden = Boolean(hidden);
  }

  function setText(selector, value) {
    var element = panel && panel.querySelector(selector);
    if (element) element.textContent = value == null || value === "" ? "—" : String(value);
  }

  function statusSlug(status) {
    return String(status || "Unknown")
      .trim()
      .toLowerCase()
      .replace(/\s+/g, "-")
      .replace(/[^a-z0-9-]/g, "") || "unknown";
  }

  function isActiveStatus(status) {
    return ["Pending", "Waiting", "Running", "Generating"].indexOf(
      String(status || "")
    ) !== -1;
  }

  function pointClass(status) {
    var value = String(status || "");
    if (value === "Accepted") return "is-accepted";
    if (["Pending", "Waiting", "Running", "Generating"].indexOf(value) !== -1) {
      return "is-active";
    }
    if (value === "Wrong Answer") {
      return "is-wrong-answer";
    }
    if (value === "Runtime Error") return "is-runtime-error";
    if (value === "Time Limit Exceeded") return "is-time-limit";
    if ([
      "Unaccepted",
      "Compile Error",
      "Memory Limit Exceeded",
      "Output Limit Exceeded",
      "Error",
      "Forbidden",
      "No Output",
      "Nonzero Exit Status",
    ].indexOf(value) !== -1) return "is-other-failure";
    return "is-neutral";
  }

  function closeDetailStream() {
    if (detailStream) {
      detailStream.close();
      detailStream = null;
    }
  }

  function abortDetailRequest() {
    if (detailRequest) {
      detailRequest.abort();
      detailRequest = null;
    }
  }

  function showPanelState(state, message) {
    if (!panel) return;
    setHidden(panel.querySelector("[data-detail-loading]"), state !== "loading");
    setHidden(panel.querySelector("[data-detail-empty]"), state !== "empty");
    setHidden(panel.querySelector("[data-detail-error]"), state !== "error");
    setHidden(panel.querySelector("[data-detail-content]"), state !== "content");
    if (state === "error" && message) {
      setText("[data-detail-error-message]", message);
    }
  }

  function setVerdictBadge(container, status) {
    if (!container) return;
    container.className = "submission-verdict submission-verdict--" + statusSlug(status);
    var text = container.querySelector("[data-detail-status-text]");
    if (text) text.textContent = status || "Unknown";
  }

  function renderPointSummary(point) {
    var summary = panel && panel.querySelector("[data-detail-test-summary]");
    if (!summary) return;
    if (!point) {
      summary.textContent = "暂无测试点结果。";
      return;
    }

    var lines = [
      "#" + point.test_index + "  " + String(point.status || "Unknown"),
    ];
    if (point.time !== null && point.time !== undefined && point.time !== "") {
      lines.push("耗时 " + point.time + " ms");
    }
    if (point.stderr) {
      lines.push("", "错误摘要", String(point.stderr));
    } else if (point.stdout) {
      lines.push("", "输出摘要", String(point.stdout));
    } else if (point.has_output_image) {
      lines.push("", "该测试点生成了输出图片，请进入完整详情查看。");
    } else {
      lines.push("", "该测试点没有额外输出。");
    }
    summary.textContent = lines.join("\n");
  }

  function renderTestMatrix(points) {
    var matrix = panel && panel.querySelector("[data-detail-test-matrix]");
    if (!matrix) return;
    matrix.replaceChildren();

    var safePoints = Array.isArray(points) ? points : [];
    setText("[data-detail-test-count]", safePoints.length + " 个");
    if (!safePoints.length) {
      renderPointSummary(null);
      return;
    }

    safePoints.forEach(function (point, index) {
      var button = document.createElement("button");
      var stateClass = pointClass(point.status);
      button.type = "button";
      button.className = "submission-test-point " + stateClass;
      button.title =
        "测试点 #" + point.test_index + " · " + String(point.status || "Unknown");
      button.setAttribute(
        "aria-label",
        "测试点 " + point.test_index + "，" + String(point.status || "Unknown")
      );
      var indexLabel = document.createElement("span");
      indexLabel.className = "submission-test-point__index";
      indexLabel.textContent = String(point.test_index);
      button.appendChild(indexLabel);
      if (stateClass === "is-active") {
        var loader = document.createElement("span");
        loader.className = "math-curve-loader";
        loader.dataset.mathCurveLoader = "";
        loader.dataset.iconOnly = "true";
        loader.dataset.size = "xs";
        loader.setAttribute("aria-hidden", "true");
        button.appendChild(loader);
      }
      button.addEventListener("click", function () {
        Array.prototype.forEach.call(
          matrix.querySelectorAll(".submission-test-point.is-selected"),
          function (selected) {
            selected.classList.remove("is-selected");
          }
        );
        button.classList.add("is-selected");
        renderPointSummary(point);
      });
      if (index === 0) button.classList.add("is-selected");
      matrix.appendChild(button);
      if (stateClass === "is-active" && window.MathCurveLoader) {
        window.MathCurveLoader.hydrate(button);
      }
    });
    renderPointSummary(safePoints[0]);
  }

  function setDetailScoreTone(status, score) {
    var element = panel && panel.querySelector("[data-detail-score]");
    if (!element) return;
    element.classList.remove("is-accepted", "is-failed", "is-zero");
    if (String(status || "") === "Accepted") {
      element.classList.add("is-accepted");
    } else if (score === null || score === undefined || Number(score) === 0) {
      element.classList.add("is-zero");
    } else {
      element.classList.add("is-failed");
    }
  }

  function renderPanel(payload) {
    if (!panel || !payload || !payload.submission) return;
    activePayload = payload;

    var submission = payload.submission;
    var problem = payload.problem || {};
    var points = Array.isArray(payload.test_points) ? payload.test_points : [];
    var maxScore = problem.max_score || (points.length || "—");
    var title = problem.title || submission.problem_title || "未命名题目";
    var language = String(problem.lang || "—").toUpperCase();
    var detailUrl = payload.detail_url || "#";

    setText("[data-detail-id]", "#" + submission.id);
    setText("[data-detail-title]", title);
    setText("[data-detail-score]", submission.score);
    setDetailScoreTone(submission.status, submission.score);
    setText("[data-detail-max-score]", "/" + maxScore);
    setText(
      "[data-detail-problem-id]",
      "P" + String(submission.problem_id || "").padStart(4, "0")
    );
    setText("[data-detail-language]", language);
    setText("[data-detail-username]", submission.username);
    setText("[data-detail-created-at]", submission.created_at);

    setVerdictBadge(
      panel.querySelector("[data-detail-status-badge]"),
      submission.status
    );
    renderTestMatrix(points);

    Array.prototype.forEach.call(
      panel.querySelectorAll("[data-detail-link], [data-detail-top-link]"),
      function (link) {
        link.href = detailUrl;
      }
    );

    var rejudgeButton = panel.querySelector("[data-detail-rejudge]");
    if (rejudgeButton) {
      rejudgeButton.dataset.rejudgeUrl = payload.rejudge_url || "";
      rejudgeButton.hidden = !payload.rejudge_url;
      rejudgeButton.disabled = false;
    }
    showPanelState("content");
  }

  function renderRowSpark(cell, points) {
    if (!cell) return;
    cell.replaceChildren();
    var safePoints = Array.isArray(points) ? points : [];
    if (!safePoints.length) {
      var empty = document.createElement("span");
      empty.className = "submission-test-spark__empty";
      empty.textContent = "—";
      cell.appendChild(empty);
      return;
    }

    var spark = document.createElement("span");
    spark.className = "submission-test-spark";
    spark.title = "共 " + safePoints.length + " 个测试点";
    spark.setAttribute("aria-label", spark.title);
    safePoints.slice(0, 18).forEach(function (point) {
      var bar = document.createElement("span");
      bar.className = "submission-test-spark__bar " + pointClass(point.status);
      bar.setAttribute("aria-hidden", "true");
      spark.appendChild(bar);
    });
    if (safePoints.length > 18) {
      var more = document.createElement("span");
      more.className = "submission-test-spark__more";
      more.textContent = "+" + (safePoints.length - 18);
      spark.appendChild(more);
    }
    cell.appendChild(spark);
  }

  function applyLiveSnapshot(snapshot) {
    if (!activeRow || !activePayload || !snapshot) return;

    activePayload.submission.status = snapshot.status;
    activePayload.submission.score = snapshot.score;
    activePayload.test_points = Array.isArray(snapshot.test_points)
      ? snapshot.test_points
      : [];

    setVerdictBadge(
      panel.querySelector("[data-detail-status-badge]"),
      snapshot.status
    );
    setText("[data-detail-score]", snapshot.score);
    setDetailScoreTone(snapshot.status, snapshot.score);
    renderTestMatrix(activePayload.test_points);

    setVerdictBadge(
      activeRow.querySelector("[data-detail-status-badge]"),
      snapshot.status
    );
    var rowScore = activeRow.querySelector("[data-row-score]");
    if (rowScore) {
      rowScore.textContent =
        snapshot.score === null || snapshot.score === undefined
          ? "—"
          : String(snapshot.score);
      rowScore.classList.toggle("is-accepted", snapshot.status === "Accepted");
      rowScore.classList.toggle(
        "is-zero",
        Number(snapshot.score || 0) === 0 && snapshot.status !== "Accepted"
      );
    }
    renderRowSpark(
      activeRow.querySelector("[data-row-test-points]"),
      activePayload.test_points
    );
  }

  function openDetailStream(url) {
    closeDetailStream();
    if (!url || !window.EventSource) return;

    detailStream = new EventSource(url);
    detailStream.addEventListener("status", function (event) {
      try {
        var snapshot = JSON.parse(event.data);
        applyLiveSnapshot(snapshot);
        if (!snapshot.is_judging) closeDetailStream();
      } catch (_error) {
        closeDetailStream();
      }
    });
    detailStream.addEventListener("done", function (event) {
      try {
        applyLiveSnapshot(JSON.parse(event.data));
      } catch (_error) {
        // 终态帧解析失败时只关闭连接，不覆盖已显示的最后状态。
      }
      closeDetailStream();
    });
    detailStream.addEventListener("timeout", closeDetailStream);
  }

  function requestPanel(row) {
    var url = row && row.dataset.panelUrl;
    if (!url) return;

    abortDetailRequest();
    closeDetailStream();
    showPanelState("loading");

    var controller = new AbortController();
    detailRequest = controller;
    var requestedId = row.dataset.submissionId;

    fetch(url, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      signal: controller.signal,
    })
      .then(function (response) {
        return response.json().then(function (payload) {
          if (!response.ok || !payload.success) {
            throw new Error(payload.message || "请求失败");
          }
          return payload;
        });
      })
      .then(function (payload) {
        if (!activeRow || activeRow.dataset.submissionId !== requestedId) return;
        detailRequest = null;
        renderPanel(payload);
        if (isActiveStatus(payload.submission.status)) {
          openDetailStream(payload.status_stream_url);
        }
      })
      .catch(function (error) {
        if (error && error.name === "AbortError") return;
        if (!activeRow || activeRow.dataset.submissionId !== requestedId) return;
        detailRequest = null;
        showPanelState("error", error.message || "请稍后重试。");
      });
  }

  function selectRow(row, force) {
    if (!row || !desktopMedia.matches) return;
    if (activeRow === row && !force) return;

    rows.forEach(function (candidate) {
      var selected = candidate === row;
      candidate.classList.toggle("is-selected", selected);
      candidate.setAttribute("aria-selected", selected ? "true" : "false");
    });
    activeRow = row;
    activePayload = null;
    requestPanel(row);
  }

  rows.forEach(function (row) {
    row.addEventListener("click", function (event) {
      if (event.target.closest("a, button, input, select, textarea")) return;
      if (desktopMedia.matches) {
        selectRow(row, false);
      } else {
        window.location.assign(row.dataset.detailUrl);
      }
    });
    row.addEventListener("keydown", function (event) {
      if (event.key !== "Enter" && event.key !== " ") return;
      if (event.target.closest("a, button, input, select, textarea")) return;
      event.preventDefault();
      if (desktopMedia.matches) {
        selectRow(row, false);
      } else {
        window.location.assign(row.dataset.detailUrl);
      }
    });
  });

  var retryButton = panel && panel.querySelector("[data-detail-retry]");
  if (retryButton) {
    retryButton.addEventListener("click", function () {
      if (activeRow) selectRow(activeRow, true);
    });
  }

  var rejudgeButton = panel && panel.querySelector("[data-detail-rejudge]");
  if (rejudgeButton) {
    rejudgeButton.addEventListener("click", function () {
      var url = rejudgeButton.dataset.rejudgeUrl;
      if (!url || !activePayload) return;
      if (!window.confirm("确认重测提交 #" + activePayload.submission.id + "？")) {
        return;
      }

      rejudgeButton.disabled = true;
      fetch(url, {
        method: "POST",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      })
        .then(function (response) {
          return response.json().then(function (payload) {
            if (!response.ok || !payload.success) {
              throw new Error(payload.message || "重测请求失败");
            }
            return payload;
          });
        })
        .then(function () {
          applyLiveSnapshot({
            status: "Pending",
            score: 0,
            test_points: [],
          });
          openDetailStream(activePayload.status_stream_url);
        })
        .catch(function (error) {
          window.alert("重测失败：" + (error.message || "请稍后重试"));
          rejudgeButton.disabled = false;
        });
    });
  }

  function syncProblemFilter() {
    var form = page.querySelector("[data-submission-filter-form]");
    var input = page.querySelector("[data-problem-filter-input]");
    var value = page.querySelector("[data-problem-filter-value]");
    var datalist = document.getElementById("submissionProblemOptions");
    if (!form || !input || !value || !datalist) return;

    var options = Array.prototype.slice.call(datalist.querySelectorAll("option"));
    function selectedProblemId() {
      var current = input.value.trim();
      if (!current) return "";
      var matched = options.find(function (option) {
        return option.value === current;
      });
      return matched ? matched.dataset.problemId || "" : null;
    }

    input.addEventListener("input", function () {
      input.setCustomValidity("");
      var problemId = selectedProblemId();
      value.value = problemId || "";
    });
    form.addEventListener("submit", function (event) {
      var problemId = selectedProblemId();
      if (problemId === null) {
        event.preventDefault();
        input.setCustomValidity("请从题目建议列表中选择，或清空该筛选。");
        input.reportValidity();
        return;
      }
      input.setCustomValidity("");
      value.value = problemId;
    });
  }

  function setupTimeRangeRejudge() {
    var startButton = document.getElementById("btnStartTimeRangeRejudge");
    if (!startButton) return;

    var endpoint = page.dataset.timeRangeRejudgeUrl;
    var statusEndpoint = page.dataset.timeRangeStatusUrl;
    var startInput = document.getElementById("rejudgeStartTime");
    var endInput = document.getElementById("rejudgeEndTime");
    var progressBar = document.getElementById("timeRangeRejudgeProgressBar");
    var progressDetail = document.getElementById("timeRangeRejudgeProgressDetail");
    var progressTimer = null;

    function updateProgress(percent, done, total) {
      progressBar.style.width = percent + "%";
      progressBar.setAttribute("aria-valuenow", String(percent));
      progressBar.textContent = percent + "%";
      var text = "已完成 " + done + " / " + total;
      if (percent < 100 && window.MathCurveLoader) {
        window.MathCurveLoader.update(progressDetail, text, { size: "sm" });
      } else {
        progressDetail.textContent = text;
      }
    }

    function stopProgressTimer() {
      if (progressTimer) {
        window.clearInterval(progressTimer);
        progressTimer = null;
      }
    }

    function checkProgress() {
      fetch(statusEndpoint, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      })
        .then(function (response) { return response.json(); })
        .then(function (data) {
          if (!data.success) {
            stopProgressTimer();
            return;
          }
          updateProgress(Number(data.progress || 0), data.done || 0, data.total || 0);
          if (Number(data.progress || 0) >= 100) stopProgressTimer();
        })
        .catch(stopProgressTimer);
    }

    function submitRequest(start, end, confirmTotal) {
      var payload = { start: start, end: end };
      if (typeof confirmTotal === "number") payload.confirm_total = confirmTotal;
      return fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      }).then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok || !data.success) {
            throw new Error(data.message || "重测请求失败");
          }
          return data;
        });
      });
    }

    function showProgress(total) {
      var formElement = document.getElementById("timeRangeRejudgeModal");
      var formModal = window.bootstrap.Modal.getInstance(formElement);
      if (formModal) formModal.hide();
      var progressModal = new window.bootstrap.Modal(
        document.getElementById("timeRangeRejudgeProgressModal")
      );
      progressModal.show();
      updateProgress(0, 0, total);
      stopProgressTimer();
      progressTimer = window.setInterval(checkProgress, 1500);
    }

    startButton.addEventListener("click", function () {
      var start = (startInput.value || "").trim();
      var end = (endInput.value || "").trim();
      if (!start || !end) {
        window.alert("请选择起始时间和结束时间");
        return;
      }
      if (start > end) {
        window.alert("起始时间不能晚于结束时间");
        return;
      }

      startButton.disabled = true;
      submitRequest(start, end)
        .then(function (preview) {
          if (!preview.preview) return preview;
          if (preview.too_many) {
            throw new Error(
              "该时间范围命中 " + preview.total +
              " 条提交，超过单次上限 " + preview.max_total + " 条。"
            );
          }
          var confirmed = window.confirm(
            "该时间范围将重测 " + preview.total + " 条提交。\n" +
            "实际命中时间：" + preview.min_created_at + " ~ " +
            preview.max_created_at + "\n\n确认开始重测吗？"
          );
          if (!confirmed) return null;
          return submitRequest(start, end, Number(preview.total));
        })
        .then(function (result) {
          startButton.disabled = false;
          if (result) showProgress(Number(result.total || 0));
        })
        .catch(function (error) {
          startButton.disabled = false;
          window.alert("重测失败：" + (error.message || "请稍后重试"));
        });
    });
  }

  syncProblemFilter();
  setupTimeRangeRejudge();

  if (desktopMedia.matches && rows.length) {
    selectRow(rows[0], true);
  } else if (!rows.length) {
    showPanelState("empty");
  }

  desktopMedia.addEventListener("change", function (event) {
    if (event.matches && rows.length) {
      selectRow(activeRow || rows[0], true);
    } else {
      closeDetailStream();
      abortDetailRequest();
    }
  });

  window.addEventListener("pagehide", function () {
    closeDetailStream();
    abortDetailRequest();
  });
})();
