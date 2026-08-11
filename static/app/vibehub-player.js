(function () {
  "use strict";

  var root = document.querySelector("[data-vibehub-player]");
  if (!root) return;

  var frame = root.querySelector("[data-vibe-player-frame]");
  var loading = root.querySelector("[data-vibe-player-loading]");
  var errorPanel = root.querySelector("[data-vibe-player-error]");
  var errorMessage = root.querySelector("[data-vibe-player-error-message]");
  var state = root.querySelector("[data-vibe-player-state] span");
  var lease = null;
  var heartbeatTimer = null;
  var heartbeatPromise = null;
  var heartbeatController = null;
  var heartbeatFailures = 0;
  var released = false;
  var recovering = false;
  var isLeaving = false;
  var acquirePromise = null;
  var acquireGeneration = 0;

  function parseResponse(response) {
    return response.json().catch(function () {
      return { success: false, message: "服务器返回了无法读取的响应。" };
    }).then(function (payload) {
      if (!response.ok || !payload.success) {
        throw new Error(payload.message || payload.error || "作品启动失败，请稍后重试。");
      }
      return payload;
    });
  }

  function setReady(label) {
    loading.hidden = true;
    errorPanel.hidden = true;
    root.classList.add("is-ready");
    state.textContent = label || "运行中";
  }

  function showError(message) {
    loading.hidden = true;
    errorPanel.hidden = false;
    root.classList.remove("is-ready");
    errorMessage.textContent = message || "作品暂时无法启动，请稍后重试。";
    state.textContent = "启动失败";
  }

  function leaseField(payload, name) {
    var source = payload.lease || payload;
    return source[name] || "";
  }

  function markReadyOnNextLoad(label) {
    function onLoad() {
      frame.removeEventListener("load", onLoad);
      setReady(label);
    }
    frame.addEventListener("load", onLoad);
  }

  function urlFromTemplate(template, token) {
    if (!template) return "";
    return template.replace("__TOKEN__", encodeURIComponent(token));
  }

  function postRelease(releaseUrl, useBeacon) {
    if (!releaseUrl) return;
    if (useBeacon && navigator.sendBeacon) {
      navigator.sendBeacon(releaseUrl, new Blob(["{}"], { type: "application/json" }));
      return;
    }
    fetch(releaseUrl, {
      method: "POST",
      credentials: "same-origin",
      keepalive: true,
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: "{}"
    }).catch(function () {});
  }

  function releaseLease(useBeacon) {
    if (!lease || released) return;
    released = true;
    if (heartbeatTimer) window.clearInterval(heartbeatTimer);
    heartbeatTimer = null;
    var controller = heartbeatController;
    heartbeatController = null;
    heartbeatPromise = null;
    if (controller) controller.abort();
    postRelease(lease.releaseUrl, useBeacon);
  }

  function releaseGrantedPayload(payload, useBeacon) {
    var token = leaseField(payload, "lease_token") || leaseField(payload, "token");
    var releaseUrl = leaseField(payload, "release_url")
      || urlFromTemplate(root.dataset.releaseUrlTemplate, token);
    postRelease(releaseUrl, useBeacon);
  }

  function invalidatePendingAcquire() {
    acquireGeneration += 1;
    acquirePromise = null;
  }

  function heartbeat() {
    if (!lease || released || !lease.heartbeatUrl) return;
    if (heartbeatPromise) return heartbeatPromise;
    var heartbeatLease = lease;
    var controller = typeof AbortController === "function" ? new AbortController() : null;
    var timeout = window.setTimeout(function () {
      if (controller) controller.abort();
    }, 15000);
    heartbeatController = controller;
    var pending = fetch(heartbeatLease.heartbeatUrl, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: "{}",
      signal: controller ? controller.signal : undefined
    }).then(function (response) {
      if (!response.ok) throw new Error("heartbeat failed");
      if (lease !== heartbeatLease || released) return;
      heartbeatFailures = 0;
    }).catch(function () {
      if (lease !== heartbeatLease || released) return;
      heartbeatFailures += 1;
      if (heartbeatFailures >= 3 && !recovering && !isLeaving) {
        recovering = true;
        state.textContent = "连接续期中";
        releaseLease(false);
        lease = null;
        window.setTimeout(function () {
          if (isLeaving) return;
          recovering = false;
          acquireLease();
        }, 500);
      }
    }).finally(function () {
      window.clearTimeout(timeout);
      if (heartbeatPromise === pending) heartbeatPromise = null;
      if (heartbeatController === controller) heartbeatController = null;
    });
    heartbeatPromise = pending;
    return pending;
  }

  function acquireLease() {
    if (lease && !released) return Promise.resolve(lease);
    if (acquirePromise) return acquirePromise;
    if (!root.dataset.acquireUrl) {
      showError("运行入口尚未配置。请联系管理员检查 VibeHub 运行服务。");
      return Promise.resolve(null);
    }
    var generation = ++acquireGeneration;
    loading.hidden = false;
    errorPanel.hidden = true;
    root.classList.remove("is-ready");
    state.textContent = "正在申请运行资源";
    released = false;
    heartbeatFailures = 0;
    var pending = fetch(root.dataset.acquireUrl, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: "{}"
    }).then(parseResponse).then(function (payload) {
      var token = leaseField(payload, "lease_token") || leaseField(payload, "token");
      var proxyUrl = leaseField(payload, "proxy_url");
      if (!token || !proxyUrl) throw new Error("运行服务没有返回完整的租约信息。");
      if (generation !== acquireGeneration || isLeaving) {
        releaseGrantedPayload(payload, isLeaving);
        return null;
      }
      lease = {
        token: token,
        proxyUrl: proxyUrl.replace(/\/$/, "") + "/",
        heartbeatUrl: leaseField(payload, "heartbeat_url")
          || urlFromTemplate(root.dataset.heartbeatUrlTemplate, token),
        releaseUrl: leaseField(payload, "release_url")
          || urlFromTemplate(root.dataset.releaseUrlTemplate, token)
      };
      markReadyOnNextLoad("隔离容器运行中");
      frame.src = lease.proxyUrl;
      heartbeatTimer = window.setInterval(heartbeat, 20000);
      return lease;
    }).catch(function (error) {
      if (generation === acquireGeneration && !isLeaving) showError(error.message);
      return null;
    }).finally(function () {
      if (acquirePromise === pending) acquirePromise = null;
    });
    acquirePromise = pending;
    return pending;
  }

  function reloadFrame() {
    if (lease && lease.proxyUrl) {
      loading.hidden = false;
      root.classList.remove("is-ready");
      markReadyOnNextLoad("隔离容器运行中");
      frame.src = lease.proxyUrl;
    } else {
      acquireLease();
    }
  }

  root.querySelectorAll("[data-vibe-reload]").forEach(function (button) {
    button.addEventListener("click", reloadFrame);
  });
  var retry = root.querySelector("[data-vibe-retry]");
  if (retry) retry.addEventListener("click", function () {
    invalidatePendingAcquire();
    releaseLease(false);
    lease = null;
    acquireLease();
  });

  window.addEventListener("pagehide", function () {
    isLeaving = true;
    invalidatePendingAcquire();
    releaseLease(true);
  });
  acquireLease();
}());
