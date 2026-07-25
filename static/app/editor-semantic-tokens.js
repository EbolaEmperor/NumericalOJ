(function () {
  "use strict";

  if (window.NumOJSemanticTokens) return;

  var SUPPORTED_LANGUAGES = ["c", "cpp", "py", "python", "matlab", "octave"];
  var RETRYABLE_BUSY_CODES = {
    legend_pending: true,
    result_pending: true,
    service_busy: true,
  };
  var BUSY_RETRY_CAPS_MS = [
    500, 1_000, 2_000, 4_000, 8_000, 12_000, 16_000, 20_000,
  ];
  var BUSY_RETRY_BUDGET_MS = 60_000;
  var legendValues = Object.create(null);

  function normalizedLanguage(value) {
    return String(value || "").toLowerCase();
  }

  function abortError() {
    var error = new Error("请求已取消");
    error.name = "AbortError";
    return error;
  }

  function waitForRetry(delayMs, signal) {
    if (signal && signal.aborted) return Promise.reject(abortError());
    return new Promise(function (resolve, reject) {
      var timer = window.setTimeout(function () {
        if (signal) signal.removeEventListener("abort", cancel);
        resolve();
      }, delayMs);
      function cancel() {
        window.clearTimeout(timer);
        signal.removeEventListener("abort", cancel);
        reject(abortError());
      }
      if (signal) signal.addEventListener("abort", cancel, { once: true });
    });
  }

  function responseRetryAfterMs(response) {
    if (
      !response.headers ||
      typeof response.headers.get !== "function"
    ) return 0;
    var seconds = Number.parseFloat(response.headers.get("Retry-After"));
    return Number.isFinite(seconds) && seconds > 0
      ? Math.ceil(seconds * 1_000)
      : 0;
  }

  async function fetchJsonWithBusyRetry(url, init, options) {
    var settings = options || {};
    var signal = settings.signal;
    var startedAt = Date.now();
    var attempt = 0;

    while (true) {
      if (signal && signal.aborted) throw abortError();
      var response = await fetch(url, init);
      var payload = null;
      try {
        payload = await response.json();
      } catch (_error) {
        // 统一在下方按无效响应处理。
      }
      if (response.ok) return payload;

      var error = new Error(
        payload && payload.message
          ? String(payload.message)
          : "语言服务返回 " + response.status
      );
      error.status = response.status;
      error.code = String(payload && payload.code || "");
      var canRetry = (
        settings.retryBusy
        && RETRYABLE_BUSY_CODES[error.code]
        && attempt < BUSY_RETRY_CAPS_MS.length
      );
      if (!canRetry) throw error;

      var minimumDelay = responseRetryAfterMs(response);
      var jitterCap = BUSY_RETRY_CAPS_MS[attempt];
      var delay = minimumDelay + Math.floor(Math.random() * jitterCap);
      if (Date.now() - startedAt + delay > BUSY_RETRY_BUDGET_MS) {
        throw error;
      }
      attempt += 1;
      await waitForRetry(delay, signal);
    }
  }

  function copyLegend(legend) {
    return {
      tokenTypes: legend.tokenTypes.slice(),
      tokenModifiers: legend.tokenModifiers.slice(),
    };
  }

  async function getLegend(language, options) {
    var normalized = normalizedLanguage(language);
    if (SUPPORTED_LANGUAGES.indexOf(normalized) === -1) {
      throw new Error("该语言暂不支持结构化高亮");
    }
    if (legendValues[normalized]) return copyLegend(legendValues[normalized]);
    var settings = options || {};

    var payload = await fetchJsonWithBusyRetry(
      "/api/editor/semantic-token-legend?language=" +
        encodeURIComponent(normalized),
      {
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "X-Requested-With": "XMLHttpRequest",
        },
        signal: settings.signal,
        mathCurveLoader: false,
      },
      {
        retryBusy: true,
        signal: settings.signal,
      },
    );
    var legend = payload && payload.legend;
    if (
      !payload ||
      !payload.success ||
      !legend ||
      !Array.isArray(legend.tokenTypes) ||
      !Array.isArray(legend.tokenModifiers)
    ) {
      throw new Error("结构化高亮 legend 格式无效");
    }
    legendValues[normalized] = copyLegend(legend);
    return copyLegend(legendValues[normalized]);
  }

  async function requestTokens(options) {
    var settings = options || {};
    var language = normalizedLanguage(settings.language);
    var problemId = Number(settings.problemId);
    var context = String(settings.context || "");
    var source = settings.source;
    if (
      SUPPORTED_LANGUAGES.indexOf(language) === -1 ||
      typeof source !== "string"
    ) {
      throw new Error("结构化高亮请求参数无效");
    }
    var body = {
      language: language,
      source: source,
    };
    if (context === "markdown" && language === "cpp") {
      body.context = context;
    } else if (Number.isInteger(problemId) && problemId > 0 && !context) {
      body.problem_id = problemId;
    } else {
      throw new Error("结构化高亮请求参数无效");
    }

    var payload = await fetchJsonWithBusyRetry(
      "/api/editor/semantic-tokens",
      {
        method: "POST",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "X-Requested-With": "XMLHttpRequest",
        },
        body: JSON.stringify(body),
        signal: settings.signal,
        mathCurveLoader: false,
      },
      {
        retryBusy: context === "markdown",
        signal: settings.signal,
      },
    );
    if (
      !payload ||
      !payload.success ||
      !Array.isArray(payload.data) ||
      payload.data.length % 5 !== 0
    ) {
      throw new Error("结构化高亮 token 数据格式无效");
    }
    return payload;
  }

  async function register(monaco, options) {
    var settings = options || {};
    var language = normalizedLanguage(settings.language);
    var monacoLanguage = String(settings.monacoLanguage || language).toLowerCase();
    var problemId = Number(settings.problemId);

    if (
      !monaco ||
      !monaco.languages ||
      SUPPORTED_LANGUAGES.indexOf(language) === -1 ||
      !Number.isInteger(problemId) ||
      problemId <= 0
    ) {
      return null;
    }

    var legend = await getLegend(language);

    var warned = false;
    return monaco.languages.registerDocumentSemanticTokensProvider(
      monacoLanguage,
      {
        getLegend: function () {
          return legend;
        },
        provideDocumentSemanticTokens: async function (
          model,
          _lastResultId,
          cancellationToken
        ) {
          var controller = new AbortController();
          var cancellation = cancellationToken.onCancellationRequested(
            function () {
              controller.abort();
            }
          );
          if (typeof settings.onRequestStart === "function") {
            settings.onRequestStart();
          }
          try {
            var payload = await requestTokens({
              problemId: problemId,
              language: language,
              source: model.getValue(),
              signal: controller.signal,
            });

            warned = false;
            return {
              data: new Uint32Array(payload.data),
              resultId: String(payload.result_id || ""),
            };
          } catch (error) {
            if (error && error.name === "AbortError") {
              return null;
            }
            if (!warned) {
              console.warn("结构化高亮失败，已保留 TextMate 着色。", error);
              warned = true;
            }
            return { data: new Uint32Array(0) };
          } finally {
            cancellation.dispose();
            if (typeof settings.onRequestEnd === "function") {
              settings.onRequestEnd();
            }
          }
        },
        releaseDocumentSemanticTokens: function () {},
      }
    );
  }

  window.NumOJSemanticTokens = Object.freeze({
    getLegend: getLegend,
    requestTokens: requestTokens,
    register: register,
  });
})();
