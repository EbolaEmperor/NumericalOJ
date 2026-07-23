(function () {
  "use strict";

  var SUPPORTED_LANGUAGES = ["c", "cpp", "py", "python", "matlab", "octave"];

  async function register(monaco, options) {
    var settings = options || {};
    var language = String(settings.language || "").toLowerCase();
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

    var legendResponse = await fetch(
      "/api/editor/semantic-token-legend?language=" +
        encodeURIComponent(language),
      {
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "X-Requested-With": "XMLHttpRequest",
        },
        mathCurveLoader: false,
      }
    );
    if (!legendResponse.ok) {
      throw new Error("结构化高亮 legend 不可用");
    }

    var legendPayload = await legendResponse.json();
    var legend = legendPayload && legendPayload.legend;
    if (
      !legendPayload ||
      !legendPayload.success ||
      !legend ||
      !Array.isArray(legend.tokenTypes) ||
      !Array.isArray(legend.tokenModifiers)
    ) {
      throw new Error("结构化高亮 legend 格式无效");
    }

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
            var response = await fetch("/api/editor/semantic-tokens", {
              method: "POST",
              credentials: "same-origin",
              headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
                "X-Requested-With": "XMLHttpRequest",
              },
              body: JSON.stringify({
                problem_id: problemId,
                language: language,
                source: model.getValue(),
              }),
              signal: controller.signal,
              mathCurveLoader: false,
            });
            if (!response.ok) {
              throw new Error("语言服务返回 " + response.status);
            }

            var payload = await response.json();
            if (
              !payload ||
              !payload.success ||
              !Array.isArray(payload.data) ||
              payload.data.length % 5 !== 0
            ) {
              throw new Error("结构化高亮 token 数据格式无效");
            }

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
    register: register,
  });
})();
