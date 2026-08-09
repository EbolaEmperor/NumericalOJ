(function () {
  "use strict";

  if (window.NumOJSemanticTokens) return;

  var SUPPORTED_LANGUAGES = ["c", "cpp", "py", "python", "matlab", "octave"];
  var MARKDOWN_LANGUAGE_ALIASES = {
    c: "c",
    cpp: "cpp",
    py: "python",
    python: "python",
    matlab: "matlab",
    octave: "matlab",
  };
  var EDITOR_CONTEXTS = {
    repository: true,
    "problem-form": true,
    "agent-workspace": true,
  };
  var RETRYABLE_BUSY_CODES = {
    legend_pending: true,
    repository_changed: true,
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
    var documentId = String(settings.documentId || "");
    var repositoryEntryId = Number(settings.repositoryEntryId);
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
    var markdownLanguage = MARKDOWN_LANGUAGE_ALIASES[language];
    if (context === "markdown" && markdownLanguage) {
      body.language = markdownLanguage;
      body.context = context;
    } else if (
      context === "repository" &&
      Number.isInteger(repositoryEntryId) &&
      repositoryEntryId > 0
    ) {
      body.context = "repository";
      body.repository_entry_id = repositoryEntryId;
    } else if (EDITOR_CONTEXTS[context] && context !== "repository" && documentId) {
      body.context = context;
      body.document_id = documentId;
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
        retryBusy: true,
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
    var context = String(settings.context || "");
    var genericEditor = !!EDITOR_CONTEXTS[context];
    var hasGenericDocumentId =
      typeof settings.documentId === "function" ||
      !!String(settings.documentId || "");
    var hasRepositoryEntryId =
      typeof settings.repositoryEntryId === "function" ||
      (
        Number.isInteger(Number(settings.repositoryEntryId)) &&
        Number(settings.repositoryEntryId) > 0
      );
    var hasContextIdentity = context === "repository"
      ? hasRepositoryEntryId
      : hasGenericDocumentId;

    if (
      !monaco ||
      !monaco.languages ||
      SUPPORTED_LANGUAGES.indexOf(language) === -1 ||
      !(
        (Number.isInteger(problemId) && problemId > 0 && !context) ||
        (genericEditor && hasContextIdentity)
      )
    ) {
      return null;
    }

    var legend = await getLegend(language);

    var warned = false;
    var disposed = false;
    var requestSerial = 0;
    var resultSerial = 0;
    var modelStates = new WeakMap();
    var trackedModels = new Set();
    var resultModels = new Map();
    var activeControllers = new Set();
    var supportsInactiveRegions = language === "c" || language === "cpp";

    function stateForModel(model) {
      var state = modelStates.get(model);
      if (!state) {
        state = {
          decorationIds: [],
          disposeListener: null,
          requestVersion: 0,
          resultId: "",
        };
        modelStates.set(model, state);
        trackedModels.add(model);
        if (model && typeof model.onWillDispose === "function") {
          state.disposeListener = model.onWillDispose(function () {
            state.requestVersion += 1;
            clearInactiveRegions(model, state);
            if (state.resultId) resultModels.delete(state.resultId);
            state.resultId = "";
            trackedModels.delete(model);
            modelStates.delete(model);
            var listener = state.disposeListener;
            state.disposeListener = null;
            if (listener && typeof listener.dispose === "function") {
              listener.dispose();
            }
          });
        }
      }
      return state;
    }

    function clearInactiveRegions(model, state) {
      var current = state || modelStates.get(model);
      if (!current) return;
      var modelDisposed = (
        model &&
        typeof model.isDisposed === "function" &&
        model.isDisposed()
      );
      if (
        current.decorationIds.length &&
        model &&
        typeof model.deltaDecorations === "function" &&
        !modelDisposed
      ) {
        try {
          current.decorationIds = model.deltaDecorations(
            current.decorationIds,
            []
          );
        } catch (_error) {
          current.decorationIds = [];
        }
      } else {
        current.decorationIds = [];
      }
    }

    function inactiveRegionRanges(model, regions) {
      var ranges = regions.reduce(function (values, region) {
        var start = region && region.start;
        var end = region && region.end;
        if (
          !start ||
          !end ||
          !Number.isInteger(start.line) ||
          !Number.isInteger(start.character) ||
          !Number.isInteger(end.line) ||
          !Number.isInteger(end.character) ||
          start.line < 0 ||
          start.character < 0 ||
          end.line < start.line ||
          end.character < 0 ||
          (
            end.line === start.line &&
            end.character < start.character
          )
        ) {
          return values;
        }
        var range = new monaco.Range(
          start.line + 1,
          start.character + 1,
          end.line + 1,
          end.character + 1
        );
        if (typeof model.validateRange === "function") {
          try {
            range = model.validateRange(range);
          } catch (_error) {
            return values;
          }
        }
        if (
          range.endLineNumber < range.startLineNumber ||
          (
            range.endLineNumber === range.startLineNumber &&
            range.endColumn <= range.startColumn
          )
        ) {
          return values;
        }
        values.push(range);
        return values;
      }, []);
      ranges.sort(function (left, right) {
        return (
          left.startLineNumber - right.startLineNumber ||
          left.startColumn - right.startColumn ||
          left.endLineNumber - right.endLineNumber ||
          left.endColumn - right.endColumn
        );
      });
      return ranges.reduce(function (merged, range) {
        var previous = merged[merged.length - 1];
        var overlaps = previous && (
          range.startLineNumber < previous.endLineNumber ||
          (
            range.startLineNumber === previous.endLineNumber &&
            range.startColumn <= previous.endColumn
          )
        );
        if (!overlaps) {
          merged.push(range);
          return merged;
        }
        var rangeEndsLater = (
          range.endLineNumber > previous.endLineNumber ||
          (
            range.endLineNumber === previous.endLineNumber &&
            range.endColumn > previous.endColumn
          )
        );
        if (rangeEndsLater) {
          merged[merged.length - 1] = new monaco.Range(
            previous.startLineNumber,
            previous.startColumn,
            range.endLineNumber,
            range.endColumn
          );
        }
        return merged;
      }, []);
    }

    function inactiveRegionDecorations(model, regions) {
      return inactiveRegionRanges(model, regions).map(function (range) {
        return {
          range: range,
          options: {
            description: "numoj-clangd-inactive-code",
            isWholeLine: true,
            inlineClassName: "numoj-clangd-inactive-code",
            inlineClassNameAffectsLetterSpacing: false,
          },
        };
      });
    }

    function applyInactiveRegions(model, state, regions) {
      if (
        !supportsInactiveRegions ||
        !model ||
        typeof model.deltaDecorations !== "function" ||
        (
          typeof model.isDisposed === "function" &&
          model.isDisposed()
        )
      ) {
        return;
      }
      try {
        state.decorationIds = model.deltaDecorations(
          state.decorationIds,
          inactiveRegionDecorations(model, regions)
        );
      } catch (_error) {
        state.decorationIds = [];
      }
    }

    function rememberResult(model, state, backendResultId) {
      resultSerial += 1;
      var resultId =
        String(backendResultId || "") + ":numoj-" + String(resultSerial);
      if (state.resultId) resultModels.delete(state.resultId);
      state.resultId = resultId;
      resultModels.set(resultId, { model: model, state: state });
      return resultId;
    }

    var registration = monaco.languages.registerDocumentSemanticTokensProvider(
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
          var state = stateForModel(model);
          requestSerial += 1;
          var requestVersion = requestSerial;
          state.requestVersion = requestVersion;
          var controller = new AbortController();
          activeControllers.add(controller);
          var cancellation = cancellationToken.onCancellationRequested(
            function () {
              controller.abort();
            }
          );
          if (typeof settings.onRequestStart === "function") {
            settings.onRequestStart();
          }
          try {
            var configuredDocumentId =
              typeof settings.documentId === "function"
                ? settings.documentId(model)
                : settings.documentId;
            var configuredRepositoryEntryId =
              typeof settings.repositoryEntryId === "function"
                ? settings.repositoryEntryId(model)
                : settings.repositoryEntryId;
            var payload = await requestTokens({
              problemId: problemId,
              context: context,
              documentId: configuredDocumentId,
              repositoryEntryId: configuredRepositoryEntryId,
              language: language,
              source: model.getValue(),
              signal: controller.signal,
            });

            if (
              disposed ||
              controller.signal.aborted ||
              state.requestVersion !== requestVersion
            ) {
              return null;
            }
            if (supportsInactiveRegions) {
              applyInactiveRegions(
                model,
                state,
                Array.isArray(payload.inactive_regions)
                  ? payload.inactive_regions
                  : []
              );
            }

            warned = false;
            return {
              data: new Uint32Array(payload.data),
              resultId: rememberResult(model, state, payload.result_id),
            };
          } catch (error) {
            if (
              !disposed &&
              state.requestVersion === requestVersion &&
              supportsInactiveRegions
            ) {
              clearInactiveRegions(model, state);
            }
            if (error && error.name === "AbortError") {
              return null;
            }
            if (!warned) {
              console.warn("结构化高亮失败，已保留 TextMate 着色。", error);
              warned = true;
            }
            return { data: new Uint32Array(0) };
          } finally {
            activeControllers.delete(controller);
            cancellation.dispose();
            if (typeof settings.onRequestEnd === "function") {
              settings.onRequestEnd();
            }
          }
        },
        releaseDocumentSemanticTokens: function (resultId) {
          var record = resultModels.get(resultId);
          resultModels.delete(resultId);
          if (!record || record.state.resultId !== resultId) return;
          clearInactiveRegions(record.model, record.state);
          record.state.resultId = "";
        },
      }
    );

    return {
      dispose: function () {
        if (disposed) return;
        disposed = true;
        activeControllers.forEach(function (controller) {
          controller.abort();
        });
        activeControllers.clear();
        trackedModels.forEach(function (model) {
          var state = modelStates.get(model);
          if (state) {
            state.requestVersion += 1;
            clearInactiveRegions(model, state);
            if (state.resultId) resultModels.delete(state.resultId);
            state.resultId = "";
            var listener = state.disposeListener;
            state.disposeListener = null;
            if (listener && typeof listener.dispose === "function") {
              listener.dispose();
            }
            modelStates.delete(model);
          }
        });
        trackedModels.clear();
        resultModels.clear();
        registration.dispose();
      },
    };
  }

  window.NumOJSemanticTokens = Object.freeze({
    getLegend: getLegend,
    requestTokens: requestTokens,
    register: register,
  });
})();
