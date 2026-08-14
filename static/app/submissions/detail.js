(function () {
  "use strict";

  var textarea = document.getElementById("submissionCode");
  var shell = document.getElementById("submissionEditorShell");
  var loading = document.getElementById("submissionEditorLoading");
  var semanticLoading = document.getElementById(
    "submissionSemanticLoading"
  );
  var monacoHost = document.getElementById("submissionMonacoContainer");
  var language = String(
    (monacoHost && monacoHost.dataset.language) || "matlab"
  ).toLowerCase();
  var runtime = window.NumOJCodeEditorRuntime;
  var languageSpec = runtime
    ? runtime.forLanguage(language)
    : {
        monacoLanguage:
          language === "py"
            ? "python"
            : language === "octave"
              ? "matlab"
              : language,
      };
  var monacoLanguage = languageSpec.monacoLanguage;
  var problemId = Number(monacoHost && monacoHost.dataset.problemId);
  var semanticRequestsInFlight = 0;

  function updateSemanticLoading(delta) {
    semanticRequestsInFlight = Math.max(
      0,
      semanticRequestsInFlight + Number(delta || 0)
    );
    if (semanticLoading) {
      semanticLoading.hidden = semanticRequestsInFlight === 0;
    }
  }

  function revealEditor() {
    if (loading) loading.hidden = true;
    if (shell) {
      shell.dataset.editorState = "ready";
      shell.setAttribute("aria-busy", "false");
    }
  }

  function revealFallback() {
    if (monacoHost) monacoHost.hidden = true;
    if (textarea) textarea.hidden = false;
    revealEditor();
  }

  async function createMonacoEditor() {
    var monaco = window.NumericalOJMonaco;
    if (!textarea || !monacoHost || !monaco || !monaco.editor) {
      return null;
    }

    var editorTheme = runtime
      ? await runtime.prepareMonaco(monaco)
      : "vs-dark";
    window.NumOJSemanticTokens.register(monaco, {
        language: language,
        monacoLanguage: monacoLanguage,
        problemId: problemId,
        onRequestStart: function () {
          updateSemanticLoading(1);
        },
        onRequestEnd: function () {
          updateSemanticLoading(-1);
        },
      }).catch(function (error) {
      console.warn("语言服务初始化失败，已保留 TextMate 着色。", error);
      });

    monacoHost.hidden = false;
    textarea.hidden = true;
    var instance = monaco.editor.create(monacoHost, runtime
      ? runtime.monacoOptions({
          value: textarea.value,
          language: monacoLanguage,
          theme: editorTheme,
          readOnly: true,
          domReadOnly: true,
          ariaLabel: "提交代码，只读",
          renderValidationDecorations: "on"
        })
      : {
      value: textarea.value,
      language: monacoLanguage,
      theme: editorTheme,
      readOnly: true,
      domReadOnly: true,
      "semanticHighlighting.enabled": true,
      automaticLayout: true,
      ariaLabel: "提交代码，只读",
      fontFamily:
        "SFMono-Regular, Consolas, Liberation Mono, Menlo, monospace",
      fontSize: 14,
      lineHeight: 22,
      lineNumbersMinChars: 3,
      minimap: { enabled: false },
      padding: { top: 14, bottom: 14 },
      roundedSelection: false,
      scrollBeyondLastLine: false,
      smoothScrolling: true,
      tabSize: 4,
      detectIndentation: false,
      wordWrap: "on",
      bracketPairColorization: { enabled: true },
      guides: { bracketPairs: true, indentation: true },
      contextmenu: true,
      renderValidationDecorations: "on",
      find: { addExtraSpaceOnTop: false },
    });

    window.requestAnimationFrame(function () {
      instance.layout();
      window.requestAnimationFrame(revealEditor);
    });

    return {
      kind: "monaco",
      getValue: function () {
        return instance.getValue();
      },
      setValue: function (value) {
        instance.setValue(String(value || ""));
      },
      refresh: function () {
        instance.layout();
      },
      getWrapperElement: function () {
        return monacoHost;
      },
      markText: function (from, to, options) {
        var reason = String((options && options.title) || "这里可能有问题");
        var collection = instance.createDecorationsCollection([{
          range: new monaco.Range(
            Number(from.line || 0) + 1,
            Number(from.ch || 0) + 1,
            Number(to.line || 0) + 1,
            Number(to.ch || 0) + 1
          ),
          options: {
            inlineClassName: "monaco-ai-issue-underline",
            hoverMessage: {
              value: reason,
              isTrusted: false,
              supportHtml: false,
            },
          },
        }]);
        return {
          clear: function () {
            collection.clear();
          },
        };
      },
    };
  }

  async function initializeEditor() {
    if (!textarea) return null;
    var ready = window.NumOJMonacoReady;
    if (ready) {
      try {
        await ready;
      } catch (_error) {
        // 下面统一降级。
      }
    }

    try {
      var editor = await createMonacoEditor();
      if (editor) {
        window.submissionCodeEditor = editor;
        return editor;
      }
    } catch (error) {
      console.error("提交代码编辑器初始化失败，已降级到文本框。", error);
    }

    revealFallback();
    var fallback = {
      kind: "textarea",
      getValue: function () {
        return textarea.value;
      },
      setValue: function (value) {
        textarea.value = String(value || "");
      },
      refresh: function () {},
      getWrapperElement: function () {
        return textarea;
      },
      markText: function () {
        return { clear: function () {} };
      },
    };
    window.submissionCodeEditor = fallback;
    return fallback;
  }

  window.submissionCodeEditor = null;
  window.SubmissionDetailEditorReady = initializeEditor();

  var rejudgeButton = document.getElementById("rejudgeSubmissionBtn");
  var rejudgeFeedback = document.getElementById("rejudgeSubmissionFeedback");
  if (rejudgeButton) {
    var defaultRejudgeHtml = rejudgeButton.innerHTML;
    rejudgeButton.addEventListener("click", function () {
      var endpoint = rejudgeButton.dataset.rejudgeUrl;
      if (!endpoint || !window.confirm("确认重测这条提交吗？")) return;

      rejudgeButton.disabled = true;
      rejudgeButton.innerHTML = window.MathCurveLoader
        ? window.MathCurveLoader.markup("正在提交重测…", "xs")
        : "正在提交重测…";
      if (rejudgeFeedback) {
        rejudgeFeedback.className = "submission-action-feedback";
        rejudgeFeedback.textContent = "";
      }

      fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        mathCurveLoader: false,
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
          if (rejudgeFeedback) {
            rejudgeFeedback.className =
              "submission-action-feedback is-success";
            rejudgeFeedback.textContent = "已加入重测队列";
          }
          rejudgeButton.innerHTML = defaultRejudgeHtml;
        })
        .catch(function (error) {
          rejudgeButton.disabled = false;
          rejudgeButton.innerHTML = defaultRejudgeHtml;
          if (rejudgeFeedback) {
            rejudgeFeedback.className =
              "submission-action-feedback is-error";
            rejudgeFeedback.textContent =
              "重测失败：" + (error.message || "请稍后重试");
          }
        });
    });
  }
})();
