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
  var leanWorkspaceElement = document.getElementById(
    "submissionLeanWorkspaceData"
  );
  var leanFileTree = document.getElementById("submissionLeanFileTree");
  var leanActiveFile = document.getElementById("submissionLeanActiveFile");
  var leanFileMode = document.getElementById("submissionLeanFileMode");
  var leanWorkspace = readLeanWorkspace();
  var leanStates = new Map();
  var activeLeanPath = leanWorkspace ? leanWorkspace.defaultFile : "";
  var semanticRequestsInFlight = 0;

  if (leanWorkspace) {
    leanWorkspace.files.forEach(function (file) {
      leanStates.set(file.path, {
        path: file.path,
        mode: file.mode,
        content: file.content,
        model: null,
        viewState: null,
        treeRow: null,
      });
    });
  }

  function readLeanWorkspace() {
    if (!leanWorkspaceElement) return null;
    var parsed;
    try {
      parsed = JSON.parse(leanWorkspaceElement.textContent || "null");
    } catch (_error) {
      return null;
    }
    if (!parsed || !Array.isArray(parsed.files) || !parsed.files.length) {
      return null;
    }
    var files = parsed.files.map(function (file) {
      return {
        path: String(file.path || ""),
        mode: file.mode === "readonly" ? "readonly" : "writable",
        content: String(file.content || ""),
      };
    }).filter(function (file) {
      return file.path;
    });
    if (!files.length) return null;
    var requestedDefault = String(parsed.default_file || "");
    var defaultFile = files.some(function (file) {
      return file.path === requestedDefault;
    }) ? requestedDefault : files[0].path;
    return {
      revision: String(parsed.revision || ""),
      submissionId: Number(parsed.submission_id || 0),
      defaultFile: defaultFile,
      files: files,
    };
  }

  function updateLeanFileChrome() {
    if (!leanWorkspace) return;
    var state = leanStates.get(activeLeanPath);
    if (!state) return;
    if (leanActiveFile) {
      leanActiveFile.textContent = state.path;
      leanActiveFile.title = state.path;
    }
    if (leanFileMode) {
      var readonly = state.mode === "readonly";
      leanFileMode.textContent = readonly ? "题目只读" : "学生提交";
      leanFileMode.classList.toggle("is-readonly", readonly);
    }
    leanStates.forEach(function (fileState) {
      if (!fileState.treeRow) return;
      var active = fileState.path === activeLeanPath;
      fileState.treeRow.classList.toggle("is-active", active);
      fileState.treeRow.setAttribute("aria-current", active ? "true" : "false");
    });
  }

  function createLeanTreeRow(label, kind, state) {
    var row = document.createElement("button");
    row.type = "button";
    row.className = "lean-file-tree-row";
    row.setAttribute("role", "treeitem");
    var chevron = document.createElement("span");
    chevron.className = "lean-file-tree-chevron";
    chevron.textContent = kind === "folder" ? "▾" : "";
    chevron.setAttribute("aria-hidden", "true");
    var icon = document.createElement("i");
    icon.className = "lean-file-tree-icon fas " + (
      kind === "folder" ? "fa-folder" :
        state.mode === "readonly" ? "fa-lock" : "fa-pen"
    );
    icon.setAttribute("aria-hidden", "true");
    var name = document.createElement("span");
    name.className = "lean-file-tree-label";
    name.textContent = label;
    row.append(chevron, icon, name);
    if (state) {
      row.classList.add(state.mode === "readonly" ? "is-readonly" : "is-writable");
      row.title = state.path + (
        state.mode === "readonly" ? "（题目只读文件）" : "（学生提交文件）"
      );
      state.treeRow = row;
    }
    return row;
  }

  function renderLeanFileTree(onSelect) {
    if (!leanWorkspace || !leanFileTree) return;
    var rootNode = { folders: new Map(), files: [] };
    leanWorkspace.files.forEach(function (file) {
      var parts = file.path.split("/");
      var node = rootNode;
      parts.slice(0, -1).forEach(function (part) {
        if (!node.folders.has(part)) {
          node.folders.set(part, { folders: new Map(), files: [] });
        }
        node = node.folders.get(part);
      });
      node.files.push({
        name: parts[parts.length - 1],
        state: leanStates.get(file.path),
      });
    });

    function renderNode(node) {
      var list = document.createElement("ul");
      list.className = "lean-file-tree-list";
      list.setAttribute("role", "group");
      Array.from(node.folders.keys()).sort().forEach(function (folderName) {
        var item = document.createElement("li");
        var row = createLeanTreeRow(folderName, "folder", null);
        var child = renderNode(node.folders.get(folderName));
        row.setAttribute("aria-expanded", "true");
        row.addEventListener("click", function () {
          var expanded = row.getAttribute("aria-expanded") !== "false";
          row.setAttribute("aria-expanded", expanded ? "false" : "true");
          child.hidden = expanded;
        });
        item.append(row, child);
        list.appendChild(item);
      });
      node.files.sort(function (left, right) {
        return left.name.localeCompare(right.name);
      }).forEach(function (file) {
        var item = document.createElement("li");
        var row = createLeanTreeRow(file.name, "file", file.state);
        row.addEventListener("click", function () {
          onSelect(file.state.path);
        });
        item.appendChild(row);
        list.appendChild(item);
      });
      return list;
    }

    leanFileTree.replaceChildren(renderNode(rootNode));
    updateLeanFileChrome();
  }

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
    var editorDocument = {
      value: textarea.value,
      language: monacoLanguage,
    };
    if (leanWorkspace) {
      leanWorkspace.files.forEach(function (file) {
        var state = leanStates.get(file.path);
        var encodedPath = file.path.split("/").map(encodeURIComponent).join("/");
        state.model = monaco.editor.createModel(
          file.content,
          "lean4",
          monaco.Uri.parse(
            "file:///workspace/submission-" +
              (leanWorkspace.submissionId || problemId) + "/" + encodedPath
          )
        );
      });
      editorDocument = { model: leanStates.get(activeLeanPath).model };
    }
    var commonOptions = Object.assign({}, editorDocument, {
      theme: editorTheme,
      readOnly: true,
      domReadOnly: true,
      ariaLabel: leanWorkspace ? "Lean 4 提交文件，只读" : "提交代码，只读",
      tabSize: leanWorkspace ? 2 : 4,
      renderValidationDecorations: "on",
    });
    var instance = monaco.editor.create(monacoHost, runtime
      ? runtime.monacoOptions(commonOptions)
      : Object.assign({
      "semanticHighlighting.enabled": true,
      automaticLayout: true,
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
      find: { addExtraSpaceOnTop: false },
    }, commonOptions));

    function switchLeanFile(path) {
      var next = leanStates.get(path);
      if (!next || !next.model) return;
      var previous = leanStates.get(activeLeanPath);
      if (previous && previous.path !== next.path) {
        previous.viewState = instance.saveViewState();
      }
      activeLeanPath = next.path;
      if (instance.getModel() !== next.model) instance.setModel(next.model);
      if (next.viewState) instance.restoreViewState(next.viewState);
      instance.updateOptions({
        readOnly: true,
        domReadOnly: true,
        ariaLabel: "Lean 4 提交文件 " + next.path + "，只读",
      });
      instance.layout();
      updateLeanFileChrome();
    }

    if (leanWorkspace) {
      renderLeanFileTree(switchLeanFile);
      switchLeanFile(activeLeanPath);
    }

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
        var text = String(value || "");
        if (!leanWorkspace) {
          instance.setValue(text);
          return;
        }
        if (activeLeanPath !== leanWorkspace.defaultFile &&
            text === instance.getValue()) {
          return;
        }
        switchLeanFile(leanWorkspace.defaultFile);
        if (instance.getValue() !== text) instance.setValue(text);
      },
      refresh: function () {
        instance.layout();
      },
      getWrapperElement: function () {
        return monacoHost;
      },
      switchFile: switchLeanFile,
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
    function switchFallbackLeanFile(path) {
      var state = leanStates.get(path);
      if (!state) return;
      activeLeanPath = state.path;
      textarea.value = state.content;
      textarea.setAttribute(
        "aria-label",
        "Lean 4 提交文件 " + state.path + "，只读"
      );
      updateLeanFileChrome();
    }
    if (leanWorkspace) {
      renderLeanFileTree(switchFallbackLeanFile);
      switchFallbackLeanFile(activeLeanPath);
    }
    var fallback = {
      kind: "textarea",
      getValue: function () {
        return textarea.value;
      },
      setValue: function (value) {
        var text = String(value || "");
        if (!leanWorkspace) {
          textarea.value = text;
          return;
        }
        if (activeLeanPath !== leanWorkspace.defaultFile &&
            text === textarea.value) {
          return;
        }
        var state = leanStates.get(leanWorkspace.defaultFile);
        state.content = text;
        switchFallbackLeanFile(state.path);
      },
      refresh: function () {},
      getWrapperElement: function () {
        return textarea;
      },
      switchFile: switchFallbackLeanFile,
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
