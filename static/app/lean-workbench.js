(function () {
  "use strict";

  if (window.NumOJLeanWorkbench) return;

  var SOURCE_DEBOUNCE_MS = 700;
  var CURSOR_DEBOUNCE_MS = 160;
  var symbolProviderRegistered = false;
  var LEAN_SYMBOLS = {
    "\\all": "∀",
    "\\forall": "∀",
    "\\ex": "∃",
    "\\exists": "∃",
    "\\fun": "λ",
    "\\lambda": "λ",
    "\\to": "→",
    "\\r": "→",
    "\\l": "←",
    "\\lr": "↔",
    "\\iff": "↔",
    "\\and": "∧",
    "\\or": "∨",
    "\\not": "¬",
    "\\ne": "≠",
    "\\le": "≤",
    "\\ge": "≥",
    "\\in": "∈",
    "\\nin": "∉",
    "\\sub": "⊆",
    "\\ssub": "⊂",
    "\\cup": "∪",
    "\\cap": "∩",
    "\\empty": "∅",
    "\\comp": "∘",
    "\\times": "×",
    "\\vdash": "⊢",
    "\\alpha": "α",
    "\\beta": "β",
    "\\gamma": "γ",
    "\\delta": "δ",
    "\\epsilon": "ε",
    "\\eta": "η",
    "\\theta": "θ",
    "\\iota": "ι",
    "\\kappa": "κ",
    "\\mu": "μ",
    "\\nu": "ν",
    "\\xi": "ξ",
    "\\pi": "π",
    "\\rho": "ρ",
    "\\sigma": "σ",
    "\\tau": "τ",
    "\\phi": "φ",
    "\\chi": "χ",
    "\\psi": "ψ",
    "\\omega": "ω",
    "\\Gamma": "Γ",
    "\\Delta": "Δ",
    "\\Theta": "Θ",
    "\\Lambda": "Λ",
    "\\Xi": "Ξ",
    "\\Pi": "Π",
    "\\Sigma": "Σ",
    "\\Phi": "Φ",
    "\\Psi": "Ψ",
    "\\Omega": "Ω"
  };

  function registerSymbolCompletions(monaco) {
    if (symbolProviderRegistered || !monaco || !monaco.languages) return;
    symbolProviderRegistered = true;
    var officialSymbols = typeof monaco.getLean4UnicodeAbbreviations === "function"
      ? monaco.getLean4UnicodeAbbreviations()
      : null;
    var symbols = officialSymbols
      ? Object.keys(officialSymbols).reduce(function (result, abbreviation) {
          result["\\" + abbreviation] = officialSymbols[abbreviation];
          return result;
        }, {})
      : LEAN_SYMBOLS;
    monaco.languages.registerCompletionItemProvider("lean4", {
      triggerCharacters: ["\\"],
      provideCompletionItems: function (model, position) {
        var before = model.getLineContent(position.lineNumber).slice(
          0,
          position.column - 1
        );
        var match = before.match(/\\[^\\\s]*$/);
        if (!match) return { suggestions: [] };
        var typed = match[0];
        var startColumn = position.column - typed.length;
        var suggestions = Object.keys(symbols)
          .filter(function (command) {
            return command.indexOf(typed) === 0;
          })
          .map(function (command) {
            var replacement = String(symbols[command]);
            var usesCursor = replacement.indexOf("$CURSOR") !== -1;
            return {
              label: command + "  " + replacement.replace("$CURSOR", "▏"),
              filterText: command,
              insertText: usesCursor
                ? replacement.replace("$CURSOR", "$0")
                : replacement,
              insertTextRules: usesCursor
                ? monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet
                : undefined,
              detail: "Lean Unicode abbreviation",
              kind: monaco.languages.CompletionItemKind.Text,
              range: new monaco.Range(
                position.lineNumber,
                startColumn,
                position.lineNumber,
                position.column
              )
            };
          });
        return { suggestions: suggestions };
      }
    });
  }

  function severityName(value) {
    if (typeof value === "number") {
      return ["", "error", "warning", "info", "hint"][value] || "info";
    }
    var normalized = String(value || "error").toLowerCase();
    return normalized === "information" ? "info" : normalized;
  }

  function point(value) {
    return {
      line: Math.max(0, Number(value && value.line) || 0),
      character: Math.max(0, Number(value && value.character) || 0)
    };
  }

  function diagnosticRange(diagnostic) {
    var range = diagnostic && diagnostic.range || {};
    var start = point(range.start);
    var end = point(range.end || range.start);
    if (end.line < start.line || (
      end.line === start.line && end.character <= start.character
    )) {
      end = { line: start.line, character: start.character + 1 };
    }
    return { start: start, end: end };
  }

  function markerSeverity(monaco, severity) {
    if (severity === "warning") return monaco.MarkerSeverity.Warning;
    if (severity === "info") return monaco.MarkerSeverity.Info;
    if (severity === "hint") return monaco.MarkerSeverity.Hint;
    return monaco.MarkerSeverity.Error;
  }

  function appendCodeBlock(parent, className, text) {
    var block = document.createElement("pre");
    block.className = className;
    block.textContent = String(text || "");
    parent.appendChild(block);
  }

  function createSemanticTokenBridge(monaco, model) {
    var registration = null;
    var legend = null;
    var legendSignature = "";
    var cachedData = new Uint32Array(0);
    var cachedVersion = 0;
    var cachedResultId = "";
    var generation = 0;
    var hasCachedData = false;
    var listeners = new Set();
    var disposed = false;

    function subscribe(listener) {
      listeners.add(listener);
      return {
        dispose: function () {
          listeners.delete(listener);
        }
      };
    }

    function fireChange() {
      listeners.forEach(function (listener) {
        listener();
      });
    }

    function registerProvider(rawLegend, signature) {
      legend = {
        tokenTypes: rawLegend.tokenTypes.map(function (tokenType) {
          return "lean4." + tokenType;
        }),
        tokenModifiers: rawLegend.tokenModifiers.slice()
      };
      legendSignature = signature;
      registration = monaco.languages.registerDocumentSemanticTokensProvider(
        "lean4",
        {
          onDidChange: subscribe,
          getLegend: function () {
            return legend;
          },
          provideDocumentSemanticTokens: function (
            requestedModel,
            _lastResultId,
            cancellationToken
          ) {
            if (
              disposed ||
              requestedModel !== model ||
              (cancellationToken && cancellationToken.isCancellationRequested)
            ) {
              return null;
            }
            if (!hasCachedData || cachedVersion !== model.getVersionId()) {
              return { data: new Uint32Array(0) };
            }
            return {
              data: new Uint32Array(cachedData),
              resultId: "lean4:" + cachedVersion + ":" + generation
            };
          },
          releaseDocumentSemanticTokens: function () {}
        }
      );
    }

    function accept(version, payload) {
      var rawLegend = payload && payload.legend;
      var rawData = payload && payload.data;
      if (
        disposed ||
        version !== model.getVersionId() ||
        !rawLegend ||
        !Array.isArray(rawLegend.tokenTypes) ||
        !rawLegend.tokenTypes.length ||
        !rawLegend.tokenTypes.every(function (item) {
          return typeof item === "string";
        }) ||
        !Array.isArray(rawLegend.tokenModifiers) ||
        !rawLegend.tokenModifiers.every(function (item) {
          return typeof item === "string";
        }) ||
        !Array.isArray(rawData) ||
        rawData.length % 5 !== 0 ||
        !rawData.every(function (item) {
          return Number.isInteger(item) && item >= 0;
        })
      ) {
        return false;
      }

      var signature = JSON.stringify(rawLegend);
      var resultId = String(payload.result_id || "");
      if (
        registration &&
        cachedVersion === version &&
        cachedResultId === resultId &&
        legendSignature === signature
      ) {
        return true;
      }

      cachedData = Uint32Array.from(rawData);
      cachedVersion = version;
      cachedResultId = resultId;
      hasCachedData = true;
      generation += 1;

      if (registration && legendSignature !== signature) {
        registration.dispose();
        registration = null;
      }
      if (!registration) {
        registerProvider(rawLegend, signature);
      } else {
        fireChange();
      }
      return true;
    }

    function invalidate() {
      if (disposed || !hasCachedData) return;
      cachedData = new Uint32Array(0);
      cachedVersion = 0;
      cachedResultId = "";
      hasCachedData = false;
      generation += 1;
      if (registration) fireChange();
    }

    return {
      accept: accept,
      invalidate: invalidate,
      dispose: function () {
        if (disposed) return;
        disposed = true;
        if (registration) registration.dispose();
        registration = null;
        listeners.clear();
      }
    };
  }

  function attach(options) {
    var settings = options || {};
    var root = document.getElementById("leanWorkbench");
    if (!root) return null;

    var monaco = settings.monaco;
    var editor = settings.editor || null;
    var textarea = settings.textarea || document.getElementById("codeEditor");
    var bootstrapModel = editor && editor.getModel ? editor.getModel() : null;
    var checkUrl = root.dataset.checkUrl || "/api/lean/check";
    var problemId = Number(root.dataset.problemId);
    var workspaceElement = document.getElementById("leanWorkspaceData");
    var workspaceInput = document.getElementById("leanWorkspaceInput");
    var fileTree = document.getElementById("leanFileTree");
    var fileCount = document.getElementById("leanFileCount");
    var activeFileName = document.getElementById("leanActiveFileName");
    var activeFileMode = document.getElementById("leanActiveFileMode");
    var status = document.getElementById("leanCheckStatus");
    var statusText = status && status.querySelector("[data-lean-status-text]");
    var cursorLabel = document.getElementById("leanCursorPosition");
    var versionLabel = document.getElementById("leanDocumentVersion");
    var goalCount = document.getElementById("leanGoalCount");
    var problemCount = document.getElementById("leanProblemCount");
    var goalsEmpty = document.getElementById("leanGoalsEmpty");
    var problemsEmpty = document.getElementById("leanProblemsEmpty");
    var goalList = document.getElementById("leanGoalList");
    var problemList = document.getElementById("leanProblemList");
    var problemsTab = document.getElementById("leanProblemsTab");
    var sourceTimer = 0;
    var cursorTimer = 0;
    var requestSerial = 0;
    var activeController = null;
    var requestInFlight = false;
    var queuedCheck = false;
    var sourceChangePending = false;
    var suppressChanges = false;
    var disposed = false;
    var disposables = [];
    var states = new Map();
    var activePath = "";

    function readWorkspace() {
      var parsed = null;
      if (workspaceElement) {
        try {
          parsed = JSON.parse(workspaceElement.textContent || "null");
        } catch (_error) {
          parsed = null;
        }
      }
      var rawFiles = parsed && Array.isArray(parsed.files) ? parsed.files : [];
      if (!rawFiles.length) {
        rawFiles = [{
          path: "Submission.lean",
          mode: "writable",
          content: textarea ? textarea.value : "",
          build_order: 0
        }];
      }
      var files = [];
      var seen = new Set();
      rawFiles.forEach(function (rawFile, index) {
        var path = String(rawFile && rawFile.path || "").trim();
        if (!path || seen.has(path)) return;
        seen.add(path);
        files.push({
          path: path,
          mode: rawFile && rawFile.mode === "readonly" ? "readonly" : "writable",
          content: String(rawFile && rawFile.content || ""),
          buildOrder: Number.isFinite(Number(rawFile && rawFile.build_order))
            ? Number(rawFile.build_order)
            : index
        });
      });
      var requestedDefault = String(parsed && parsed.default_file || "");
      var defaultFile = files.some(function (file) {
        return file.path === requestedDefault;
      }) ? requestedDefault : "";
      if (!defaultFile) {
        var writable = files.find(function (file) {
          return file.mode === "writable";
        });
        defaultFile = (writable || files[0]).path;
      }
      return {
        revision: String(parsed && parsed.revision || ""),
        defaultFile: defaultFile,
        files: files
      };
    }

    var workspace = readWorkspace();
    activePath = workspace.defaultFile;
    registerSymbolCompletions(monaco);

    workspace.files.forEach(function (file) {
      states.set(file.path, {
        path: file.path,
        mode: file.mode,
        originalContent: file.content,
        content: file.content,
        buildOrder: file.buildOrder,
        fallbackVersion: 1,
        model: null,
        semanticTokens: null,
        viewState: null,
        treeRow: null,
        dirtyDot: null,
        errorCount: null
      });
    });

    function currentState() {
      return states.get(activePath) || null;
    }

    function stateValue(state) {
      if (!state) return "";
      return state.model ? state.model.getValue() : state.content;
    }

    function saveFallbackState() {
      var state = currentState();
      if (!editor && textarea && state) state.content = textarea.value;
    }

    function currentVersion() {
      var state = currentState();
      if (!state) return 1;
      return state.model ? state.model.getVersionId() : state.fallbackVersion;
    }

    function currentPosition() {
      if (editor && editor.getPosition) {
        var editorPosition = editor.getPosition();
        if (editorPosition) {
          return {
            line: editorPosition.lineNumber - 1,
            character: editorPosition.column - 1
          };
        }
      }
      if (textarea) {
        var prefix = textarea.value.slice(0, textarea.selectionStart || 0);
        var lines = prefix.split("\n");
        return {
          line: lines.length - 1,
          character: lines[lines.length - 1].length
        };
      }
      return { line: 0, character: 0 };
    }

    function writableFiles() {
      saveFallbackState();
      var files = {};
      workspace.files.forEach(function (file) {
        var state = states.get(file.path);
        if (state.mode === "writable") files[state.path] = stateValue(state);
      });
      return files;
    }

    function submissionPayload() {
      return {
        revision: workspace.revision,
        files: writableFiles()
      };
    }

    function setStatus(state, text) {
      if (!status) return;
      status.dataset.state = state;
      if (statusText) statusText.textContent = text;
    }

    function updateCursorLabel() {
      if (!cursorLabel) return;
      var position = currentPosition();
      cursorLabel.textContent = "Ln " + (position.line + 1) +
        ", Col " + (position.character + 1);
    }

    function updateVersionLabel() {
      if (versionLabel) versionLabel.textContent = "v" + currentVersion();
    }

    function updateFileState(state) {
      if (!state) return;
      var dirty = state.mode === "writable" &&
        stateValue(state) !== state.originalContent;
      if (state.dirtyDot) state.dirtyDot.hidden = !dirty;
      if (state.treeRow) {
        state.treeRow.classList.toggle("is-active", state.path === activePath);
        state.treeRow.setAttribute(
          "aria-current",
          state.path === activePath ? "true" : "false"
        );
      }
    }

    function updateActiveFileChrome() {
      var state = currentState();
      if (!state) return;
      if (activeFileName) {
        activeFileName.textContent = state.path;
        activeFileName.title = state.path;
      }
      if (activeFileMode) {
        var readonly = state.mode === "readonly";
        activeFileMode.textContent = readonly ? "只读" : "可写";
        activeFileMode.classList.toggle("is-readonly", readonly);
      }
      states.forEach(updateFileState);
    }

    function createTreeRow(label, kind, state) {
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
        row.title = state.path + (state.mode === "readonly" ? "（只读）" : "（可写）");
        var dirty = document.createElement("span");
        dirty.className = "lean-file-dirty";
        dirty.hidden = true;
        dirty.title = "有未提交的修改";
        var errors = document.createElement("span");
        errors.className = "lean-file-error-count";
        errors.hidden = true;
        row.append(dirty, errors);
        state.treeRow = row;
        state.dirtyDot = dirty;
        state.errorCount = errors;
      }
      return row;
    }

    function renderFileTree() {
      if (!fileTree) return;
      var rootNode = { folders: new Map(), files: [] };
      workspace.files.forEach(function (file) {
        var parts = file.path.split("/");
        var node = rootNode;
        parts.slice(0, -1).forEach(function (part) {
          if (!node.folders.has(part)) {
            node.folders.set(part, { folders: new Map(), files: [] });
          }
          node = node.folders.get(part);
        });
        node.files.push({ name: parts[parts.length - 1], state: states.get(file.path) });
      });

      function renderNode(node) {
        var list = document.createElement("ul");
        list.className = "lean-file-tree-list";
        list.setAttribute("role", "group");
        Array.from(node.folders.keys()).sort().forEach(function (folderName) {
          var item = document.createElement("li");
          var row = createTreeRow(folderName, "folder", null);
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
          var row = createTreeRow(file.name, "file", file.state);
          row.addEventListener("click", function () {
            switchFile(file.state.path, true);
          });
          item.appendChild(row);
          list.appendChild(item);
        });
        return list;
      }

      var tree = renderNode(rootNode);
      fileTree.replaceChildren(tree);
      if (fileCount) fileCount.textContent = String(workspace.files.length);
      states.forEach(updateFileState);
    }

    function activateTab(name) {
      root.querySelectorAll("[data-lean-tab]").forEach(function (tab) {
        var active = tab.dataset.leanTab === name;
        tab.classList.toggle("is-active", active);
        tab.setAttribute("aria-selected", active ? "true" : "false");
      });
      root.querySelectorAll("[data-lean-panel]").forEach(function (panel) {
        var active = panel.dataset.leanPanel === name;
        panel.classList.toggle("is-active", active);
        panel.hidden = !active;
      });
    }

    root.querySelectorAll("[data-lean-tab]").forEach(function (tab) {
      tab.addEventListener("click", function () {
        activateTab(tab.dataset.leanTab);
      });
    });

    function setEmptyCopy(element, glyph, title, description) {
      if (!element) return;
      var glyphElement = element.querySelector(".lean-empty-glyph");
      var titleElement = element.querySelector("strong");
      var descriptionElement = element.querySelector("span:last-child");
      if (glyphElement) glyphElement.textContent = glyph;
      if (titleElement) titleElement.textContent = title;
      if (descriptionElement) descriptionElement.textContent = description;
    }

    function renderGoals(goals) {
      var items = Array.isArray(goals) ? goals : [];
      goalList.replaceChildren();
      goalCount.textContent = String(items.length);
      goalsEmpty.hidden = items.length > 0;
      if (!items.length) {
        setEmptyCopy(
          goalsEmpty,
          "✓",
          "当前没有目标",
          "光标位置没有未完成的证明目标。"
        );
        return;
      }

      items.forEach(function (goal, index) {
        var card = document.createElement("article");
        card.className = "lean-goal-card";
        var heading = document.createElement("header");
        heading.className = "lean-goal-heading";
        heading.textContent = "Goal " + (index + 1);
        card.appendChild(heading);

        if (typeof goal === "string") {
          appendCodeBlock(card, "lean-goal-code", goal);
        } else if (goal && goal.text) {
          appendCodeBlock(card, "lean-goal-code", goal.text);
        } else {
          var hypotheses = goal && (goal.hyps || goal.hypotheses) || [];
          if (hypotheses.length) {
            appendCodeBlock(
              card,
              "lean-goal-hypotheses",
              hypotheses.map(function (item) {
                return typeof item === "string"
                  ? item
                  : String(item.name || "") + " : " + String(item.type || "");
              }).join("\n")
            );
          }
          appendCodeBlock(card, "lean-goal-target", goal && goal.target || "");
        }
        goalList.appendChild(card);
      });
    }

    function diagnosticPath(diagnostic) {
      var raw = diagnostic && (
        diagnostic.path || diagnostic.file || diagnostic.file_path ||
        diagnostic.filename || diagnostic.uri
      );
      var path = String(raw || activePath);
      path = path.replace(/^file:\/\//, "").replace(/^\/workspace\//, "");
      path = path.split("?")[0];
      try {
        path = decodeURIComponent(path);
      } catch (_error) {
        // 保留服务端返回的原始路径。
      }
      if (!states.has(path)) {
        var suffix = Array.from(states.keys()).find(function (candidate) {
          return path.endsWith("/" + candidate);
        });
        path = suffix || activePath;
      }
      return path;
    }

    function normalizedDiagnostics(diagnostics) {
      if (Array.isArray(diagnostics)) return diagnostics;
      if (!diagnostics || typeof diagnostics !== "object") return [];
      return Object.keys(diagnostics).flatMap(function (path) {
        var items = Array.isArray(diagnostics[path]) ? diagnostics[path] : [];
        return items.map(function (item) {
          return Object.assign({ path: path }, item);
        });
      });
    }

    function switchFile(path, shouldCheck) {
      var next = states.get(path);
      if (!next) return false;
      var previous = currentState();
      if (previous && previous.path !== next.path) {
        if (editor) previous.viewState = editor.saveViewState();
        else saveFallbackState();
      }
      activePath = next.path;
      if (editor && next.model) {
        if (editor.getModel() !== next.model) editor.setModel(next.model);
        editor.updateOptions({
          readOnly: next.mode === "readonly",
          domReadOnly: next.mode === "readonly",
          ariaLabel: "Lean 4 文件 " + next.path +
            (next.mode === "readonly" ? "，只读" : "，可编辑")
        });
        if (next.viewState) editor.restoreViewState(next.viewState);
        editor.layout();
      } else if (textarea) {
        textarea.value = next.content;
        textarea.readOnly = next.mode === "readonly";
        textarea.setAttribute(
          "aria-label",
          "Lean 4 文件 " + next.path +
            (next.mode === "readonly" ? "，只读" : "，可编辑")
        );
      }
      updateActiveFileChrome();
      updateCursorLabel();
      updateVersionLabel();
      if (shouldCheck) {
        sourceChangePending = false;
        window.clearTimeout(sourceTimer);
        sourceTimer = window.setTimeout(checkDocument, 40);
      }
      return true;
    }

    function revealDiagnostic(diagnostic) {
      var path = diagnosticPath(diagnostic);
      switchFile(path, false);
      if (!editor) return;
      var range = diagnosticRange(diagnostic);
      editor.setPosition({
        lineNumber: range.start.line + 1,
        column: range.start.character + 1
      });
      editor.revealLineInCenter(range.start.line + 1);
      editor.focus();
    }

    function renderDiagnostics(diagnostics, includeMarkers) {
      var items = normalizedDiagnostics(diagnostics);
      var byPath = new Map();
      problemList.replaceChildren();
      problemCount.textContent = String(items.length);
      problemsEmpty.hidden = items.length > 0;
      problemsTab.classList.toggle("has-errors", items.some(function (item) {
        return severityName(item.severity) === "error";
      }));

      states.forEach(function (state) {
        byPath.set(state.path, []);
        if (state.errorCount) state.errorCount.hidden = true;
      });

      items.forEach(function (diagnostic) {
        var path = diagnosticPath(diagnostic);
        var severity = severityName(diagnostic.severity);
        var range = diagnosticRange(diagnostic);
        byPath.get(path).push(diagnostic);
        var item = document.createElement("li");
        item.className = "lean-problem-item";
        item.dataset.severity = severity;
        item.tabIndex = 0;
        var dot = document.createElement("span");
        dot.className = "lean-problem-severity";
        dot.setAttribute("aria-hidden", "true");
        var body = document.createElement("div");
        var message = document.createElement("p");
        message.className = "lean-problem-message";
        message.textContent = String(diagnostic.message || "Lean 检查失败");
        var location = document.createElement("span");
        location.className = "lean-problem-location";
        location.textContent = path + " · " + severity.toUpperCase() + " · Ln " +
          (range.start.line + 1) + ", Col " + (range.start.character + 1);
        body.append(message, location);
        item.append(dot, body);
        item.addEventListener("click", function () {
          revealDiagnostic(diagnostic);
        });
        item.addEventListener("keydown", function (event) {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            revealDiagnostic(diagnostic);
          }
        });
        problemList.appendChild(item);
      });

      byPath.forEach(function (fileDiagnostics, path) {
        var state = states.get(path);
        var errors = fileDiagnostics.filter(function (diagnostic) {
          return severityName(diagnostic.severity) === "error";
        }).length;
        if (state.errorCount) {
          state.errorCount.textContent = String(errors);
          state.errorCount.hidden = errors === 0;
        }
        if (includeMarkers && monaco && state.model) {
          monaco.editor.setModelMarkers(
            state.model,
            "lean4",
            fileDiagnostics.map(function (diagnostic) {
              var range = diagnosticRange(diagnostic);
              var severity = severityName(diagnostic.severity);
              return {
                startLineNumber: range.start.line + 1,
                startColumn: range.start.character + 1,
                endLineNumber: range.end.line + 1,
                endColumn: range.end.character + 1,
                message: String(diagnostic.message || "Lean 检查失败"),
                severity: markerSeverity(monaco, severity),
                source: "Lean 4"
              };
            })
          );
        }
      });
    }

    async function checkDocument() {
      window.clearTimeout(sourceTimer);
      window.clearTimeout(cursorTimer);
      if (requestInFlight) {
        queuedCheck = true;
        return;
      }
      sourceChangePending = false;
      requestInFlight = true;
      var requestedPath = activePath;
      var requestedVersion = currentVersion();
      var requestedPosition = currentPosition();
      var serial = ++requestSerial;
      activeController = new AbortController();
      setStatus("checking", "正在检查");

      try {
        var response = await fetch(checkUrl, {
          method: "POST",
          credentials: "same-origin",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest"
          },
          body: JSON.stringify({
            problem_id: problemId,
            revision: workspace.revision,
            files: writableFiles(),
            active_file: requestedPath,
            version: requestedVersion,
            position: requestedPosition
          }),
          signal: activeController.signal,
          mathCurveLoader: false
        });
        var payload = await response.json();
        if (
          serial !== requestSerial ||
          requestedPath !== activePath ||
          requestedVersion !== currentVersion()
        ) return;
        if (Number.isFinite(Number(payload.version)) &&
            Number(payload.version) !== requestedVersion) return;
        if (!response.ok || !payload.success) {
          if (payload.code === "service_busy" &&
              requestedVersion === currentVersion()) {
            setStatus("checking", "正在等待 Lean");
            sourceTimer = window.setTimeout(checkDocument, 500);
            return;
          }
          throw new Error(payload.message || "Lean 服务暂时不可用");
        }

        var diagnostics = normalizedDiagnostics(payload.diagnostics);
        var requestedState = states.get(requestedPath);
        if (requestedState && requestedState.semanticTokens) {
          requestedState.semanticTokens.accept(
            requestedVersion,
            payload.semantic_tokens
          );
        }
        renderGoals(payload.goals);
        renderDiagnostics(diagnostics, true);
        updateVersionLabel();
        setStatus(
          diagnostics.length ? "problems" : "ready",
          diagnostics.length ? diagnostics.length + " 个问题" : "已同步"
        );
      } catch (error) {
        if (error && error.name === "AbortError") return;
        if (serial !== requestSerial) return;
        var message = error && error.message || "Lean 服务暂时不可用";
        setStatus("offline", "检查失败");
        renderDiagnostics([{
          path: requestedPath,
          severity: "error",
          message: message,
          range: {
            start: requestedPosition,
            end: requestedPosition
          }
        }], false);
        activateTab("problems");
      } finally {
        requestInFlight = false;
        activeController = null;
        if (queuedCheck) {
          queuedCheck = false;
          window.setTimeout(checkDocument, 0);
        }
      }
    }

    function scheduleSourceCheck() {
      sourceChangePending = true;
      window.clearTimeout(sourceTimer);
      window.clearTimeout(cursorTimer);
      setStatus("idle", "等待检查");
      sourceTimer = window.setTimeout(checkDocument, SOURCE_DEBOUNCE_MS);
    }

    function scheduleCursorCheck() {
      updateCursorLabel();
      if (sourceChangePending) return;
      window.clearTimeout(cursorTimer);
      cursorTimer = window.setTimeout(checkDocument, CURSOR_DEBOUNCE_MS);
    }

    if (editor && monaco && monaco.editor) {
      workspace.files.forEach(function (file) {
        var state = states.get(file.path);
        var encodedPath = file.path.split("/").map(encodeURIComponent).join("/");
        var uri = monaco.Uri.parse(
          "file:///workspace/numoj-" + problemId + "/" + encodedPath
        );
        state.model = monaco.editor.createModel(file.content, "lean4", uri);
        if (monaco.languages &&
            monaco.languages.registerDocumentSemanticTokensProvider) {
          state.semanticTokens = createSemanticTokenBridge(monaco, state.model);
        }
        disposables.push(state.model.onDidChangeContent(function () {
          updateFileState(state);
          if (state.semanticTokens) state.semanticTokens.invalidate();
          if (suppressChanges || state.path !== activePath) return;
          updateVersionLabel();
          scheduleSourceCheck();
        }));
      });
      disposables.push(editor.onDidChangeCursorPosition(scheduleCursorCheck));
    } else if (textarea) {
      textarea.addEventListener("input", function () {
        var state = currentState();
        if (!state) return;
        state.content = textarea.value;
        state.fallbackVersion += 1;
        updateFileState(state);
        updateVersionLabel();
        scheduleSourceCheck();
      });
      textarea.addEventListener("keyup", scheduleCursorCheck);
      textarea.addEventListener("click", scheduleCursorCheck);
    }

    renderFileTree();
    switchFile(activePath, false);
    if (bootstrapModel && bootstrapModel !== currentState().model) {
      bootstrapModel.dispose();
    }
    updateCursorLabel();
    updateVersionLabel();
    sourceTimer = window.setTimeout(checkDocument, 80);

    function setWritableFiles(files) {
      var values = files;
      if (Array.isArray(values)) {
        values = values.reduce(function (result, file) {
          if (file && file.path) result[file.path] = file.content || "";
          return result;
        }, {});
      }
      if (!values || typeof values !== "object") return;
      suppressChanges = true;
      states.forEach(function (state) {
        if (state.mode !== "writable" || !(state.path in values)) return;
        var value = String(values[state.path] || "");
        if (state.model) state.model.setValue(value);
        else state.content = value;
        updateFileState(state);
      });
      suppressChanges = false;
      if (!editor && textarea) textarea.value = stateValue(currentState());
      updateVersionLabel();
      scheduleSourceCheck();
    }

    function setLegacyCode(value) {
      var preferred = states.get(workspace.defaultFile);
      var state = preferred && preferred.mode === "writable"
        ? preferred
        : workspace.files.map(function (file) {
          return states.get(file.path);
        }).find(function (candidate) {
          return candidate.mode === "writable";
        });
      if (!state) return;
      switchFile(state.path, false);
      setWritableFiles(Object.fromEntries([[state.path, String(value || "")]]));
    }

    var controller = {
      checkNow: checkDocument,
      getActiveValue: function () {
        saveFallbackState();
        return stateValue(currentState());
      },
      setActiveValue: setLegacyCode,
      setWritableFiles: setWritableFiles,
      getSubmissionPayload: submissionPayload,
      prepareSubmission: function () {
        var payload = submissionPayload();
        if (workspaceInput) workspaceInput.value = JSON.stringify(payload);
        return payload;
      },
      switchFile: function (path) {
        return switchFile(path, true);
      },
      focus: function () {
        if (editor) editor.focus();
        else if (textarea) textarea.focus();
      },
      layout: function () {
        if (editor) editor.layout();
      },
      dispose: function () {
        if (disposed) return;
        disposed = true;
        window.clearTimeout(sourceTimer);
        window.clearTimeout(cursorTimer);
        queuedCheck = false;
        requestSerial += 1;
        if (activeController) activeController.abort();
        disposables.forEach(function (disposable) {
          if (disposable && disposable.dispose) disposable.dispose();
        });
        states.forEach(function (state) {
          if (state.semanticTokens) state.semanticTokens.dispose();
          if (monaco && state.model) {
            monaco.editor.setModelMarkers(state.model, "lean4", []);
            state.model.dispose();
          }
        });
      }
    };
    window.addEventListener("pagehide", controller.dispose, { once: true });
    return controller;
  }

  window.NumOJLeanWorkbench = Object.freeze({
    attach: attach,
    createSemanticTokenBridge: createSemanticTokenBridge
  });
})();
