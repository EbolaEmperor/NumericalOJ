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
    var model = editor && editor.getModel ? editor.getModel() : null;
    var checkUrl = root.dataset.checkUrl || "/api/lean/check";
    var problemId = Number(root.dataset.problemId);
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
    var fallbackVersion = 1;
    var activeController = null;
    var requestInFlight = false;
    var queuedCheck = false;
    var sourceChangePending = false;
    var disposables = [];
    var semanticTokens = monaco && model && monaco.languages &&
      monaco.languages.registerDocumentSemanticTokensProvider
      ? createSemanticTokenBridge(monaco, model)
      : null;

    registerSymbolCompletions(monaco);

    function currentSource() {
      if (model) return model.getValue();
      return textarea ? textarea.value : "";
    }

    function currentVersion() {
      return model ? model.getVersionId() : fallbackVersion;
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

    function revealDiagnostic(diagnostic) {
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
      var items = Array.isArray(diagnostics) ? diagnostics : [];
      problemList.replaceChildren();
      problemCount.textContent = String(items.length);
      problemsEmpty.hidden = items.length > 0;
      problemsTab.classList.toggle("has-errors", items.some(function (item) {
        return severityName(item.severity) === "error";
      }));

      items.forEach(function (diagnostic) {
        var severity = severityName(diagnostic.severity);
        var range = diagnosticRange(diagnostic);
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
        location.textContent = severity.toUpperCase() + " · Ln " +
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

      if (includeMarkers && monaco && model) {
        monaco.editor.setModelMarkers(model, "lean4", items.map(function (item) {
          var range = diagnosticRange(item);
          var severity = severityName(item.severity);
          return {
            startLineNumber: range.start.line + 1,
            startColumn: range.start.character + 1,
            endLineNumber: range.end.line + 1,
            endColumn: range.end.character + 1,
            message: String(item.message || "Lean 检查失败"),
            severity: markerSeverity(monaco, severity),
            source: "Lean 4"
          };
        }));
      }
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
      var requestedVersion = currentVersion();
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
            source: currentSource(),
            version: requestedVersion,
            position: currentPosition()
          }),
          signal: activeController.signal,
          mathCurveLoader: false
        });
        var payload = await response.json();
        if (serial !== requestSerial || requestedVersion !== currentVersion()) return;
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

        var diagnostics = Array.isArray(payload.diagnostics)
          ? payload.diagnostics
          : [];
        if (semanticTokens) {
          semanticTokens.accept(requestedVersion, payload.semantic_tokens);
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
          severity: "error",
          message: message,
          range: {
            start: currentPosition(),
            end: currentPosition()
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

    if (editor && model) {
      disposables.push(model.onDidChangeContent(function () {
        if (semanticTokens) semanticTokens.invalidate();
        updateVersionLabel();
        scheduleSourceCheck();
      }));
      disposables.push(editor.onDidChangeCursorPosition(scheduleCursorCheck));
    } else if (textarea) {
      textarea.addEventListener("input", function () {
        fallbackVersion += 1;
        updateVersionLabel();
        scheduleSourceCheck();
      });
      textarea.addEventListener("keyup", scheduleCursorCheck);
      textarea.addEventListener("click", scheduleCursorCheck);
    }

    updateCursorLabel();
    updateVersionLabel();
    sourceTimer = window.setTimeout(checkDocument, 80);

    var controller = {
      checkNow: checkDocument,
      dispose: function () {
        window.clearTimeout(sourceTimer);
        window.clearTimeout(cursorTimer);
        queuedCheck = false;
        requestSerial += 1;
        if (activeController) activeController.abort();
        if (semanticTokens) semanticTokens.dispose();
        disposables.forEach(function (disposable) {
          if (disposable && disposable.dispose) disposable.dispose();
        });
        if (monaco && model) monaco.editor.setModelMarkers(model, "lean4", []);
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
