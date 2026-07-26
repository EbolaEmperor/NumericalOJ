(function () {
  "use strict";

  if (window.NumOJCodeEditorRuntime) return;

  var LANGUAGE_SPECS = {
    c: {
      language: "c",
      monacoLanguage: "c",
      codeMirrorMode: "text/x-csrc",
      label: "C",
    },
    cpp: {
      language: "cpp",
      monacoLanguage: "cpp",
      codeMirrorMode: "text/x-c++src",
      label: "C++",
    },
    python: {
      language: "python",
      monacoLanguage: "python",
      codeMirrorMode: "python",
      label: "Python",
    },
    matlab: {
      language: "matlab",
      monacoLanguage: "matlab",
      codeMirrorMode: "octave",
      label: "MATLAB / Octave",
    },
    plaintext: {
      language: null,
      monacoLanguage: "plaintext",
      codeMirrorMode: null,
      label: "Plain Text",
    },
  };

  var EXTENSION_LANGUAGES = {
    c: "c",
    cc: "cpp",
    cpp: "cpp",
    cxx: "cpp",
    h: "cpp",
    hh: "cpp",
    hpp: "cpp",
    hxx: "cpp",
    py: "python",
    m: "matlab",
  };
  var TEXTMATE_INITIAL_WAIT_MS = 250;
  var textMateStates = new WeakMap();

  function copySpec(spec, label) {
    return {
      language: spec.language,
      monacoLanguage: spec.monacoLanguage,
      codeMirrorMode: spec.codeMirrorMode,
      label: label || spec.label,
    };
  }

  function forLanguage(value) {
    var normalized = String(value || "").toLowerCase();
    if (normalized === "py") normalized = "python";
    if (normalized === "octave") normalized = "matlab";
    return copySpec(LANGUAGE_SPECS[normalized] || LANGUAGE_SPECS.plaintext);
  }

  function forFilename(filename) {
    var pieces = String(filename || "").split(".");
    var extension = pieces.length > 1
      ? pieces.pop().toLowerCase()
      : "";
    var spec = forLanguage(EXTENSION_LANGUAGES[extension] || "plaintext");
    if (extension === "c") spec.label = "C Source";
    if (extension === "h") spec.label = "C++ Header";
    if (["cc", "cpp", "cxx"].indexOf(extension) !== -1) {
      spec.label = "C++ Source";
    }
    if (["hh", "hpp", "hxx"].indexOf(extension) !== -1) {
      spec.label = "C++ Header";
    }
    return spec;
  }

  function registerMatlab(monaco) {
    if (
      !monaco ||
      !monaco.languages ||
      monaco.languages.getLanguages().some(function (item) {
        return item.id === "matlab";
      })
    ) {
      return;
    }

    monaco.languages.register({
      id: "matlab",
      extensions: [".m"],
      aliases: ["MATLAB", "matlab"],
    });
    monaco.languages.setLanguageConfiguration("matlab", {
      comments: { lineComment: "%" },
      brackets: [["(", ")"], ["[", "]"], ["{", "}"]],
      autoClosingPairs: [
        { open: "(", close: ")" },
        { open: "[", close: "]" },
        { open: "{", close: "}" },
        { open: "'", close: "'", notIn: ["string", "comment"] },
        { open: '"', close: '"', notIn: ["string", "comment"] },
      ],
      surroundingPairs: [
        { open: "(", close: ")" },
        { open: "[", close: "]" },
        { open: "{", close: "}" },
        { open: "'", close: "'" },
        { open: '"', close: '"' },
      ],
      indentationRules: {
        increaseIndentPattern:
          /^\s*(?:if|for|while|switch|try|function|classdef|properties|methods|events|enumeration)\b(?!.*\bend\b).*$/i,
        decreaseIndentPattern:
          /^\s*(?:end|else|elseif|case|otherwise|catch)\b/i,
      },
    });
    monaco.languages.setMonarchTokensProvider("matlab", {
      defaultToken: "",
      tokenPostfix: ".matlab",
      keywords: [
        "break", "case", "catch", "classdef", "continue", "else", "elseif",
        "end", "enumeration", "events", "for", "function", "global", "if",
        "methods", "otherwise", "parfor", "persistent", "properties",
        "return", "spmd", "switch", "try", "while",
      ],
      constants: ["true", "false", "NaN", "Inf", "pi", "eps"],
      tokenizer: {
        root: [
          [/%\{/, "comment", "@commentBlock"],
          [/%.*$/, "comment"],
          [/[a-zA-Z_]\w*/, {
            cases: {
              "@keywords": "keyword",
              "@constants": "constant",
              "@default": "identifier",
            },
          }],
          [/\d*\.\d+(?:[eE][+-]?\d+)?[ij]?/, "number.float"],
          [/\d+(?:[eE][+-]?\d+)?[ij]?/, "number"],
          [/\.\.\..*$/, "keyword"],
          [/'(?:[^']|'')*'/, "string"],
          [/"(?:[^"]|"")*"/, "string"],
          [/[{}()[\]]/, "@brackets"],
          [/[+\-*/\\^~<>=&|:@.]+/, "operator"],
          [/[;,]/, "delimiter"],
        ],
        commentBlock: [
          [/%\}/, "comment", "@pop"],
          [/./, "comment"],
        ],
      },
    });
  }

  function resolveWithin(promise, timeoutMs) {
    return new Promise(function (resolve) {
      var settled = false;
      var timeout = window.setTimeout(function () {
        if (settled) return;
        settled = true;
        resolve({ settled: false });
      }, timeoutMs);
      Promise.resolve(promise).then(function (value) {
        if (settled) return;
        settled = true;
        window.clearTimeout(timeout);
        resolve({ settled: true, value: value });
      }, function () {
        if (settled) return;
        settled = true;
        window.clearTimeout(timeout);
        resolve({ settled: true, value: false });
      });
    });
  }

  function warnTextMateFailure(state, message, error) {
    if (state.warned) return;
    state.warned = true;
    console.warn(message, error);
  }

  function getTextMateState(monaco) {
    var existing = textMateStates.get(monaco);
    if (existing) return existing;

    var state = {
      status: "pending",
      warned: false,
      themeApplyScheduled: false,
      themeApplied: false,
      promise: null,
    };
    textMateStates.set(monaco, state);

    var preparation;
    try {
      preparation = monaco.prepareTextMateHighlighting();
    } catch (error) {
      preparation = Promise.reject(error);
    }
    state.promise = Promise.resolve(preparation).then(function () {
      state.status = "ready";
      return true;
    }, function (error) {
      state.status = "failed";
      warnTextMateFailure(
        state,
        "VS Code 语法 grammar 初始化失败，已降级为 Monaco 基础着色。",
        error
      );
      return false;
    });
    return state;
  }

  function applyTextMateThemeWhenReady(monaco, state) {
    state.promise.then(function (ready) {
      if (
        !ready ||
        state.themeApplyScheduled ||
        state.themeApplied ||
        !monaco.editor ||
        typeof monaco.editor.setTheme !== "function"
      ) {
        return;
      }
      state.themeApplyScheduled = true;
      window.setTimeout(function () {
        if (state.themeApplied) return;
        try {
          monaco.editor.setTheme("dark-plus");
          state.themeApplied = true;
        } catch (error) {
          warnTextMateFailure(
            state,
            "VS Code 语法主题切换失败，已保留 Monaco 基础着色。",
            error
          );
        }
      }, 0);
    });
  }

  async function prepareMonaco(monaco) {
    registerMatlab(monaco);
    if (typeof monaco.prepareTextMateHighlighting !== "function") {
      return "vs-dark";
    }

    var state = getTextMateState(monaco);
    if (state.status === "ready") return "dark-plus";
    if (state.status === "failed") return "vs-dark";

    var initialResult = await resolveWithin(
      state.promise,
      TEXTMATE_INITIAL_WAIT_MS
    );
    if (initialResult.settled && initialResult.value) {
      return "dark-plus";
    }

    applyTextMateThemeWhenReady(monaco, state);
    return "vs-dark";
  }

  function monacoOptions(overrides) {
    return Object.assign({
      theme: "dark-plus",
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
      insertSpaces: true,
      detectIndentation: false,
      wordWrap: "on",
      bracketPairColorization: { enabled: true },
      guides: { bracketPairs: true, indentation: true },
      quickSuggestions: false,
      suggestOnTriggerCharacters: false,
      contextmenu: true,
      find: { addExtraSpaceOnTop: false },
    }, overrides || {});
  }

  function protectEditorInput(input, name, ariaLabel) {
    if (!input) return;
    if (name) input.setAttribute("name", name);
    if (ariaLabel) input.setAttribute("aria-label", ariaLabel);
    input.setAttribute("autocomplete", "off");
    input.setAttribute("autocapitalize", "off");
    input.setAttribute("autocorrect", "off");
    input.setAttribute("spellcheck", "false");
    input.setAttribute("data-1p-ignore", "");
    input.setAttribute("data-lpignore", "true");
    input.setAttribute("data-bwignore", "");
  }

  window.NumOJCodeEditorRuntime = Object.freeze({
    forFilename: forFilename,
    forLanguage: forLanguage,
    monacoOptions: monacoOptions,
    prepareMonaco: prepareMonaco,
    protectEditorInput: protectEditorInput,
    registerMatlab: registerMatlab,
  });
})();
