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
    javascript: {
      language: "javascript",
      monacoLanguage: "javascript",
      codeMirrorMode: "javascript",
      label: "JavaScript",
    },
    jsx: {
      language: "jsx",
      monacoLanguage: "jsx",
      codeMirrorMode: "javascript",
      label: "JavaScript JSX",
    },
    typescript: {
      language: "typescript",
      monacoLanguage: "typescript",
      codeMirrorMode: "javascript",
      label: "TypeScript",
    },
    tsx: {
      language: "tsx",
      monacoLanguage: "tsx",
      codeMirrorMode: "javascript",
      label: "TypeScript TSX",
    },
    java: {language: "java", monacoLanguage: "java", codeMirrorMode: "text/x-java", label: "Java"},
    csharp: {language: "csharp", monacoLanguage: "csharp", codeMirrorMode: "text/x-csharp", label: "C#"},
    go: {language: "go", monacoLanguage: "go", codeMirrorMode: "go", label: "Go"},
    rust: {language: "rust", monacoLanguage: "rust", codeMirrorMode: "rust", label: "Rust"},
    php: {language: "php", monacoLanguage: "php", codeMirrorMode: "php", label: "PHP"},
    ruby: {language: "ruby", monacoLanguage: "ruby", codeMirrorMode: "ruby", label: "Ruby"},
    shell: {language: "shell", monacoLanguage: "shell", codeMirrorMode: "shell", label: "Shell"},
    powershell: {language: "powershell", monacoLanguage: "powershell", codeMirrorMode: "powershell", label: "PowerShell"},
    bat: {language: "bat", monacoLanguage: "bat", codeMirrorMode: null, label: "Batch"},
    sql: {language: "sql", monacoLanguage: "sql", codeMirrorMode: "text/x-sql", label: "SQL"},
    html: {language: "html", monacoLanguage: "html", codeMirrorMode: "htmlmixed", label: "HTML"},
    css: {language: "css", monacoLanguage: "css", codeMirrorMode: "css", label: "CSS"},
    scss: {language: "scss", monacoLanguage: "scss", codeMirrorMode: "text/x-scss", label: "SCSS"},
    less: {language: "less", monacoLanguage: "less", codeMirrorMode: "text/x-less", label: "Less"},
    json: {language: "json", monacoLanguage: "json", codeMirrorMode: "application/json", label: "JSON"},
    yaml: {language: "yaml", monacoLanguage: "yaml", codeMirrorMode: "yaml", label: "YAML"},
    xml: {language: "xml", monacoLanguage: "xml", codeMirrorMode: "xml", label: "XML"},
    dockerfile: {language: "dockerfile", monacoLanguage: "dockerfile", codeMirrorMode: "dockerfile", label: "Dockerfile"},
    latex: {language: "latex", monacoLanguage: "latex", codeMirrorMode: "stex", label: "LaTeX"},
    lua: {language: "lua", monacoLanguage: "lua", codeMirrorMode: "lua", label: "Lua"},
    kotlin: {language: "kotlin", monacoLanguage: "kotlin", codeMirrorMode: "text/x-kotlin", label: "Kotlin"},
    swift: {language: "swift", monacoLanguage: "swift", codeMirrorMode: "swift", label: "Swift"},
    r: {language: "r", monacoLanguage: "r", codeMirrorMode: "r", label: "R"},
    julia: {language: "julia", monacoLanguage: "julia", codeMirrorMode: "julia", label: "Julia"},
    dart: {language: "dart", monacoLanguage: "dart", codeMirrorMode: "dart", label: "Dart"},
    scala: {language: "scala", monacoLanguage: "scala", codeMirrorMode: "text/x-scala", label: "Scala"},
    perl: {language: "perl", monacoLanguage: "perl", codeMirrorMode: "perl", label: "Perl"},
    solidity: {language: "solidity", monacoLanguage: "solidity", codeMirrorMode: null, label: "Solidity"},
    protobuf: {language: "protobuf", monacoLanguage: "protobuf", codeMirrorMode: "protobuf", label: "Protocol Buffers"},
    graphql: {language: "graphql", monacoLanguage: "graphql", codeMirrorMode: "graphql", label: "GraphQL"},
    ini: {language: "ini", monacoLanguage: "ini", codeMirrorMode: "properties", label: "INI"},
    cmake: {language: "cmake", monacoLanguage: "cmake", codeMirrorMode: "cmake", label: "CMake"},
    makefile: {language: "makefile", monacoLanguage: "makefile", codeMirrorMode: "text/x-makefile", label: "Makefile"},
    asm: {language: "asm", monacoLanguage: "asm", codeMirrorMode: "gas", label: "Assembly"},
    fsharp: {language: "fsharp", monacoLanguage: "fsharp", codeMirrorMode: "text/x-fsharp", label: "F#"},
    vb: {language: "vb", monacoLanguage: "vb", codeMirrorMode: "text/x-vb", label: "Visual Basic"},
    clojure: {language: "clojure", monacoLanguage: "clojure", codeMirrorMode: "clojure", label: "Clojure"},
    coffeescript: {language: "coffeescript", monacoLanguage: "coffeescript", codeMirrorMode: "coffeescript", label: "CoffeeScript"},
    elixir: {language: "elixir", monacoLanguage: "elixir", codeMirrorMode: "elixir", label: "Elixir"},
    erlang: {language: "erlang", monacoLanguage: "erlang", codeMirrorMode: "erlang", label: "Erlang"},
    groovy: {language: "groovy", monacoLanguage: "groovy", codeMirrorMode: "groovy", label: "Groovy"},
    haskell: {language: "haskell", monacoLanguage: "haskell", codeMirrorMode: "haskell", label: "Haskell"},
    "objective-c": {language: "objective-c", monacoLanguage: "objective-c", codeMirrorMode: "text/x-objectivec", label: "Objective-C"},
    pascal: {language: "pascal", monacoLanguage: "pascal", codeMirrorMode: "pascal", label: "Pascal"},
    scheme: {language: "scheme", monacoLanguage: "scheme", codeMirrorMode: "scheme", label: "Scheme"},
    systemverilog: {language: "systemverilog", monacoLanguage: "systemverilog", codeMirrorMode: "text/x-systemverilog", label: "SystemVerilog"},
    tcl: {language: "tcl", monacoLanguage: "tcl", codeMirrorMode: "tcl", label: "Tcl"},
    toml: {language: "toml", monacoLanguage: "toml", codeMirrorMode: "toml", label: "TOML"},
    verilog: {language: "verilog", monacoLanguage: "verilog", codeMirrorMode: "verilog", label: "Verilog"},
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
    pyw: "python",
    pyi: "python",
    m: "matlab",
    js: "javascript",
    mjs: "javascript",
    cjs: "javascript",
    jsx: "jsx",
    ts: "typescript",
    mts: "typescript",
    cts: "typescript",
    tsx: "tsx",
    java: "java",
    cs: "csharp",
    go: "go",
    rs: "rust",
    php: "php",
    rb: "ruby",
    sh: "shell",
    bash: "shell",
    zsh: "shell",
    fish: "shell",
    ps1: "powershell",
    bat: "bat",
    cmd: "bat",
    sql: "sql",
    html: "html",
    htm: "html",
    xhtml: "html",
    css: "css",
    scss: "scss",
    sass: "scss",
    less: "less",
    json: "json",
    jsonc: "json",
    jsonl: "json",
    ipynb: "json",
    yaml: "yaml",
    yml: "yaml",
    xml: "xml",
    xsd: "xml",
    xsl: "xml",
    svg: "xml",
    tex: "latex",
    sty: "latex",
    cls: "latex",
    bib: "latex",
    lua: "lua",
    kt: "kotlin",
    kts: "kotlin",
    swift: "swift",
    r: "r",
    jl: "julia",
    dart: "dart",
    scala: "scala",
    sc: "scala",
    pl: "perl",
    pm: "perl",
    sol: "solidity",
    proto: "protobuf",
    graphql: "graphql",
    gql: "graphql",
    ini: "ini",
    cfg: "ini",
    conf: "ini",
    toml: "toml",
    cmake: "cmake",
    dockerfile: "dockerfile",
    asm: "asm",
    s: "asm",
    fs: "fsharp",
    fsx: "fsharp",
    vb: "vb",
    clj: "clojure",
    cljs: "clojure",
    coffee: "coffeescript",
    ex: "elixir",
    exs: "elixir",
    erl: "erlang",
    hrl: "erlang",
    groovy: "groovy",
    hs: "haskell",
    lhs: "haskell",
    mm: "objective-c",
    pas: "pascal",
    scm: "scheme",
    sv: "systemverilog",
    svh: "systemverilog",
    tcl: "tcl",
    v: "verilog",
    vh: "verilog",
    vue: "html",
  };
  var FILENAME_LANGUAGES = {
    dockerfile: "dockerfile",
    "dockerfile.dev": "dockerfile",
    gemfile: "ruby",
    makefile: "makefile",
    gnumakefile: "makefile",
    rakefile: "ruby",
    cmakelists: "cmake",
    "cmakelists.txt": "cmake",
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
    if (normalized === "js") normalized = "javascript";
    if (normalized === "ts") normalized = "typescript";
    if (normalized === "c#" || normalized === "cs") normalized = "csharp";
    if (normalized === "sh" || normalized === "bash" || normalized === "zsh") normalized = "shell";
    if (normalized === "tex") normalized = "latex";
    if (normalized === "objective_c" || normalized === "objc") normalized = "objective-c";
    if (normalized === "system-verilog" || normalized === "sv") normalized = "systemverilog";
    return copySpec(LANGUAGE_SPECS[normalized] || LANGUAGE_SPECS.plaintext);
  }

  function forFilename(filename) {
    var basename = String(filename || "").split(/[\\/]/).pop().toLowerCase();
    var pieces = basename.split(".");
    var extension = pieces.length > 1
      ? pieces.pop().toLowerCase()
      : "";
    var language = FILENAME_LANGUAGES[basename]
      || FILENAME_LANGUAGES[basename.replace(/\.[^.]+$/, "")]
      || EXTENSION_LANGUAGES[extension]
      || "plaintext";
    var spec = forLanguage(language);
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
