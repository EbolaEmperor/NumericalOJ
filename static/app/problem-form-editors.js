(function () {
  "use strict";

  var form =
    document.getElementById("addProblemForm") ||
    document.getElementById("editProblemForm");
  var languageSelect = document.getElementById("langSelect");
  var runtime = window.NumOJCodeEditorRuntime;
  var descriptors = [
    {
      documentId: "initial-code",
      textarea: document.getElementById("initialCode"),
      host: document.getElementById("initialCodeEditorBox"),
      ariaLabel: "初始代码编辑器",
      autofocus: true,
    },
    {
      documentId: "test-code",
      textarea: document.getElementById("testCode"),
      host: document.getElementById("testCodeEditorBox"),
      ariaLabel: "交互库代码编辑器",
      autofocus: false,
    },
  ].filter(function (item) {
    return item.textarea && item.host;
  });

  if (!form || !languageSelect || !descriptors.length) return;

  var desktop = window.matchMedia("(min-width: 992px)").matches;
  var editors = [];
  var semanticProviders = Object.create(null);

  function currentSpec() {
    return runtime
      ? runtime.forLanguage(languageSelect.value)
      : {
          language: String(languageSelect.value || "matlab").toLowerCase(),
          monacoLanguage: String(languageSelect.value || "matlab").toLowerCase(),
          codeMirrorMode: null,
        };
  }

  function specForDescriptor(spec, descriptor) {
    if (
      spec.language === "lean4" &&
      descriptor.documentId === "test-code" &&
      runtime
    ) {
      return runtime.forLanguage("json");
    }
    return spec;
  }

  function revealTextarea(descriptor) {
    descriptor.host.hidden = true;
    descriptor.textarea.hidden = false;
    descriptor.textarea.classList.add("numoj-form-code-textarea-fallback");
    if (runtime) {
      runtime.protectEditorInput(
        descriptor.textarea,
        descriptor.documentId,
        descriptor.ariaLabel
      );
    }
    return {
      kind: "textarea",
      getValue: function () {
        return descriptor.textarea.value;
      },
      setValue: function (value) {
        descriptor.textarea.value = value || "";
      },
      setLanguage: function () {},
      layout: function () {},
    };
  }

  function ensureSemanticProvider(monaco, spec) {
    if (
      !spec.language ||
      spec.language === "lean4" ||
      semanticProviders[spec.language] ||
      !window.NumOJSemanticTokens
    ) {
      return;
    }
    semanticProviders[spec.language] = true;
    window.NumOJSemanticTokens.register(monaco, {
      context: "problem-form",
      documentId: function (model) {
        var pieces = String(model && model.uri && model.uri.path || "")
          .split("/")
          .filter(Boolean);
        return pieces.pop() || "code-editor";
      },
      language: spec.language,
      monacoLanguage: spec.monacoLanguage,
    }).then(function (disposable) {
      semanticProviders[spec.language] = disposable || true;
    }).catch(function (error) {
      delete semanticProviders[spec.language];
      console.warn("题目代码语言服务初始化失败，已保留 TextMate 着色。", error);
    });
  }

  async function createMonacoEditors() {
    var monaco = window.NumericalOJMonaco;
    if (!desktop || !monaco || !runtime) return false;

    var theme = await runtime.prepareMonaco(monaco);
    var spec = currentSpec();
    ensureSemanticProvider(monaco, spec);
    editors = descriptors.map(function (descriptor) {
      var descriptorSpec = specForDescriptor(spec, descriptor);
      descriptor.host.hidden = false;
      var model = monaco.editor.createModel(
        descriptor.textarea.value || "",
        descriptorSpec.monacoLanguage,
        monaco.Uri.parse(
          "inmemory://problem-form/" + descriptor.documentId
        )
      );
      var instance = monaco.editor.create(
        descriptor.host,
        runtime.monacoOptions({
          model: model,
          theme: theme,
          ariaLabel: descriptor.ariaLabel,
          wordWrap: "on",
          tabSize: descriptorSpec.language === "lean4" || descriptorSpec.language === "json" ? 2 : 4,
        })
      );
      var unicodeInput = descriptorSpec.language === "lean4"
        && typeof monaco.attachLean4UnicodeInput === "function"
        ? monaco.attachLean4UnicodeInput(instance)
        : null;
      runtime.protectEditorInput(
        instance.getDomNode() &&
          instance.getDomNode().querySelector("textarea.inputarea"),
        descriptor.documentId,
        descriptor.ariaLabel
      );
      return {
        kind: "monaco",
        getValue: function () {
          return instance.getValue();
        },
        setValue: function (value) {
          instance.setValue(value || "");
        },
        setLanguage: function (nextSpec) {
          var nextDescriptorSpec = specForDescriptor(nextSpec, descriptor);
          ensureSemanticProvider(monaco, nextDescriptorSpec);
          monaco.editor.setModelLanguage(model, nextDescriptorSpec.monacoLanguage);
          if (unicodeInput) unicodeInput.dispose();
          unicodeInput = nextDescriptorSpec.language === "lean4"
            && typeof monaco.attachLean4UnicodeInput === "function"
            ? monaco.attachLean4UnicodeInput(instance)
            : null;
        },
        layout: function () {
          instance.layout();
        },
      };
    });
    window.requestAnimationFrame(function () {
      editors.forEach(function (editor) { editor.layout(); });
    });
    return true;
  }

  function createCodeMirrorEditors() {
    if (desktop || !window.CodeMirror) return false;
    var spec = currentSpec();
    editors = descriptors.map(function (descriptor) {
      var descriptorSpec = specForDescriptor(spec, descriptor);
      descriptor.host.hidden = false;
      var instance = window.CodeMirror(descriptor.host, {
        value: descriptor.textarea.value || "",
        mode: descriptorSpec.codeMirrorMode,
        theme: "eclipse",
        lineNumbers: true,
        lineWrapping: true,
        indentUnit: descriptorSpec.language === "lean4" || descriptorSpec.language === "json" ? 2 : 4,
        tabSize: descriptorSpec.language === "lean4" || descriptorSpec.language === "json" ? 2 : 4,
        matchBrackets: true,
        autofocus: descriptor.autofocus,
        extraKeys: {
          Tab: "indentMore",
          "Shift-Tab": "indentLess",
        },
      });
      instance.setSize(null, "100%");
      if (runtime) {
        runtime.protectEditorInput(
          instance.getInputField(),
          descriptor.documentId,
          descriptor.ariaLabel
        );
      }
      return {
        kind: "codemirror",
        getValue: function () {
          return instance.getValue();
        },
        setValue: function (value) {
          instance.setValue(value || "");
        },
        setLanguage: function (nextSpec) {
          instance.setOption(
            "mode",
            specForDescriptor(nextSpec, descriptor).codeMirrorMode
          );
        },
        layout: function () {
          instance.refresh();
        },
      };
    });
    return true;
  }

  async function initialize() {
    var created = false;
    try {
      if (desktop && window.NumOJMonacoReady) {
        await window.NumOJMonacoReady;
        created = await createMonacoEditors();
      } else if (!desktop && window.NumOJCodeMirrorReady) {
        await window.NumOJCodeMirrorReady;
        created = createCodeMirrorEditors();
      }
    } catch (error) {
      console.error("题目代码编辑器初始化失败，已降级到文本框。", error);
    }

    if (!created) {
      editors = descriptors.map(revealTextarea);
    }

    languageSelect.addEventListener("change", function () {
      var spec = currentSpec();
      editors.forEach(function (editor) {
        editor.setLanguage(spec);
      });
    });
    form.addEventListener("submit", function () {
      descriptors.forEach(function (descriptor, index) {
        descriptor.textarea.value = editors[index].getValue();
      });
    });

    window.initialCodeEditor = editors[0] || null;
    window.testCodeEditor = editors[1] || null;
    return editors;
  }

  window.NumOJProblemFormEditorsReady = initialize();
})();
