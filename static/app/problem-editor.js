(function () {
  'use strict';

  const PROBLEM_EDITOR_FONT_SIZE = 12.5;
  const PROBLEM_EDITOR_LINE_HEIGHT = 20;

  async function initializeProblemEditor() {
  const textarea = document.getElementById('codeEditor');
  if (!textarea) return;

  const editorHost = document.getElementById('monacoEditorContainer');
  const editorShell = document.getElementById('problemEditorShell');
  const editorLoading = document.getElementById('monacoEditorLoading');
  const form = textarea.closest('form');
  const language = (editorHost?.dataset.language || 'matlab').toLowerCase();
  const runtime = window.NumOJCodeEditorRuntime;
  const languageSpec = runtime
    ? runtime.forLanguage(language)
    : {
        language,
        monacoLanguage: language === 'py' ? 'python'
          : language === 'octave' ? 'matlab'
          : language
      };
  const monacoLanguage = languageSpec.monacoLanguage;
  let editorAdapter = null;
  let monacoEditorInstance = null;
  let leanWorkbenchController = null;

  function revealMonacoEditor(instance) {
    window.requestAnimationFrame(function () {
      instance.layout();
      window.requestAnimationFrame(function () {
        if (editorShell) {
          editorShell.dataset.editorState = 'ready';
          editorShell.setAttribute('aria-busy', 'false');
        }
        if (editorLoading) editorLoading.hidden = true;
      });
    });
  }

  function revealFallbackTextarea() {
    if (editorShell) editorShell.hidden = true;
    textarea.hidden = false;
    textarea.classList.add('numoj-code-textarea-fallback');
  }

  async function createMonacoAdapter() {
    const monaco = window.NumericalOJMonaco;
    if (!editorHost || !monaco?.editor || !monaco?.languages) return null;

    const editorTheme = runtime
      ? await runtime.prepareMonaco(monaco)
      : 'vs-dark';
    if (language !== 'lean' && language !== 'lean4') {
      window.NumOJSemanticTokens.register(monaco, {
        language,
        monacoLanguage,
        problemId: document.getElementById('problemMeta')?.dataset.problemId
      }).catch(function (error) {
        console.warn('语言服务初始化失败，已保留 TextMate 着色。', error);
      });
    }
    editorHost.hidden = false;
    const instance = monaco.editor.create(editorHost, runtime
      ? runtime.monacoOptions({
          value: textarea.value,
          language: monacoLanguage,
          theme: editorTheme,
          ariaLabel: '代码编辑器',
          fontSize: PROBLEM_EDITOR_FONT_SIZE,
          lineHeight: PROBLEM_EDITOR_LINE_HEIGHT,
          tabSize: (language === 'lean' || language === 'lean4') ? 2 : 4
        })
      : {
      value: textarea.value,
      language: monacoLanguage,
      theme: editorTheme,
      'semanticHighlighting.enabled': true,
      automaticLayout: true,
      ariaLabel: '代码编辑器',
      fontFamily: 'SFMono-Regular, Consolas, Liberation Mono, Menlo, monospace',
      fontSize: PROBLEM_EDITOR_FONT_SIZE,
      lineHeight: PROBLEM_EDITOR_LINE_HEIGHT,
      lineNumbersMinChars: 3,
      minimap: { enabled: false },
      padding: { top: 14, bottom: 14 },
      roundedSelection: false,
      scrollBeyondLastLine: false,
      smoothScrolling: true,
      tabSize: (language === 'lean' || language === 'lean4') ? 2 : 4,
      insertSpaces: true,
      detectIndentation: false,
      wordWrap: 'on',
      bracketPairColorization: { enabled: true },
      guides: { bracketPairs: true, indentation: true },
      quickSuggestions: false,
      suggestOnTriggerCharacters: false,
      contextmenu: true,
      find: { addExtraSpaceOnTop: false }
    });
    if (
      (language === 'lean' || language === 'lean4') &&
      typeof monaco.attachLean4UnicodeInput === 'function'
    ) {
      monaco.attachLean4UnicodeInput(instance);
    }
    monacoEditorInstance = instance;
    textarea.hidden = true;
    revealMonacoEditor(instance);
    return {
      getValue: () => instance.getValue(),
      setValue: value => instance.setValue(value),
      focus: () => instance.focus(),
      layout: () => instance.layout()
    };
  }

  try {
    editorAdapter = await createMonacoAdapter();
  } catch (error) {
    console.error('代码编辑器初始化失败，已降级到文本框。', error);
    editorHost?.setAttribute('hidden', '');
    revealFallbackTextarea();
  }

  if (!editorAdapter) {
    revealFallbackTextarea();
    editorAdapter = {
      getValue: () => textarea.value,
      setValue: value => { textarea.value = value; },
      focus: () => textarea.focus(),
      layout: () => {}
    };
  }

  // 保持现有管理员造数据逻辑可复用统一编辑器接口。
  window.editor = editorAdapter;

  if (
    (language === 'lean' || language === 'lean4') &&
    window.NumOJLeanWorkbench
  ) {
    leanWorkbenchController = window.NumOJLeanWorkbench.attach({
      monaco: window.NumericalOJMonaco,
      editor: monacoEditorInstance,
      textarea: textarea
    });
    if (leanWorkbenchController) {
      editorAdapter = {
        getValue: () => leanWorkbenchController.getActiveValue(),
        setValue: value => leanWorkbenchController.setActiveValue(value),
        focus: () => leanWorkbenchController.focus(),
        layout: () => leanWorkbenchController.layout()
      };
      window.editor = editorAdapter;
    }
  }

  form?.addEventListener('submit', function () {
    if (leanWorkbenchController) {
      leanWorkbenchController.prepareSubmission();
    } else {
      textarea.value = editorAdapter.getValue();
    }
  });

  document.getElementById('loadLastCodeBtn')?.addEventListener('click', function () {
    const problemId = document.getElementById('problemMeta')?.dataset.problemId;
    const button = this;
    const originalHtml = button.innerHTML;
    button.disabled = true;
    button.innerHTML = window.MathCurveLoader
      ? window.MathCurveLoader.markup('加载中…', 'xs')
      : '加载中…';

    fetch(`/api/get_last_submission_code/${problemId}`)
      .then(response => response.json())
      .then(data => {
        if (!data.success) throw new Error(data.message || '加载失败');
        if (leanWorkbenchController) {
          let workspace = data.workspace || data.lean_workspace || null;
          if (typeof workspace === 'string') {
            try {
              workspace = JSON.parse(workspace);
            } catch (_error) {
              workspace = null;
            }
          }
          const files = data.files || workspace?.files;
          if (files) {
            leanWorkbenchController.setWritableFiles(files);
          } else {
            leanWorkbenchController.setActiveValue(data.code || '');
          }
        } else {
          editorAdapter.setValue(data.code || '');
        }
        editorAdapter.focus();
        leanWorkbenchController?.checkNow();
      })
      .catch(error => {
        alert(error.message || '请求失败，请稍后再试');
      })
      .finally(() => {
        button.disabled = false;
        button.innerHTML = originalHtml;
      });
  });
  }

  const editorReady = window.NumOJMonacoReady;
  (editorReady || Promise.resolve(null))
    .catch(() => null)
    .then(initializeProblemEditor);
})();
