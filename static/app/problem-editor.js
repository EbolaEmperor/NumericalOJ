(function () {
  'use strict';

  async function initializeProblemEditor() {
  const textarea = document.getElementById('codeEditor');
  if (!textarea) return;

  const editorHost = document.getElementById('monacoEditorContainer');
  const editorShell = document.getElementById('desktopEditorShell');
  const editorLoading = document.getElementById('monacoEditorLoading');
  const codeMirrorHost = document.getElementById('codeMirrorContainer');
  const form = textarea.closest('form');
  const language = (editorHost?.dataset.language || 'matlab').toLowerCase();
  const monacoLanguage = language === 'py' ? 'python'
    : language === 'octave' ? 'matlab'
    : language;
  const desktop = window.matchMedia('(min-width: 992px)').matches;
  let editorAdapter = null;

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

  async function registerSemanticTokens(monaco) {
    if (!['c', 'cpp', 'py', 'python', 'matlab', 'octave'].includes(language)) return null;
    const problemId = Number(document.getElementById('problemMeta')?.dataset.problemId);
    if (!Number.isInteger(problemId) || problemId <= 0) return null;

    const legendResponse = await fetch(
      `/api/editor/semantic-token-legend?language=${encodeURIComponent(language)}`,
      {
        credentials: 'same-origin',
        headers: { Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest' }
      }
    );
    if (!legendResponse.ok) throw new Error('结构化高亮 legend 不可用');
    const legendPayload = await legendResponse.json();
    const legend = legendPayload?.legend;
    if (!legendPayload?.success || !Array.isArray(legend?.tokenTypes)
        || !Array.isArray(legend?.tokenModifiers)) {
      throw new Error('结构化高亮 legend 格式无效');
    }

    let warned = false;
    return monaco.languages.registerDocumentSemanticTokensProvider(monacoLanguage, {
      getLegend: () => legend,
      provideDocumentSemanticTokens: async (model, _lastResultId, cancellationToken) => {
        const controller = new AbortController();
        const cancellation = cancellationToken.onCancellationRequested(
          () => controller.abort()
        );
        try {
          const response = await fetch('/api/editor/semantic-tokens', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
              Accept: 'application/json',
              'Content-Type': 'application/json',
              'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({
              problem_id: problemId,
              language,
              source: model.getValue()
            }),
            signal: controller.signal
          });
          if (!response.ok) throw new Error(`语言服务返回 ${response.status}`);
          const payload = await response.json();
          if (!payload?.success || !Array.isArray(payload.data)
              || payload.data.length % 5 !== 0) {
            throw new Error('结构化高亮 token 数据格式无效');
          }
          warned = false;
          return {
            data: new Uint32Array(payload.data),
            resultId: String(payload.result_id || '')
          };
        } catch (error) {
          if (error?.name === 'AbortError') return null;
          if (!warned) {
            console.warn('结构化高亮失败，已保留 TextMate 着色。', error);
            warned = true;
          }
          return { data: new Uint32Array(0) };
        } finally {
          cancellation.dispose();
        }
      },
      releaseDocumentSemanticTokens: () => {}
    });
  }

  function registerMatlab(monaco) {
    if (monaco.languages.getLanguages().some(item => item.id === 'matlab')) return;

    monaco.languages.register({ id: 'matlab', extensions: ['.m'], aliases: ['MATLAB', 'matlab'] });
    monaco.languages.setLanguageConfiguration('matlab', {
      comments: { lineComment: '%' },
      brackets: [['(', ')'], ['[', ']'], ['{', '}']],
      autoClosingPairs: [
        { open: '(', close: ')' },
        { open: '[', close: ']' },
        { open: '{', close: '}' },
        { open: "'", close: "'", notIn: ['string', 'comment'] },
        { open: '"', close: '"', notIn: ['string', 'comment'] }
      ],
      surroundingPairs: [
        { open: '(', close: ')' },
        { open: '[', close: ']' },
        { open: '{', close: '}' },
        { open: "'", close: "'" },
        { open: '"', close: '"' }
      ],
      indentationRules: {
        increaseIndentPattern: /^\s*(?:if|for|while|switch|try|function|classdef|properties|methods|events|enumeration)\b(?!.*\bend\b).*$/i,
        decreaseIndentPattern: /^\s*(?:end|else|elseif|case|otherwise|catch)\b/i
      }
    });
    monaco.languages.setMonarchTokensProvider('matlab', {
      defaultToken: '',
      tokenPostfix: '.matlab',
      ignoreCase: false,
      keywords: [
        'break', 'case', 'catch', 'classdef', 'continue', 'else', 'elseif', 'end',
        'enumeration', 'events', 'for', 'function', 'global', 'if', 'methods',
        'otherwise', 'parfor', 'persistent', 'properties', 'return', 'spmd',
        'switch', 'try', 'while'
      ],
      constants: ['true', 'false', 'NaN', 'Inf', 'pi', 'eps'],
      operators: ['+', '-', '*', '/', '\\', '^', '~', '<', '>', '=', '&', '|', ':', '@'],
      tokenizer: {
        root: [
          [/%\{/, 'comment', '@commentBlock'],
          [/%.*$/, 'comment'],
          [/[a-zA-Z_]\w*/, { cases: { '@keywords': 'keyword', '@constants': 'constant', '@default': 'identifier' } }],
          [/\d*\.\d+(?:[eE][+-]?\d+)?[ij]?/, 'number.float'],
          [/\d+(?:[eE][+-]?\d+)?[ij]?/, 'number'],
          [/\.\.\..*$/, 'keyword'],
          [/'(?:[^']|'')*'/, 'string'],
          [/"(?:[^"]|"")*"/, 'string'],
          [/[{}()\[\]]/, '@brackets'],
          [/[+\-*\/\\^~<>=&|:@.]+/, 'operator'],
          [/[;,]/, 'delimiter']
        ],
        commentBlock: [
          [/%\}/, 'comment', '@pop'],
          [/./, 'comment']
        ]
      }
    });
  }

  async function createMonacoAdapter() {
    const monaco = window.NumericalOJMonaco;
    if (!desktop || !editorHost || !monaco?.editor || !monaco?.languages) return null;

    registerMatlab(monaco);
    let editorTheme = 'vs-dark';
    if (typeof monaco.prepareTextMateHighlighting === 'function') {
      try {
        await monaco.prepareTextMateHighlighting();
        editorTheme = 'dark-plus';
      } catch (error) {
        console.warn('VS Code 语法 grammar 初始化失败，已降级为 Monaco 基础着色。', error);
      }
    }
    try {
      await registerSemanticTokens(monaco);
    } catch (error) {
      console.warn('语言服务初始化失败，已保留 TextMate 着色。', error);
    }
    editorHost.hidden = false;
    const instance = monaco.editor.create(editorHost, {
      value: textarea.value,
      language: monacoLanguage,
      theme: editorTheme,
      'semanticHighlighting.enabled': true,
      automaticLayout: true,
      ariaLabel: '代码编辑器',
      fontFamily: 'SFMono-Regular, Consolas, Liberation Mono, Menlo, monospace',
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
      wordWrap: 'on',
      bracketPairColorization: { enabled: true },
      guides: { bracketPairs: true, indentation: true },
      quickSuggestions: false,
      suggestOnTriggerCharacters: false,
      contextmenu: true,
      find: { addExtraSpaceOnTop: false }
    });
    textarea.hidden = true;
    revealMonacoEditor(instance);
    return {
      getValue: () => instance.getValue(),
      setValue: value => instance.setValue(value),
      focus: () => instance.focus(),
      layout: () => instance.layout()
    };
  }

  function createCodeMirrorAdapter() {
    if (desktop || typeof window.CodeMirror === 'undefined' || !codeMirrorHost) return null;
    const mode = language === 'cpp' ? 'text/x-c++src'
      : language === 'c' ? 'text/x-csrc'
      : (language === 'python' || language === 'py') ? 'python'
      : 'octave';
    const instance = window.CodeMirror.fromTextArea(textarea, {
      mode,
      theme: 'eclipse',
      lineNumbers: true,
      lineWrapping: true,
      indentUnit: 4,
      tabSize: 4,
      matchBrackets: true,
      autofocus: true,
      extraKeys: { Tab: 'indentMore', 'Shift-Tab': 'indentLess' }
    });
    codeMirrorHost.appendChild(instance.getWrapperElement());
    instance.setSize(null, '300px');
    instance.getWrapperElement().style.fontFamily = 'monospace';
    instance.getWrapperElement().style.fontSize = '14px';
    return {
      getValue: () => instance.getValue(),
      setValue: value => instance.setValue(value),
      focus: () => instance.focus(),
      layout: () => instance.refresh()
    };
  }

  try {
    editorAdapter = await createMonacoAdapter() || createCodeMirrorAdapter();
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

  form?.addEventListener('submit', function () {
    textarea.value = editorAdapter.getValue();
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
        editorAdapter.setValue(data.code || '');
        editorAdapter.focus();
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

  const editorReady = window.matchMedia('(min-width: 992px)').matches
    ? window.NumOJMonacoReady
    : window.NumOJCodeMirrorReady;
  (editorReady || Promise.resolve(null))
    .catch(() => null)
    .then(initializeProblemEditor);
})();
