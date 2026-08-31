import {useEffect, useRef, useState} from 'react'

type Disposable = {dispose: () => void}

export type MonacoEditorInstance = {
  dispose: () => void
  focus: () => void
  getValue: () => string
  layout: () => void
  onDidChangeModelContent: (listener: () => void) => Disposable
  setValue: (value: string) => void
  [key: string]: unknown
}

export type MonacoApi = {
  editor: {
    create: (element: HTMLElement, options: Record<string, unknown>) => MonacoEditorInstance
    [key: string]: unknown
  }
  languages: Record<string, unknown>
  [key: string]: unknown
}

export type MonacoEditorReadyContext = {
  monaco: MonacoApi
  editor: MonacoEditorInstance
  textarea: HTMLTextAreaElement | null
}

type EditorRuntime = {
  forLanguage: (language: string) => {language: string; monacoLanguage: string}
  monacoOptions: (overrides: Record<string, unknown>) => Record<string, unknown>
  prepareMonaco: (monaco: MonacoApi) => Promise<string>
}

type SemanticTokensRuntime = {
  register: (monaco: MonacoApi, options: Record<string, unknown>) => Promise<unknown>
}

declare global {
  interface Window {
    MonacoEnvironment?: {getWorkerUrl: () => string}
    NumOJCodeEditorRuntime?: EditorRuntime
    NumOJSemanticTokens?: SemanticTokensRuntime
    NumericalOJMonaco?: MonacoApi
  }
}

let runtimePromise: Promise<MonacoApi | null> | null = null

function ensureStylesheet(href: string) {
  if (document.querySelector(`link[href="${href}"]`)) return
  const link = document.createElement('link')
  link.rel = 'stylesheet'
  link.href = href
  link.dataset.numojSpaAsset = 'true'
  document.head.appendChild(link)
}

function loadScript(src: string) {
  const existing = document.querySelector<HTMLScriptElement>(`script[src="${src}"]`)
  if (existing?.dataset.loaded === 'true') return Promise.resolve()
  return new Promise<void>((resolve, reject) => {
    const script = existing || document.createElement('script')
    const finish = () => {
      script.dataset.loaded = 'true'
      resolve()
    }
    script.addEventListener('load', finish, {once: true})
    script.addEventListener('error', () => reject(new Error(`无法加载 ${src}`)), {once: true})
    if (!existing) {
      script.src = src
      script.async = true
      script.dataset.numojSpaAsset = 'true'
      document.head.appendChild(script)
    }
  })
}

function loadMonacoRuntime() {
  if (window.NumericalOJMonaco?.editor && window.NumOJCodeEditorRuntime) {
    return Promise.resolve(window.NumericalOJMonaco)
  }
  if (runtimePromise) return runtimePromise
  runtimePromise = (async () => {
    ensureStylesheet('/static/styles/code-editor.css')
    ensureStylesheet('/static/vendor/monaco/editor-minimal.css')
    window.MonacoEnvironment = {
      getWorkerUrl: () => '/static/vendor/monaco/editor.worker.js',
    }
    await Promise.all([
      window.NumOJSemanticTokens ? Promise.resolve() : loadScript('/static/app/editor-semantic-tokens.js'),
      window.NumOJCodeEditorRuntime ? Promise.resolve() : loadScript('/static/app/code-editor-runtime.js'),
    ])
    if (!window.NumericalOJMonaco) await loadScript('/static/vendor/monaco/editor-minimal.js')
    return window.NumericalOJMonaco || null
  })().catch((error) => {
    console.error('代码编辑器初始化失败，已降级到文本框。', error)
    return null
  })
  return runtimePromise
}

export function MonacoEditor({
  language,
  problemId,
  value,
  onChange,
  idPrefix = 'problem',
  ariaLabel = '代码编辑器',
  readOnly = false,
  fontSize = 12.5,
  lineHeight = 20,
  shellClassName = '',
  hostClassName = '',
  fallbackClassName = 'numoj-code-textarea-fallback',
  shellBaseClassName = 'problem-editor-shell',
  onReady,
}: {
  language: string
  problemId: number
  value: string
  onChange: (value: string) => void
  idPrefix?: string
  ariaLabel?: string
  readOnly?: boolean
  fontSize?: number
  lineHeight?: number
  shellClassName?: string
  hostClassName?: string
  fallbackClassName?: string
  shellBaseClassName?: string
  onReady?: (context: MonacoEditorReadyContext) => void | (() => void) | Promise<void | (() => void)>
}) {
  const hostRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const editorRef = useRef<MonacoEditorInstance | null>(null)
  const valueRef = useRef(value)
  const onChangeRef = useRef(onChange)
  const onReadyRef = useRef(onReady)
  const [fallback, setFallback] = useState(false)
  const [ready, setReady] = useState(false)

  valueRef.current = value
  onChangeRef.current = onChange
  onReadyRef.current = onReady

  useEffect(() => {
    let disposed = false
    let changeSubscription: Disposable | null = null
    let resizeObserver: ResizeObserver | null = null
    let readyCleanup: (() => void) | null = null

    const initialize = async () => {
      const monaco = await loadMonacoRuntime()
      const host = hostRef.current
      const runtime = window.NumOJCodeEditorRuntime
      if (disposed) return
      if (!monaco?.editor || !monaco.languages || !host || !runtime) {
        setFallback(true)
        setReady(true)
        return
      }

      try {
        const normalizedLanguage = String(language || 'matlab').toLowerCase()
        const languageSpec = runtime.forLanguage(normalizedLanguage)
        const theme = await runtime.prepareMonaco(monaco)
        if (disposed) return
        if (!['lean', 'lean4'].includes(normalizedLanguage)) {
          window.NumOJSemanticTokens?.register(monaco, {
            language: normalizedLanguage,
            monacoLanguage: languageSpec.monacoLanguage,
            problemId,
          }).catch((error) => console.warn('语言服务初始化失败，已保留 TextMate 着色。', error))
        }
        const editor = monaco.editor.create(host, runtime.monacoOptions({
          value: valueRef.current,
          language: languageSpec.monacoLanguage,
          theme,
          ariaLabel,
          readOnly,
          domReadOnly: readOnly,
          fontSize,
          lineHeight,
          tabSize: ['lean', 'lean4'].includes(normalizedLanguage) ? 2 : 4,
        }))
        editorRef.current = editor
        changeSubscription = editor.onDidChangeModelContent(() => {
          const nextValue = editor.getValue()
          valueRef.current = nextValue
          onChangeRef.current(nextValue)
        })
        resizeObserver = new ResizeObserver(() => editor.layout())
        resizeObserver.observe(host)
        const cleanup = await onReadyRef.current?.({monaco, editor, textarea: textareaRef.current})
        if (typeof cleanup === 'function') {
          if (disposed) cleanup()
          else readyCleanup = cleanup
        }
        if (disposed) return
        requestAnimationFrame(() => {
          editor.layout()
          requestAnimationFrame(() => {
            if (!disposed) setReady(true)
          })
        })
      } catch (error) {
        console.error('代码编辑器初始化失败，已降级到文本框。', error)
        if (!disposed) {
          setFallback(true)
          setReady(true)
        }
      }
    }

    void initialize()
    return () => {
      disposed = true
      readyCleanup?.()
      resizeObserver?.disconnect()
      changeSubscription?.dispose()
      editorRef.current?.dispose()
      editorRef.current = null
    }
  }, [ariaLabel, fontSize, language, lineHeight, problemId, readOnly])

  useEffect(() => {
    const editor = editorRef.current
    if (editor && editor.getValue() !== value) editor.setValue(value)
  }, [value])

  return <>
    <textarea
      ref={textareaRef}
      id={`${idPrefix}CodeEditor`}
      name="code"
      className={fallback ? fallbackClassName : undefined}
      hidden={!fallback}
      readOnly={readOnly}
      spellCheck={false}
      autoComplete="off"
      value={value}
      onChange={(event) => onChange(event.target.value)}
    />
    <div
      id={`${idPrefix}EditorShell`}
      className={`${shellBaseClassName}${shellClassName ? ` ${shellClassName}` : ''}`}
      data-editor-state={ready ? 'ready' : 'loading'}
      aria-busy={ready ? 'false' : 'true'}
      hidden={fallback}
    >
      <div id={`${idPrefix}EditorLoading`} className="problem-editor-loading-state" hidden={ready}>
        <span className="math-curve-loader problem-editor-loading-indicator" data-math-curve-loader data-size="lg" data-color-a="#fb923c" data-color-b="#f97316">
          <span className="math-curve-loader__label">代码编辑器正在加载</span>
        </span>
      </div>
      <div ref={hostRef} id={`${idPrefix}EditorContainer`} className={hostClassName || undefined} data-language={language} />
    </div>
  </>
}
