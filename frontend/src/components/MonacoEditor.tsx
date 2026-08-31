import {useEffect, useRef, useState} from 'react'

import {attachLeanUnicodeInput, languageSpec, monacoOptions, prepareMonaco} from '../editor/codeEditorRuntime'
import {loadMonaco} from '../editor/monacoLoader'
import {registerSemanticTokens} from '../editor/semanticTokens'
import type {Disposable, MonacoEditorInstance, MonacoEditorReadyContext} from '../editor/types'
import {MathCurveLoader} from './MathCurveLoader'

export type {MonacoApi, MonacoEditorInstance, MonacoEditorReadyContext} from '../editor/types'

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
    let unicodeSubscription: Disposable | null = null
    let semanticRegistration: Disposable | null = null
    let semanticController: AbortController | null = null
    let resizeObserver: ResizeObserver | null = null
    let readyCleanup: (() => void) | null = null

    const initialize = async () => {
      try {
        const monaco = await loadMonaco()
        const host = hostRef.current
        if (disposed || !host) return

        const normalizedLanguage = String(language || 'matlab').toLowerCase()
        const spec = languageSpec(normalizedLanguage)
        const theme = prepareMonaco(monaco)
        const editor = monaco.editor.create(host, monacoOptions({
          value: valueRef.current,
          language: spec.monacoLanguage,
          theme,
          ariaLabel,
          readOnly,
          domReadOnly: readOnly,
          fontSize,
          lineHeight,
          tabSize: ['lean', 'lean4'].includes(normalizedLanguage) ? 2 : 4,
        }))
        editorRef.current = editor
        if (['lean', 'lean4'].includes(normalizedLanguage)) unicodeSubscription = attachLeanUnicodeInput(monaco, editor)
        else {
          // 语义服务在编辑器显示之后注册；TextMate/Monarch 的当前配色不会被网络请求阻塞。
          semanticController = new AbortController()
          void registerSemanticTokens(monaco, {language: normalizedLanguage, monacoLanguage: spec.monacoLanguage, problemId, signal: semanticController.signal})
            .then((registration) => {
              if (!registration) return
              if (disposed) registration.dispose()
              else semanticRegistration = registration
            })
            .catch((error) => {if (!(error instanceof DOMException && error.name === 'AbortError')) console.warn('语言服务初始化失败，已保留当前配色。', error)})
        }
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
      unicodeSubscription?.dispose()
      semanticController?.abort()
      semanticRegistration?.dispose()
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
        <MathCurveLoader className="problem-editor-loading-indicator" size="lg" colorA="#fb923c" colorB="#f97316" label="代码编辑器正在加载" />
      </div>
      <div ref={hostRef} id={`${idPrefix}EditorContainer`} className={hostClassName || undefined} data-language={language} />
    </div>
  </>
}
