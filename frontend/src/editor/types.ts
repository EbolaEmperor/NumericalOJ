export type Disposable = {dispose: () => void}

export type MonacoPosition = {lineNumber: number; column: number}

export type MonacoModel = {
  dispose: () => void
  getLineContent?: (line: number) => string
  getValue: () => string
  getVersionId: () => number
  onDidChangeContent: (listener: () => void) => Disposable
  onWillDispose?: (listener: () => void) => Disposable
  deltaDecorations?: (oldDecorations: string[], newDecorations: unknown[]) => string[]
  isDisposed?: () => boolean
  setValue?: (value: string) => void
  validateRange?: (range: unknown) => unknown
}

export type MonacoEditorInstance = {
  blur?: () => void
  dispose: () => void
  focus: () => void
  getDomNode?: () => HTMLElement | null
  getModel?: () => MonacoModel | null
  getPosition?: () => MonacoPosition | null
  getLayoutInfo?: () => {height: number; [key: string]: unknown}
  getScrollHeight?: () => number
  getScrollTop?: () => number
  getValue: () => string
  layout: () => void
  onDidChangeCursorPosition?: (listener: (event: {position?: MonacoPosition}) => void) => Disposable
  onDidChangeModelContent: (listener: () => void) => Disposable
  restoreViewState?: (state: unknown) => void
  revealLineInCenter?: (line: number) => void
  saveViewState?: () => unknown
  setModel?: (model: MonacoModel) => void
  setPosition?: (position: MonacoPosition) => void
  setValue: (value: string) => void
  updateOptions?: (options: Record<string, unknown>) => void
  [key: string]: unknown
}

export type MonacoApi = {
  editor: {
    create: (element: HTMLElement, options: Record<string, unknown>) => MonacoEditorInstance
    createModel: (value: string, language?: string, uri?: unknown) => MonacoModel
    setModelMarkers: (model: MonacoModel, owner: string, markers: unknown[]) => void
    setTheme?: (theme: string) => void
    [key: string]: unknown
  }
  languages: {
    CompletionItemInsertTextRule?: {InsertAsSnippet: number}
    CompletionItemKind?: {Text: number}
    getLanguages: () => Array<{id: string}>
    register: (definition: Record<string, unknown>) => void
    registerCompletionItemProvider: (language: string, provider: Record<string, unknown>) => Disposable
    registerDocumentSemanticTokensProvider?: (language: string, provider: Record<string, unknown>) => Disposable
    setLanguageConfiguration: (language: string, configuration: Record<string, unknown>) => void
    setMonarchTokensProvider: (language: string, provider: Record<string, unknown>) => void
    [key: string]: unknown
  }
  Uri: {parse: (value: string) => unknown}
  Range: new (startLine: number, startColumn: number, endLine: number, endColumn: number) => unknown
  MarkerSeverity: {Error: number; Warning: number; Info: number; Hint: number}
  attachLean4UnicodeInput?: (editor: MonacoEditorInstance) => Disposable
  getLean4UnicodeAbbreviations?: () => Record<string, string>
  prepareTextMateHighlighting?: () => Promise<unknown>
  [key: string]: unknown
}

export type MonacoEditorReadyContext = {
  monaco: MonacoApi
  editor: MonacoEditorInstance
  textarea: HTMLTextAreaElement | null
}
