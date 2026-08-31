import type {MonacoApi} from './types'

let monacoPromise: Promise<MonacoApi> | null = null

function ensureStylesheet(href: string) {
  if (document.querySelector(`link[href="${href}"]`)) return
  const link = document.createElement('link')
  link.rel = 'stylesheet'
  link.href = href
  link.dataset.numojSpaAsset = 'true'
  document.head.appendChild(link)
}

export function loadMonaco() {
  if (monacoPromise) return monacoPromise
  ensureStylesheet('/static/styles/code-editor.css')
  ensureStylesheet('/static/vendor/monaco/editor-minimal.css')
  ;(globalThis as typeof globalThis & {MonacoEnvironment?: {getWorkerUrl: () => string}}).MonacoEnvironment = {getWorkerUrl: () => '/static/vendor/monaco/editor.worker.js'}
  const source = '/static/vendor/monaco/editor-minimal.js'
  monacoPromise = import(/* @vite-ignore */ source)
    .then((module) => module as unknown as MonacoApi)
    .catch((error) => {monacoPromise = null; throw error})
  return monacoPromise
}
