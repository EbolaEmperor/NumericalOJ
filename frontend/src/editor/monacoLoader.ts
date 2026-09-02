import type {MonacoApi} from './types'

const monacoPromises: Partial<Record<'minimal' | 'full', Promise<MonacoApi>>> = {}

function ensureStylesheet(href: string) {
  if (document.querySelector(`link[href="${href}"]`)) return
  const link = document.createElement('link')
  link.rel = 'stylesheet'
  link.href = href
  link.dataset.numojSpaAsset = 'true'
  document.head.appendChild(link)
}

export function loadMonaco(bundle: 'minimal' | 'full' = 'minimal') {
  if (monacoPromises[bundle]) return monacoPromises[bundle]
  ensureStylesheet('/static/styles/code-editor.css')
  const stylesheet = bundle === 'full'
    ? '/static/vendor/monaco/editor.css'
    : '/static/vendor/monaco/editor-minimal.css'
  ensureStylesheet(stylesheet)
  // 直接创建同源模块 Worker。Monaco 的 getWorkerUrl 兼容路径会先生成
  // blob 模块、再从其中 import 带 #label 的 URL；Safari 会把这条链路误报为
  // 404，并让编辑器退回主线程。由模块加载器持有工厂可同时避免 blob 生命周期
  // 和 URL 片段在浏览器之间的差异。
  ;(globalThis as typeof globalThis & {
    MonacoEnvironment?: {getWorker: (_moduleId: string, label: string) => Worker}
  }).MonacoEnvironment = {
    getWorker: (_moduleId, label) => new Worker('/static/vendor/monaco/editor.worker.js', {
      type: 'module',
      name: label,
    }),
  }
  const source = '/static/vendor/monaco/editor-minimal.js'
  const selectedSource = bundle === 'full' ? '/static/vendor/monaco/editor.js' : source
  monacoPromises[bundle] = import(/* @vite-ignore */ selectedSource)
    .then((module) => module as unknown as MonacoApi)
    .catch((error) => {delete monacoPromises[bundle]; throw error})
  return monacoPromises[bundle]
}
