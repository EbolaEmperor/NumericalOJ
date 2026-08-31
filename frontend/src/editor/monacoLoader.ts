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
  monacoPromise = import(/* @vite-ignore */ source)
    .then((module) => module as unknown as MonacoApi)
    .catch((error) => {monacoPromise = null; throw error})
  return monacoPromise
}
