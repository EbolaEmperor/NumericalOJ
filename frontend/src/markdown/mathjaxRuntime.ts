type MathJaxRuntime = {
  startup?: {
    defaultReady?: () => void
    promise?: Promise<unknown>
  }
  typesetClear?: (roots: Element[]) => void
  typesetPromise?: (roots: Element[]) => Promise<unknown>
}

type MathJaxGlobal = typeof globalThis & {MathJax?: MathJaxRuntime | Record<string, unknown>}

const SCRIPT_URL = '/static/vendor/mathjax/tex-mml-chtml.js'
let loadPromise: Promise<MathJaxRuntime> | null = null
let typesetQueue: Promise<unknown> = Promise.resolve()

function currentRuntime() {
  return (globalThis as MathJaxGlobal).MathJax as MathJaxRuntime | undefined
}

function configureRuntime(resolve: (runtime: MathJaxRuntime) => void, reject: (error: unknown) => void) {
  const global = globalThis as MathJaxGlobal
  global.MathJax = {
    startup: {
      typeset: false,
      ready: () => {
        try {
          const runtime = currentRuntime()
          runtime?.startup?.defaultReady?.()
          void runtime?.startup?.promise?.then(() => {
            const readyRuntime = currentRuntime()
            if (readyRuntime?.typesetPromise) resolve(readyRuntime)
            else reject(new Error('MathJax 排版接口不可用'))
          }, reject)
        } catch (error) {
          reject(error)
        }
      },
    },
    loader: {load: []},
    tex: {
      inlineMath: [['$', '$'], ['\\(', '\\)']],
      displayMath: [['$$', '$$'], ['\\[', '\\]']],
      packages: ['base', 'ams', 'newcommand', 'noundefined'],
    },
    options: {enableMenu: false},
  }
}

function loadMathJax() {
  const readyRuntime = currentRuntime()
  if (readyRuntime?.typesetPromise) return Promise.resolve(readyRuntime)
  if (loadPromise) return loadPromise
  loadPromise = new Promise<MathJaxRuntime>((resolve, reject) => {
    configureRuntime(resolve, reject)
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${SCRIPT_URL}"]`)
    const script = existing || document.createElement('script')
    const fail = () => reject(new Error('MathJax 资源加载失败'))
    script.addEventListener('error', fail, {once: true})
    if (!existing) {
      script.src = SCRIPT_URL
      script.async = true
      script.dataset.numojReactAsset = 'true'
      document.head.appendChild(script)
    }
  }).catch((error) => {
    loadPromise = null
    throw error
  })
  return loadPromise
}

export function typesetMath(root: HTMLElement) {
  typesetQueue = typesetQueue.catch(() => undefined).then(async () => {
    const runtime = await loadMathJax()
    if (!root.isConnected) return
    runtime.typesetClear?.([root])
    await runtime.typesetPromise?.([root])
  })
  return typesetQueue
}

export function clearMath(root: HTMLElement) {
  typesetQueue = typesetQueue.catch(() => undefined).then(() => {
    currentRuntime()?.typesetClear?.([root])
  })
}
