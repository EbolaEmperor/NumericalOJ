const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const {JSDOM} = require('jsdom')

const loaderSource = fs.readFileSync(
  path.join(__dirname, '../public/static/math-curve-loaders/loader.js'),
  'utf8',
)

function createPage() {
  const dom = new JSDOM(
    '<!doctype html><html><body><div id="root"><main><div class="numoj-spa-route"><section data-math-curve-scope="component"><button type="button">运行</button></section></div></main></div></body></html>',
    {pretendToBeVisual: true, runScripts: 'dangerously', url: 'http://localhost/'},
  )
  dom.window.matchMedia = () => ({matches: true})
  dom.window.eval(loaderSource)
  return dom
}

function waitForTimer() {
  return new Promise((resolve) => setTimeout(resolve, 10))
}

test('页面加载曲线直接挂载到当前页面且不会创建蒙版弹窗', async () => {
  const dom = createPage()
  await waitForTimer()
  const end = dom.window.MathCurveLoader.begin('正在加载页面…', {delay: 0, scope: 'page'})

  await waitForTimer()

  const route = dom.window.document.querySelector('.numoj-spa-route')
  const indicator = route.querySelector(':scope > .math-curve-loader-request--page')
  assert.ok(indicator)
  assert.equal(route.getAttribute('aria-busy'), 'true')
  assert.equal(dom.window.document.querySelector('.math-curve-loader-overlay'), null)
  assert.equal(dom.window.document.querySelector('.modal-backdrop'), null)

  end()
  assert.equal(route.querySelector('.math-curve-loader-request'), null)
  assert.equal(route.hasAttribute('aria-busy'), false)
  dom.window.close()
})

test('组件加载曲线只渲染在指定组件中', async () => {
  const dom = createPage()
  await waitForTimer()
  const component = dom.window.document.querySelector('[data-math-curve-scope="component"]')
  const end = dom.window.MathCurveLoader.begin('正在刷新组件…', {
    delay: 0,
    scope: 'component',
    target: component,
  })

  await waitForTimer()

  assert.ok(component.querySelector(':scope > .math-curve-loader-request--component'))
  assert.equal(dom.window.document.body.querySelector(':scope > .math-curve-loader-request'), null)

  end()
  dom.window.close()
})
