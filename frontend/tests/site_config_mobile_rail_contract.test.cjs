const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const assert = require('node:assert/strict')

const frontendRoot = path.resolve(__dirname, '..')
const siteConfigStyles = fs.readFileSync(path.join(frontendRoot, 'public/static/app/site-config.css'), 'utf8')
const layoutStyles = fs.readFileSync(path.join(frontendRoot, 'public/static/app/layout.css'), 'utf8')

test('全站配置的手机端分类栏沿用全站 layout 宽度', () => {
  assert.match(layoutStyles, /--numoj-mobile-sidebar-width:\s*150px;/)

  const mobileStyles = siteConfigStyles.slice(siteConfigStyles.indexOf('@media (max-width: 991.98px)'))
  assert.match(mobileStyles, /\.site-config-function-rail\s*\{[^}]*width:\s*var\(--numoj-mobile-sidebar-width\);[^}]*max-width:\s*var\(--numoj-mobile-sidebar-width\);/s)
  assert.doesNotMatch(mobileStyles, /\.site-config-function-rail\s*\{[^}]*width:\s*min\(86vw,\s*310px\);/s)
})

test('全站配置的手机端分类按钮与标题栏右侧对齐', () => {
  const tabletStyles = siteConfigStyles.slice(siteConfigStyles.indexOf('@media (max-width: 991.98px)'))
  const phoneStyles = siteConfigStyles.slice(siteConfigStyles.indexOf('@media (max-width: 620px)'))

  assert.match(tabletStyles, /\.site-config-header\s*\{[^}]*padding:\s*13px 15px;/s)
  assert.match(tabletStyles, /\.site-config-mobile-rail-open\s*\{[^}]*justify-self:\s*end;/s)
  assert.match(phoneStyles, /\.site-config-header\s*\{[^}]*padding-inline:\s*12px;/s)
})
