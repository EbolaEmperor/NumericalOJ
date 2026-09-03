const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const assert = require('node:assert/strict')

const frontendRoot = path.resolve(__dirname, '..')
const siteConfigStyles = fs.readFileSync(path.join(frontendRoot, 'public/static/app/site-config.css'), 'utf8')
const layoutStyles = fs.readFileSync(path.join(frontendRoot, 'public/static/app/layout.css'), 'utf8')
const siteConfigPage = fs.readFileSync(path.join(frontendRoot, 'src/pages/SiteConfigPage.tsx'), 'utf8')

test('全站配置的 React 过渡层传递满高并保留正文滚动', () => {
  assert.match(siteConfigStyles, /\.site-config-shell\s*>\s*\.numoj-spa-route\s*\{[^}]*height:\s*100%;[^}]*min-height:\s*0;/s)
  assert.match(siteConfigStyles, /\.site-config-content-scroll\s*\{[^}]*overflow-y:\s*auto;[^}]*scrollbar-width:\s*thin;/s)
  assert.match(siteConfigStyles, /\.site-config-content-scroll::\-webkit-scrollbar-thumb/)
})

test('邮件与联网搜索测试恢复旧版短时 toast 反馈', () => {
  assert.doesNotMatch(siteConfigPage, /site-config-form-status/)
  assert.match(siteConfigPage, /测试邮件已发送/)
  assert.match(siteConfigPage, /搜索服务连接正常/)
  assert.match(siteConfigPage, /fa-check-circle/)
  assert.match(siteConfigPage, /tone === 'error' \? 6500 : 3500/)
})

test('全站配置在 LIVE 右侧显示部署 commit 的前六位', () => {
  assert.match(siteConfigPage, /import\.meta\.env\.VITE_NUMOJ_COMMIT_SHA/)
  assert.match(siteConfigPage, /className="site-config-deploy-commit"/)
  assert.match(siteConfigPage, /deploymentCommit\.slice\(0, 6\)/)
  assert.match(siteConfigStyles, /\.site-config-deploy-commit\s*\{[^}]*border-left:[^}]*font-variant-numeric:\s*tabular-nums;/s)
})

test('邮件与联网搜索并入功能配置并删除其他配置分类', () => {
  assert.match(siteConfigPage, /site-config-feature-card site-config-service-card/)
  assert.match(siteConfigPage, /site-config-services-panel/)
  assert.doesNotMatch(siteConfigPage, /tab === 'other'/)
  assert.doesNotMatch(siteConfigPage, />其他配置</)
  assert.doesNotMatch(siteConfigStyles, /site-config-other-grid/)
})

test('邮件服务在桌面端使用两行两栏字段布局', () => {
  assert.match(siteConfigStyles, /\.site-config-form-grid\s*\{[^}]*grid-template-columns:\s*repeat\(2,\s*minmax\(0,\s*1fr\)\);/s)
  assert.match(siteConfigPage, /<label><span>SMTP 服务器<\/span>/)
  assert.match(siteConfigPage, /<label><span>端口<\/span>/)
  assert.match(siteConfigPage, /<label><span>用户名<\/span>/)
  assert.match(siteConfigPage, /<label><span>密码<\/span>/)
})

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
