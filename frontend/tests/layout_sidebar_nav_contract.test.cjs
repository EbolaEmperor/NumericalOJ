const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const assert = require('node:assert/strict')

const frontendRoot = path.resolve(__dirname, '..')
const layoutStyles = fs.readFileSync(path.join(frontendRoot, 'public/static/app/layout.css'), 'utf8')
const appShell = fs.readFileSync(path.join(frontendRoot, 'src/components/AppShell.tsx'), 'utf8')

test('桌面侧栏链接与账户操作使用相同的整行宽度', () => {
  const desktopStyles = layoutStyles.slice(
    layoutStyles.indexOf('@media (min-width: 992px)'),
    layoutStyles.indexOf('@media (min-width: 992px) and (max-width: 1199.98px)'),
  )

  assert.match(desktopStyles, /\.numoj-nav-item\s*\{[^}]*width:\s*calc\(100% - 16px\);/s)
  assert.match(appShell, /<button className="numoj-nav-item" type="button" title="修改密码"/)
  assert.match(appShell, /<button className="numoj-nav-item" type="button" title="调整班级"/)
})

test('移动侧栏链接与账户操作使用相同的整行宽度', () => {
  const mobileStyles = layoutStyles.slice(layoutStyles.indexOf('@media (max-width: 991.98px)'))

  assert.match(mobileStyles, /\.numoj-mobile-sidebar \.numoj-nav-item\s*\{[^}]*width:\s*calc\(100% - 12px\);/s)
})
