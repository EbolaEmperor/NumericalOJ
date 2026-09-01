const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const assert = require('node:assert/strict')

const frontendRoot = path.resolve(__dirname, '..')
const source = fs.readFileSync(path.join(frontendRoot, 'src/pages/AgentTasksPage.tsx'), 'utf8')
const styles = fs.readFileSync(path.join(frontendRoot, 'public/static/app/agents/task-list.css'), 'utf8')

test('手机端 Harness 与身份选择器折叠时只显示图标', () => {
  assert.match(source, /className="agent-composer-choice agent-composer-choice--harness"/)
  assert.match(source, /className="agent-composer-choice agent-composer-choice--role"/)
  assert.match(source, /className="rk-choice-trigger" role="combobox" aria-label=\{label\}/)

  const mobileStyles = styles.slice(styles.indexOf('@media (max-width: 575.98px)'))
  assert.match(mobileStyles, /\.agent-composer-choice--harness,\s*\.agent-composer-choice--role\s*\{[^}]*width:\s*40px;/)
  assert.match(mobileStyles, /\.agent-composer-choice--harness \.rk-choice-trigger-main > span,\s*\.agent-composer-choice--role \.rk-choice-trigger-main > span\s*\{\s*display:\s*none;/)
})

test('展开菜单仍显示 Harness 与身份名称', () => {
  assert.match(source, /className="rk-choice-option-name">\{option\.label\}<\/span>/)
  assert.doesNotMatch(styles, /rk-choice-option-name[^}]*display:\s*none/)
})
