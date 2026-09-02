const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')

const source = fs.readFileSync(path.resolve(__dirname, '../src/pages/SubmissionsPage.tsx'), 'utf8')
const styles = fs.readFileSync(path.resolve(__dirname, '../public/static/app/submissions.css'), 'utf8')

test('提交列表整行统一打开提交详情，题目标题不再跳转题目页', () => {
  assert.match(source, /<span className="submission-problem-title">/)
  assert.doesNotMatch(source, /className="submission-problem-title"\s+to=/)
  assert.match(source, /openSubmission\(row\.id\)/)
  assert.match(source, /to={`\/submissions\/\$\{row\.id\}`}\s+state=/)
})

test('提交列表恢复桌面表头与主从选择，手机端仍使用对称水平留白', () => {
  assert.match(source, /<thead>[\s\S]*提交号<\/th>[\s\S]*状态<\/th>[\s\S]*得分<\/th>[\s\S]*题目<\/th>/)
  assert.match(source, /aria-selected=\{selectedId === row\.id\}/)
  assert.match(source, /desktop \? setSelectedId\(row\.id\) : openSubmission\(row\.id\)/)
  assert.match(source, /<Panel id=\{desktop \? selectedId : undefined\}/)
  assert.match(source, /event\.key === 'Enter' \|\| event\.key === ' '/)
  const mobileStyles = styles.slice(styles.indexOf('@media (max-width: 767.98px)'))
  assert.match(mobileStyles, /\.submission-page-header \{\s*padding: 0 12px 10px;/)
  assert.match(mobileStyles, /\.submission-filter-panel \{\s*padding-right: 12px;\s*padding-left: 12px;/)
  assert.match(mobileStyles, /\.submission-status-filters \{[^}]*margin-right: 0;\s*padding-right: 0;/)
  assert.match(mobileStyles, /\.submission-master-detail \{\s*padding: 14px 12px 0;/)
})
