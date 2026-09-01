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

test('提交列表不渲染表头，手机端列表使用对称水平留白', () => {
  assert.doesNotMatch(source, /<thead>|提交号<\/th>|状态<\/th>|得分<\/th>|题目<\/th>/)
  assert.match(source, /<table className="submission-data-table" aria-label="提交记录"><tbody>/)
  assert.match(styles, /@media \(max-width: 767\.98px\)[\s\S]*\.submission-master-detail \{\s*padding: 14px 12px 0;/)
})
