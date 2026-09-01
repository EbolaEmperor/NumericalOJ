const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')

const source = fs.readFileSync(path.resolve(__dirname, '../src/pages/SubmissionsPage.tsx'), 'utf8')

test('提交列表整行统一打开提交详情，题目标题不再跳转题目页', () => {
  assert.match(source, /<span className="submission-problem-title">/)
  assert.doesNotMatch(source, /className="submission-problem-title"\s+to=/)
  assert.match(source, /openSubmission\(row\.id\)/)
  assert.match(source, /to={`\/submissions\/\$\{row\.id\}`}\s+state=/)
})
