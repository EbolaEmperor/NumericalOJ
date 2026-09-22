const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')

const source = fs.readFileSync(path.resolve(__dirname, '../src/pages/SubmissionsPage.tsx'), 'utf8')
const styles = fs.readFileSync(path.resolve(__dirname, '../public/static/app/submissions.css'), 'utf8')
const detailSource = fs.readFileSync(path.resolve(__dirname, '../src/pages/SubmissionDetailPage.tsx'), 'utf8')
const detailStyles = fs.readFileSync(path.resolve(__dirname, '../public/static/app/submissions/detail.css'), 'utf8')

test('提交列表整行统一打开提交详情，题目标题不再跳转题目页', () => {
  assert.match(source, /<span className="submission-problem-title">/)
  assert.doesNotMatch(source, /className="submission-problem-title"\s+to=/)
  assert.match(source, /openSubmission\(row\.id\)/)
  assert.match(source, /to={`\/submissions\/\$\{row\.id\}`}\s+state=/)
})

test('提交列表隐藏视觉表头并保留主从选择，手机端仍使用对称水平留白', () => {
  assert.match(source, /<thead className="visually-hidden">[\s\S]*提交号<\/th>[\s\S]*状态<\/th>[\s\S]*得分<\/th>[\s\S]*题目<\/th>/)
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

test('时间范围重测弹窗在 Portal 中仍保留提交页按钮颜色', () => {
  assert.match(source, /className="submission-rejudge-modal"/)
  assert.match(styles, /\.submission-rejudge-modal \{[\s\S]*--submission-accent: #d97706;[\s\S]*--submission-accent-dark: #92400e;/)
})

test('提交详情的 AI 评委按模型名称显示 Logo', () => {
  assert.match(detailSource, /import \{ModelLogo\} from '\.\.\/components\/ModelLogo'/)
  assert.match(detailSource, /active\.kind === 'vote' \? <ModelLogo model=\{active\.model\} \/>/)
  assert.match(detailStyles, /\.submission-vote-identity \[data-model-family-logo\] \{[\s\S]*width: 16px;[\s\S]*height: 16px;/)
})
