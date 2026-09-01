const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')

const frontendRoot = path.resolve(__dirname, '..')
const detailSource = fs.readFileSync(path.join(frontendRoot, 'src/pages/SubmissionDetailPage.tsx'), 'utf8')
const editorSource = fs.readFileSync(path.join(frontendRoot, 'src/components/MonacoEditor.tsx'), 'utf8')

test('提交详情的普通代码与 Lean 文件统一使用不可聚焦的只读查看器', () => {
  assert.match(detailSource, /function SubmissionCodeViewer\(/)
  assert.match(detailSource, /viewer[\s\S]*attachReadonlyEditorTouchHandoff\(editor\)/)
  assert.match(detailSource, /submission-code-surface submission-code-viewer/)
  assert.doesNotMatch(detailSource, /onTouchMoveCapture=/)

  assert.match(editorSource, /const effectiveReadOnly = readOnly \|\| viewer/)
  assert.match(editorSource, /cursorBlinking: 'hidden'/)
  assert.match(editorSource, /tabIndex=\{viewer \? -1 : undefined\}/)
})
