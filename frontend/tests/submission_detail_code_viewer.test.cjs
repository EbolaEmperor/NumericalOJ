const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')

const frontendRoot = path.resolve(__dirname, '..')
const detailSource = fs.readFileSync(path.join(frontendRoot, 'src/pages/SubmissionDetailPage.tsx'), 'utf8')
const viewerSource = fs.readFileSync(path.join(frontendRoot, 'src/components/ReadonlyCodeViewer.tsx'), 'utf8')
const editorSource = fs.readFileSync(path.join(frontendRoot, 'src/components/MonacoEditor.tsx'), 'utf8')
const stylesSource = fs.readFileSync(path.join(frontendRoot, 'src/styles.css'), 'utf8')

test('提交详情的普通代码与 Lean 文件统一使用浏览器原生滚动的静态查看器', () => {
  assert.match(detailSource, /<ReadonlyCodeViewer[\s\S]*language="lean4"/)
  assert.match(detailSource, /<ReadonlyCodeViewer[\s\S]*language=\{data\.plang \|\| 'matlab'\}/)
  assert.match(detailSource, /submission-code-surface submission-code-viewer/)
  assert.doesNotMatch(detailSource, /MonacoEditor|attachReadonlyEditorTouchHandoff|onTouchMove/)

  assert.match(viewerSource, /<div className="submission-static-code-viewer" role="region"/)
  assert.doesNotMatch(viewerSource, /textarea|contentEditable|addEventListener|scrollBy|touchstart|touchmove/)
  assert.match(stylesSource, /\.submission-static-code-viewer \{[\s\S]*overflow-y: auto;[\s\S]*overscroll-behavior-y: auto;[\s\S]*-webkit-overflow-scrolling: touch;[\s\S]*touch-action: pan-y;/)

  assert.doesNotMatch(editorSource, /viewer|data-editor-mode|monaco-viewer-fallback/)
})
