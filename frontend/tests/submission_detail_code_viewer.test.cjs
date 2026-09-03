const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')

const frontendRoot = path.resolve(__dirname, '..')
const detailSource = fs.readFileSync(path.join(frontendRoot, 'src/pages/SubmissionDetailPage.tsx'), 'utf8')
const editorSource = fs.readFileSync(path.join(frontendRoot, 'src/components/MonacoEditor.tsx'), 'utf8')
const detailStyles = fs.readFileSync(path.join(frontendRoot, 'public/static/app/submissions/detail.css'), 'utf8')
const globalStyles = fs.readFileSync(path.join(frontendRoot, 'src/styles.css'), 'utf8')

test('提交详情恢复 Jinja 版只读 Monaco、Lean 多文件模型与 AI 标注能力', () => {
  assert.match(detailSource, /<MonacoEditor language="lean4"[\s\S]*readOnly bundle="full"/)
  assert.match(detailSource, /<MonacoEditor language=\{data\.plang \|\| 'matlab'\}[\s\S]*readOnly bundle="full"/)
  assert.match(detailSource, /submission-code-surface submission-code-viewer/)
  assert.match(detailSource, /monaco\.editor\.createModel\(item\.content/)
  assert.match(detailSource, /saveViewState\?\.\(\)/)
  assert.match(detailSource, /restoreViewState\?\.\(viewState\)/)
  assert.match(detailSource, /setDisplayCode:[\s\S]*selectFile\(defaultPath\)/)
  assert.match(detailSource, /submission\.status === 'Unaccepted' \? <AiTutor/)
  assert.match(detailSource, /createDecorationsCollection/)
  assert.match(detailSource, /monaco-ai-issue-underline/)
  assert.match(editorSource, /readOnly/)
  assert.match(editorSource, /onReady/)
})

test('触屏和手机端使用 Safari 原生惯性滚动的静态代码查看器', () => {
  assert.match(detailSource, /nativeCodeViewerQuery = '\(max-width: 991\.98px\), \(hover: none\) and \(pointer: coarse\)'/)
  assert.match(detailSource, /nativeViewer \? <ReadonlyCodeViewer[\s\S]*: <MonacoEditor language="lean4"/)
  assert.match(detailSource, /nativeCodeViewer \? <ReadonlyCodeViewer[\s\S]*: <MonacoEditor language=\{data\.plang \|\| 'matlab'\}/)
  assert.match(globalStyles, /\.submission-static-code-viewer \{[\s\S]*?overflow-y: auto;[\s\S]*?-webkit-overflow-scrolling: touch;[\s\S]*?touch-action: pan-y;/)
  assert.match(detailSource, /disabled=\{loading\}/)
})

test('提交详情编辑器加载动画和文案使用白色', () => {
  assert.match(editorSource, /colorA="var\(--problem-editor-loading-color-a, #fb923c\)"/)
  assert.match(editorSource, /colorB="var\(--problem-editor-loading-color-b, #f97316\)"/)
  assert.match(detailStyles, /\.submission-code-surface \.problem-editor-loading-state \{[\s\S]*?--problem-editor-loading-color-a: #ffffff;[\s\S]*?--problem-editor-loading-color-b: #ffffff;[\s\S]*?color: #ffffff;[\s\S]*?\}/)
})

test('提交详情只读代码查看器不显示文本光标', () => {
  assert.match(detailStyles, /\.submission-code-viewer \.monaco-editor \.cursors-layer \{\s*display: none;/)
  assert.match(detailStyles, /\.submission-code-viewer \.monaco-editor \.monaco-mouse-cursor-text,[\s\S]*?\.submission-code-viewer textarea\[readonly\] \{[\s\S]*?caret-color: transparent;[\s\S]*?cursor: default;/)
})
