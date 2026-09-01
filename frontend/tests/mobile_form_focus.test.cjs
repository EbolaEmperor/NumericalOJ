const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')

const frontendRoot = path.resolve(__dirname, '..')
const styles = fs.readFileSync(path.join(frontendRoot, 'src/styles.css'), 'utf8')
const index = fs.readFileSync(path.join(frontendRoot, 'index.html'), 'utf8')

test('触屏 WebKit 的文字输入控件不会因小字号触发 Safari 聚焦放大', () => {
  assert.ok(styles.includes('@supports (-webkit-touch-callout: none)'))
  assert.ok(styles.includes('@media (hover: none) and (pointer: coarse)'))
  assert.ok(styles.includes('input:not([type="hidden"])'))
  assert.ok(styles.includes('select,\n    textarea'))
  assert.ok(styles.includes('font-size: max(16px, 1em) !important;'))
  assert.doesNotMatch(styles, /touch-action:\s*manipulation/)
})

test('viewport 仍允许用户双指缩放', () => {
  assert.doesNotMatch(index, /maximum-scale/i)
  assert.doesNotMatch(index, /user-scalable/i)
})
