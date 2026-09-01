const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')

const frontendRoot = path.resolve(__dirname, '..')

function occurrenceCount(source, text) {
  return source.split(text).length - 1
}

test('页面过渡保留原有退场与入场的时长、延迟和曲线', () => {
  const styles = fs.readFileSync(path.join(frontendRoot, 'src', 'styles.css'), 'utf8')

  assert.equal(occurrenceCount(styles, 'numoj-content-sink 260ms cubic-bezier(.45, 0, .55, 1) both'), 1)
  assert.equal(occurrenceCount(styles, 'numoj-content-dissolve 260ms linear both'), 1)
  assert.equal(occurrenceCount(styles, 'numoj-content-rise 260ms 130ms cubic-bezier(.45, 0, .55, 1) both'), 1)
  assert.equal(occurrenceCount(styles, 'numoj-content-appear 260ms 130ms linear both'), 1)
  assert.doesNotMatch(styles, /::view-transition-/)
})
