const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const vm = require('node:vm')

const context = vm.createContext({})
const source = fs.readFileSync(path.join(__dirname, '../public/static/app/model-family.js'), 'utf8')
vm.runInContext(source, context)

test('旧版模型名称规则仍能解析到对应厂商 Logo', () => {
  const {detect, iconClass} = context.NumojModelFamily
  const cases = [
    ['deepseek-r1-distill-qwen-32b', 'deepseek'],
    ['gpt-5.6-codex', 'openai'],
    ['claude-opus-4.1', 'claude'],
    ['gemini-3-pro', 'gemini'],
    ['qwen3.6-plus', 'qwen'],
    ['doubao-seed-2.0-pro', 'doubao'],
    ['glm-5', 'glm'],
    ['kimi-k2', 'kimi'],
    ['llama-4', 'llama'],
    ['mistral-large', 'mistral'],
  ]

  for (const [model, family] of cases) {
    assert.equal(detect(model), family)
    assert.equal(iconClass(model), `model-family-logo model-family-logo--${family}`)
  }

  assert.equal(detect('unknown-local-model'), null)
  assert.equal(iconClass('unknown-local-model'), 'fas fa-microchip')
})
