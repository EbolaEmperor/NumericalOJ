const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')

const source = fs.readFileSync(path.resolve(__dirname, '../src/pages/RankingDetailPage.tsx'), 'utf8')
const styles = fs.readFileSync(path.resolve(__dirname, '../public/static/app/ranking/content-v2.css'), 'utf8')

test('ELO 对战胜负标记保留 Jinja 版圆形徽章与中央对战线', () => {
  assert.match(source, /className="match-vs-badge"/)
  assert.match(styles, /\.ranking-v2-detail \.match-vs::before \{[\s\S]*content: "";[\s\S]*width: 1px;[\s\S]*background: var\(--rkv2-line\);/)
  assert.match(styles, /\.ranking-v2-detail \.match-vs-badge \{[\s\S]*display: inline-flex;[\s\S]*border: 1\.5px solid #c89b30;[\s\S]*border-radius: 50%;[\s\S]*background: #fff;/)
})

test('手机端胜负徽章继续使用原来的 25px 紧凑尺寸', () => {
  assert.match(styles, /@media \(max-width: 760px\)[\s\S]*\.ranking-v2-detail \.match-vs-badge \{\s*width: 25px;\s*height: 25px;\s*border-width: 1px;/)
})

test('轨迹弹窗在 pointerdown 阶段固定遮罩命中目标', () => {
  assert.match(source, /id="eloTrajectoryModal"[\s\S]*?onPointerDown=\{\(event\) => \{if \(event\.target === event\.currentTarget\) closeTrajectory\(\)\}\}/)
  assert.doesNotMatch(source, /id="eloTrajectoryModal"[^\n]*onMouseDown=/)
})
