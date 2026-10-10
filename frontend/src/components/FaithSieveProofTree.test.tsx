// @vitest-environment jsdom

import {cleanup, fireEvent, render, screen} from '@testing-library/react'
import {afterEach, describe, expect, it, vi} from 'vitest'

import type {FaithSieveJsonProofTree, FaithSieveLegacyProofTree} from '../lib/faithSieveProofTree'
import {FaithSieveProofTree} from './FaithSieveProofTree'

vi.mock('./useMarkdownEnhancements', () => ({useMarkdownEnhancements: vi.fn()}))
vi.mock('./MarkdownContent', () => ({MarkdownContent: () => null}))
const tree: FaithSieveJsonProofTree = {schema_version: 1, root_id: 'N1', nodes: [{id: 'N1', label: '初始状态', conditions: ['\\(a > 0\\)'], goal: '\\(a^2 > 0\\)', scope: ['\\(a\\) 为实数']}, {id: 'N2', label: '平方', conditions: ['\\(a > 0\\)', '\\(a^2 > 0\\)'], goal: '目标成立', scope: []}, {id: 'N3', label: '另一分支', conditions: ['\\(a > 0\\)'], goal: '\\(a^3 > 0\\)', scope: []}], edges: [{id: 'E1', from: 'N1', to: 'N2', step_id: 'S1', source_location: '第 2 页第 3 行', source_text: '对正数平方。', changes: {retained: ['正数条件'], added: ['平方结论'], consumed: [], transformed: []}, goal_relation: '原目标已得', transition_type: '直接推导', scope: ['使用实数次序']}, {id: 'E2', from: 'N1', to: 'N3', step_id: 'S2', source_location: '第 2 页第 4 行', source_text: '继续乘以正数。', changes: {retained: [], added: [], consumed: [], transformed: ['乘法']}, goal_relation: '目标细化', transition_type: '直接推导', scope: []}], ambiguities: ['步骤 S2 未写明符号。']}
afterEach(() => cleanup())

describe('证明状态树画布', () => {
  it('真实圆节点与直线父子边，选中状态显示其数学条件', () => {
    const select = vi.fn()
    const {container} = render(<FaithSieveProofTree tree={tree} onSelect={select} />)
    expect(container.querySelectorAll('[data-proof-node]')).toHaveLength(3)
    expect(container.querySelectorAll('.faithsieve-proof-edge-line')).toHaveLength(2)
    expect(container.querySelector('[data-source="N2"][data-target="N3"]')).toBeNull()
    expect(screen.getByText('\\(a^2 > 0\\)')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', {name: '证明状态 N3，另一分支'}))
    expect(select).toHaveBeenCalledWith({kind: 'node', id: 'N3'})
    expect(screen.getByRole('heading', {name: 'N3 · 另一分支'})).toBeTruthy()
    expect(screen.getByText('\\(a^3 > 0\\)')).toBeTruthy()
  })
  it('边可通过键盘选择，显示原文、条件变化和父子状态', () => {
    render(<FaithSieveProofTree tree={tree} />)
    fireEvent.keyDown(screen.getByRole('button', {name: '证明步骤 E1，S1，N1 到 N2'}), {key: 'Enter'})
    expect(screen.getByRole('heading', {name: 'E1'})).toBeTruthy()
    expect(screen.getByText('第 2 页第 3 行')).toBeTruthy()
    expect(screen.getByText('对正数平方。')).toBeTruthy()
    expect(screen.getByText('平方结论')).toBeTruthy()
    expect(screen.getByText('原目标已得')).toBeTruthy()
    expect(screen.getByText('状态 N1 → N2')).toBeTruthy()
    expect(screen.queryByRole('heading', {name: '消耗'})).toBeNull()
  })
  it('历史字串按原文展示，不将前态引用补成猜测状态', () => {
    const legacy: FaithSieveLegacyProofTree = {schema_version: 1, format: 'legacy_markdown', root_id: 'N1', nodes: [{id: 'N1', label: 'N1', raw_state: '<img src=x onerror=alert(1)> \\(\\Gamma_1\\)'}, {id: 'N2', label: 'N2', raw_state: '沿用 N1'}], edges: [{id: 'E1', from: 'N1', to: 'N2', step_id: 'S1', source_location: '', source_text: '', raw_input: '见 N1', raw_output: '见 N2', raw_changes: '沿用全部条件', goal_relation: '', transition_type: '', scope_text: ''}], ambiguities: []}
    const {container} = render(<FaithSieveProofTree tree={legacy} />)
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByRole('heading', {name: 'N1'})).toBeTruthy()
    expect(screen.getByRole('button', {name: '证明状态 N1'})).toBeTruthy()
    expect(screen.getByText('<img src=x onerror=alert(1)> \\(\\Gamma_1\\)')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', {name: '证明步骤 E1，S1，N1 到 N2'}))
    expect(screen.getByText('见 N1')).toBeTruthy()
    expect(screen.getByText('沿用全部条件')).toBeTruthy()
    expect(screen.queryByRole('heading', {name: '目标关系'})).toBeNull()
  })
  it('缩放保持结构，外层页签可关闭标题，展开后Escape恢复页面', () => {
    const {container} = render(<FaithSieveProofTree tree={tree} title="" />)
    expect(screen.queryByRole('heading', {name: '证明状态树'})).toBeNull()
    const canvas = container.querySelector<HTMLElement>('.faithsieve-proof-canvas')!
    const initial = canvas.style.transform
    fireEvent.click(screen.getByRole('button', {name: '放大证明状态树'}))
    expect(canvas.style.transform).not.toBe(initial)
    expect(container.querySelectorAll('.faithsieve-proof-edge-line')).toHaveLength(2)
    fireEvent.click(screen.getByRole('button', {name: '适应证明状态树'}))
    expect(canvas.style.transform).toBe(initial)
    fireEvent.click(screen.getByRole('button', {name: '展开证明状态树'}))
    expect(screen.getByRole('dialog', {name: '证明状态树'})).toBeTruthy()
    expect(screen.getByRole('heading', {name: '证明状态树（历史）'})).toBeTruthy()
    expect(document.body.style.overflow).toBe('hidden')
    fireEvent.keyDown(document, {key: 'Escape'})
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.body.style.overflow).toBe('')
  })
  it('切换树时不保留已不存在的选中节点', () => {
    const {rerender} = render(<FaithSieveProofTree tree={tree} />)
    fireEvent.click(screen.getByRole('button', {name: '证明状态 N3，另一分支'}))
    rerender(<FaithSieveProofTree tree={{...tree, nodes: tree.nodes.slice(0, 2), edges: tree.edges.slice(0, 1)}} />)
    expect(screen.getByRole('heading', {name: 'N1 · 初始状态'})).toBeTruthy()
    expect(screen.getByRole('button', {name: '证明状态 N1，初始状态'}).getAttribute('aria-pressed')).toBe('true')
  })
})
