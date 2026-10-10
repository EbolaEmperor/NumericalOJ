// @vitest-environment jsdom

import {cleanup, fireEvent, render, screen} from '@testing-library/react'
import {afterEach, describe, expect, it, vi} from 'vitest'

import type {FaithSieveStage} from '../pages/faithsieveTypes'
import {FaithSieveWorkflowGraph} from './FaithSieveWorkflowGraph'

const stage = (key: string, label: string, kind = 'llm'): FaithSieveStage => ({key, label, kind, sequence: null, role: key, state: 'completed', report: label})
const stages = [stage('source', '原稿核对', 'judge'), stage('left', '义务一'), stage('right', '义务二'), stage('merge', '独立审计', 'judge')]
afterEach(() => cleanup())

describe('Faith Sieve DAG', () => {
  it('v2验证阶段用结论编号区分，反驳只标记局部推理', () => {
    const first = {...stage('first', '数值验证', 'judge'), status: 'refuted', parameters: {node_id: 'N7', obligation_id: 'N7-O1'}}
    const second = {...stage('second', '数值验证', 'judge'), parameters: {node_id: 'N9'}}
    const select = vi.fn()
    render(<FaithSieveWorkflowGraph stages={[first, second]} runStatus="completed" onSelect={select} />)
    const refuted = screen.getByRole('button', {name: /数值验证.*推理被反驳.*结论 N7/})
    expect(refuted.querySelector('.faithsieve-graph-node-outcome')?.textContent).toBe('推理被反驳')
    fireEvent.click(screen.getByRole('button', {name: /数值验证.*结论 N9/}))
    expect(select).toHaveBeenCalledWith(second)
  })
  it('复用拓扑分层绘制真实分叉和合流，点击节点交付真实stage', () => {
    const select = vi.fn()
    const {container} = render(<FaithSieveWorkflowGraph stages={stages} edges={[{source: 'source', target: 'left'}, {source: 'source', target: 'right'}, {source: 'left', target: 'merge'}, {source: 'right', target: 'merge'}]} runStatus="completed" selectedKey="left" onSelect={select} />)
    const edges = container.querySelectorAll('.faithsieve-graph-edge')
    expect(edges.length).toBe(4)
    expect(container.querySelector('[data-source="source"][data-target="right"]')).toBeTruthy()
    expect(container.querySelector('[data-source="left"][data-target="right"]')).toBeNull()
    const source = screen.getByRole('button', {name: '原稿核对，Judge，已完成'})
    const left = screen.getByRole('button', {name: '义务一，LLM，已完成'})
    const right = screen.getByRole('button', {name: '义务二，LLM，已完成'})
    const merge = screen.getByRole('button', {name: '独立审计，Judge，已完成'})
    expect(left.style.left).toBe(right.style.left)
    expect(left.style.top).not.toBe(right.style.top)
    expect(parseFloat(source.style.left)).toBeLessThan(parseFloat(left.style.left))
    expect(parseFloat(merge.style.top)).toBeGreaterThan(parseFloat(right.style.top))
    expect(parseFloat(source.style.top)).toBeGreaterThan(parseFloat(left.style.top))
    expect(left.getAttribute('aria-pressed')).toBe('true')
    fireEvent.click(right)
    expect(select).toHaveBeenCalledWith(stages[2])
  })
  it('多stage无edges保持独立，不自动按序连链', () => {
    const {container} = render(<FaithSieveWorkflowGraph stages={stages} edges={[]} runStatus="completed" onSelect={() => undefined} />)
    expect(container.querySelectorAll('[data-stage-key]').length).toBe(4)
    expect(container.querySelectorAll('.faithsieve-graph-edge').length).toBe(0)
    expect(new Set([...container.querySelectorAll<HTMLElement>('[data-stage-key]')].map((node) => node.style.left)).size).toBe(1)
  })
  it('状态上色、终态未完成与缩放控制不改变依赖', () => {
    const pending = {...stage('pending', '待处理', 'code'), state: 'pending'}
    const {container, rerender} = render(<FaithSieveWorkflowGraph stages={[pending]} runStatus="running" onSelect={() => undefined} />)
    expect(screen.getByRole('button', {name: '待处理，代码，运行中'}).classList.contains('is-running')).toBe(true)
    const canvas = container.querySelector<HTMLElement>('.faithsieve-graph-canvas')!
    const before = canvas.style.transform
    fireEvent.click(screen.getByRole('button', {name: '放大 Workflow 图'}))
    expect(canvas.style.transform).not.toBe(before)
    fireEvent.click(screen.getByRole('button', {name: '适应 Workflow 图'}))
    expect(canvas.style.transform).toBe(before)
    rerender(<FaithSieveWorkflowGraph stages={[pending]} runStatus="failed" onSelect={() => undefined} />)
    expect(screen.getByRole('button', {name: '待处理，代码，未完成'}).classList.contains('is-stopped')).toBe(true)
  })
  it('queued无阶段不虚构计划节点', () => {
    const {container} = render(<FaithSieveWorkflowGraph stages={[]} edges={[]} runStatus="queued" headingMeta={<span>排队中</span>} onSelect={() => undefined} />)
    expect(screen.getByRole('heading', {name: 'Workflow'})).toBeTruthy()
    expect(screen.getByText('排队中')).toBeTruthy()
    expect(screen.getByText('暂无阶段记录')).toBeTruthy()
    expect(container.querySelectorAll('[data-stage-key]').length).toBe(0)
  })
  it('相同角色用必要义务和分支区分，详情按宽度保留可读字号', () => {
    const original = {...stage('original', '形式化审计', 'judge'), parameters: {obligation_id: 'e1-o1', branch: 'original'}}
    const negation = {...stage('negation', '形式化审计', 'judge'), parameters: {obligation_id: 'e1-o2', branch: 'negation'}}
    const {container} = render(<FaithSieveWorkflowGraph stages={[original, negation, ...stages]} edges={[]} runStatus="completed" onSelect={() => undefined} />)
    expect(screen.getByRole('button', {name: /形式化审计.*义务 1.1 · 原命题/})).toBeTruthy()
    expect(screen.getByRole('button', {name: /形式化审计.*义务 1.2 · 否定/})).toBeTruthy()
    const scale = Number(container.querySelector<HTMLElement>('.faithsieve-graph-canvas')!.style.transform.match(/[\d.]+/)?.[0])
    expect(scale).toBe(1)
    const canvas = container.querySelector<HTMLElement>('.faithsieve-graph-canvas')!
    expect(parseFloat(canvas.style.width) * scale).toBeLessThanOrEqual(600 - 48)
    expect(parseFloat(canvas.style.height) * scale).toBeLessThanOrEqual(840 - 48)
    expect(container.querySelector('.faithsieve-graph-scroll')).toBeTruthy()
  })
  it('选择与轮询保留完整图视野，不自动滚入当前节点', () => {
    const edges = [{source: 'source', target: 'left'}, {source: 'left', target: 'right'}, {source: 'right', target: 'merge'}]
    const {container, rerender} = render(<FaithSieveWorkflowGraph stages={stages} edges={edges} runStatus="running" selectedKey="source" onSelect={() => undefined} />)
    const viewport = container.querySelector<HTMLElement>('.faithsieve-graph-scroll')!
    Object.defineProperty(viewport, 'clientWidth', {value: 400, configurable: true})
    Object.defineProperty(viewport, 'clientHeight', {value: 160, configurable: true})
    const pageScroll = vi.spyOn(window, 'scrollTo').mockImplementation(() => undefined)
    rerender(<FaithSieveWorkflowGraph stages={stages} edges={edges} runStatus="running" selectedKey="merge" onSelect={() => undefined} />)
    expect(viewport.scrollTop).toBe(0)
    expect(viewport.scrollLeft).toBe(0)
    expect(pageScroll).not.toHaveBeenCalled()
    pageScroll.mockRestore()
  })
  it('同名阶段标明真实轮次，保留各自选择和执行历史', () => {
    const first = {...stage('first', '义务拆分'), parameters: {attempt: 1}}
    const second = {...stage('second', '义务拆分'), parameters: {attempt: 1}}
    const select = vi.fn()
    render(<FaithSieveWorkflowGraph stages={[first, second]} edges={[{source: 'first', target: 'second'}]} runStatus="completed" onSelect={select} />)
    expect(screen.getByRole('button', {name: /义务拆分.*第 1 轮/})).toBeTruthy()
    fireEvent.click(screen.getByRole('button', {name: /义务拆分.*第 2 轮/}))
    expect(select).toHaveBeenCalledWith(second)
  })
  it('唯一节点保留自身重试轮次，不用显示序号替代执行参数', () => {
    const retried = {...stage('retry', '独立审计'), parameters: {attempt: 3}}
    render(<FaithSieveWorkflowGraph stages={[retried]} runStatus="completed" onSelect={() => undefined} />)
    expect(screen.getByRole('button', {name: /独立审计.*第 3 轮/})).toBeTruthy()
  })
  it.each([
    {state: 'pending', runStatus: 'running', status: '', label: '运行中'},
    {state: 'pending', runStatus: 'queued', status: '', label: '排队中'},
    {state: 'protocol_error', runStatus: 'failed', status: '', label: '协议异常'},
    {state: 'endpoint_error', runStatus: 'failed', status: '', label: '失败'},
    {state: 'completed', runStatus: 'completed', status: 'needs_revision', label: '需修订'},
    {state: 'completed', runStatus: 'completed', status: 'graph_defect', label: '需修图'},
    {state: 'completed', runStatus: 'completed', status: 'failed', label: '失败'},
    {state: 'completed', runStatus: 'completed', status: 'inconclusive', label: '无结论'},
    {state: 'completed', runStatus: 'completed', status: 'refuted', label: '已反驳'},
  ])('节点直接显示重要状态：$label', ({state, runStatus, status, label}) => {
    const item = {...stage('status', '形式化审计', 'judge'), state, status, parameters: {obligation_id: 'e1-o1', branch: 'original'}}
    render(<FaithSieveWorkflowGraph stages={[item]} runStatus={runStatus} onSelect={() => undefined} />)
    const button = screen.getByRole('button', {name: new RegExp(`形式化审计.*${label}`)})
    expect(button.querySelector('.faithsieve-graph-node-outcome')?.textContent).toBe(label)
    expect(button.querySelector('.faithsieve-graph-node-reference')?.textContent).toBe('义务 1.1 · 原命题')
    if (state === 'endpoint_error') {expect(button.classList.contains('is-failed')).toBe(true); expect(button.classList.contains('is-issue')).toBe(true); expect(button.classList.contains('is-completed')).toBe(false)}
  })
  it('正常完成省略状态文字，修订状态不改变同名阶段的轮次分组', () => {
    const first = {...stage('first', '义务拆分'), status: 'needs_revision', parameters: {attempt: 1}}
    const second = {...stage('second', '义务拆分'), status: 'ok', parameters: {attempt: 1}}
    render(<FaithSieveWorkflowGraph stages={[first, second]} runStatus="completed" onSelect={() => undefined} />)
    expect(screen.getByRole('button', {name: /义务拆分.*需修订.*第 1 轮/}).querySelector('.faithsieve-graph-node-outcome')).toBeTruthy()
    expect(screen.getByRole('button', {name: /义务拆分.*已完成.*第 2 轮/}).querySelector('.faithsieve-graph-node-outcome')).toBeNull()
  })
  it('局部构图诊断用警示样式展示，审核保持LLM身份并可选择报告', () => {
    const verification = {...stage('local', '验证局部命题', 'judge'), role: 'local-verifier', status: 'graph_defect', parameters: {node_id: 'N6'}}
    const audit = {...stage('audit', '审核局部验证'), role: 'verification-auditor', status: 'graph_defect', parameters: {node_id: 'N6'}}
    const select = vi.fn()
    render(<FaithSieveWorkflowGraph stages={[verification, audit]} edges={[{source: 'local', target: 'audit'}]} runStatus="running" onSelect={select} />)
    for (const label of [/验证局部命题，Judge，需修图，结论 N6/, /审核局部验证，LLM，需修图，结论 N6/]) {
      const button = screen.getByRole('button', {name: label})
      expect(button.classList.contains('is-warning')).toBe(true)
      expect(button.classList.contains('is-issue')).toBe(false)
      expect(button.querySelector('.faithsieve-graph-node-outcome')?.textContent).toBe('需修图')
    }
    fireEvent.click(screen.getByRole('button', {name: /审核局部验证，LLM，需修图/}))
    expect(select).toHaveBeenCalledWith(audit)
    expect(screen.queryByText('无结论')).toBeNull()
    expect(screen.queryByText('推理被反驳')).toBeNull()
  })
  it('常规六个串行阶段按视口折行，默认保持可读字号并完整显示', () => {
    const serial = Array.from({length: 6}, (_, index) => stage(`stage-${index}`, `阶段 ${index + 1}`))
    const edges = serial.slice(1).map((item, index) => ({source: serial[index].key, target: item.key}))
    const {container} = render(<FaithSieveWorkflowGraph stages={serial} edges={edges} runStatus="completed" onSelect={() => undefined} />)
    const canvas = container.querySelector<HTMLElement>('.faithsieve-graph-canvas')!
    const scale = Number(canvas.style.transform.match(/[\d.]+/)?.[0])
    expect(scale).toBeGreaterThanOrEqual(0.9)
    expect(parseFloat(canvas.style.width) * scale).toBeLessThanOrEqual(600 - 48)
    expect(parseFloat(canvas.style.height) * scale).toBeLessThanOrEqual(840 - 48)
    expect(new Set([...container.querySelectorAll<HTMLElement>('[data-stage-key]')].map((node) => node.style.top)).size).toBe(3)
    expect(container.querySelectorAll('.faithsieve-graph-edge').length).toBe(5)
  })
  it.each([10, 12])('%i 个串行阶段保持原字号，视口随内容增高且无需内部滚动', (count) => {
    const serial = Array.from({length: count}, (_, index) => stage(`stage-${index}`, `阶段 ${index + 1}`))
    const edges = serial.slice(1).map((item, index) => ({source: serial[index].key, target: item.key}))
    const {container} = render(<FaithSieveWorkflowGraph stages={serial} edges={edges} runStatus="completed" onSelect={() => undefined} />)
    const canvas = container.querySelector<HTMLElement>('.faithsieve-graph-canvas')!
    const size = container.querySelector<HTMLElement>('.faithsieve-graph-size')!
    const viewport = container.querySelector<HTMLElement>('.faithsieve-graph-scroll')!
    expect(canvas.style.transform).toBe('scale(1)')
    expect(parseFloat(viewport.style.height)).toBeGreaterThan(600)
    expect(parseFloat(viewport.style.height)).toBeLessThanOrEqual(840)
    expect(parseFloat(size.style.height)).toBeLessThanOrEqual(parseFloat(viewport.style.height) - 2)
    expect(container.querySelectorAll('[data-stage-key]').length).toBe(count)
  })
  it('标题与状态共用工具栏，预览限制高度，展开可用Escape退出', () => {
    const {container} = render(<FaithSieveWorkflowGraph compact title="验证流程" headingMeta={<span>运行中</span>} stages={stages} edges={[]} runStatus="running" onSelect={() => undefined} />)
    expect(screen.getByRole('heading', {name: '验证流程'})).toBeTruthy()
    expect(screen.getByText('运行中')).toBeTruthy()
    expect(parseFloat(container.querySelector<HTMLElement>('.faithsieve-graph-scroll')!.style.height)).toBeLessThanOrEqual(240)
    fireEvent.click(screen.getByRole('button', {name: '展开 Workflow 图'}))
    expect(screen.getByRole('dialog', {name: 'Workflow DAG'})).toBeTruthy()
    expect(document.body.style.overflow).toBe('hidden')
    fireEvent.keyDown(document, {key: 'Escape'})
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.body.style.overflow).toBe('')
  })
})
