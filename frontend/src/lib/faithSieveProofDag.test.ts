import {describe, expect, it} from 'vitest'

import {proofDagExternalFixture, proofDagExternalVerificationFixture, proofDagFixture, proofDagV3Fixture, proofDagVerificationFixture} from '../test/faithSieveProofDag'
import {faithSieveDagNodeOrder, faithSieveDagPremises, parseFaithSieveNodeVerification, parseFaithSieveProofDag, type FaithSieveProofDagData} from './faithSieveProofDag'
import {parseFaithSieveProofTree} from './faithSieveProofTree'

describe('证明依赖 DAG v2', () => {
  it('接受多根、多父、共享分支及非连续编号，保持原文与目标顺序', () => {
    const graph = proofDagFixture()
    expect(parseFaithSieveProofTree(graph)).toEqual(graph)
    const parsed = parseFaithSieveProofDag(graph)
    expect(parsed).toEqual(graph)
    expect(parsed).not.toBe(graph)
    expect(parsed.target_ids).toEqual(['N9', 'N20'])
    expect(faithSieveDagPremises(parsed, 'N9').map((node) => node.id)).toEqual(['N11', 'N13'])
    expect(faithSieveDagPremises(parsed, 'N20')).toEqual([])
    const order = faithSieveDagNodeOrder(parsed).map((index) => parsed.nodes[index].id)
    for (const edge of graph.edges) expect(order.indexOf(edge.from)).toBeLessThan(order.indexOf(edge.to))
    expect(order).toEqual(['N1', 'N4', 'N7', 'N11', 'N13', 'N9', 'N20'])
  })
  it('同一原文步骤可以对应多个结论，而单个节点的步骤必须按数字顺序排列', () => {
    const graph = proofDagFixture()
    graph.nodes[0].step_ids = ['S1', 'S2', 'S10']
    const parsed = parseFaithSieveProofDag(graph)
    expect(parsed.schema_version === 2 && parsed.nodes[0].step_ids).toEqual(['S1', 'S2', 'S10'])
    for (const steps of [['S2', 'S1'], ['S1', 'S1'], ['S10', 'S2']]) {
      graph.nodes[0].step_ids = steps
      expect(() => parseFaithSieveProofDag(graph)).toThrow(/顺序/)
    }
  })
  it.each([
    ['历史字段', (graph: FaithSieveProofDagData) => ({...graph, root_id: 'N1'}), /未知字段/],
    ['缺失字段', (graph: FaithSieveProofDagData) => ({...graph, target_ids: undefined}), /数组/],
    ['空目标', (graph: FaithSieveProofDagData) => ({...graph, target_ids: []}), /结论节点/],
    ['条件目标', (graph: FaithSieveProofDagData) => ({...graph, target_ids: ['N1']}), /结论节点/],
    ['未知目标', (graph: FaithSieveProofDagData) => ({...graph, target_ids: ['N100']}), /结论节点/],
    ['重复目标', (graph: FaithSieveProofDagData) => ({...graph, target_ids: ['N9', 'N9']}), /结论节点/],
    ['重复依赖', (graph: FaithSieveProofDagData) => ({...graph, edges: [...graph.edges, {...graph.edges[0], id: 'D99'}]}), /重复/],
    ['重复边编号', (graph: FaithSieveProofDagData) => ({...graph, edges: graph.edges.map((edge) => ({...edge, id: 'D1'}))}), /重复/],
    ['重复节点', (graph: FaithSieveProofDagData) => ({...graph, nodes: [...graph.nodes, graph.nodes[0]]}), /重复/],
    ['自环', (graph: FaithSieveProofDagData) => ({...graph, edges: [{id: 'D1', from: 'N9', to: 'N9'}]}), /自身/],
    ['未知端点', (graph: FaithSieveProofDagData) => ({...graph, edges: [{id: 'D1', from: 'N100', to: 'N9'}]}), /不存在/],
    ['条件入边', (graph: FaithSieveProofDagData) => ({...graph, edges: [{id: 'D1', from: 'N9', to: 'N1'}]}), /不能有前驱/],
    ['环', (graph: FaithSieveProofDagData) => ({...graph, edges: [...graph.edges, {id: 'D99', from: 'N9', to: 'N7'}]}), /包含环/],
    ['额外边状态', (graph: FaithSieveProofDagData) => ({...graph, edges: [{...graph.edges[0], status: 'passed'}]}), /未知字段/],
    ['额外节点状态', (graph: FaithSieveProofDagData) => ({...graph, nodes: graph.nodes.map((node) => ({...node, established: true}))}), /未知字段/],
  ] as const)('拒绝%s且不补写结构', (_, mutate, error) => expect(() => parseFaithSieveProofDag(mutate(proofDagFixture()))).toThrow(error))
  it('节点来源、标识、步骤和字面文本边界严格', () => {
    for (const change of [{kind: 'given'}, {source_type: 'problem'}, {step_ids: []}, {id: 'N0'}, {id: 'N01'}, {id: 'N' + '1'.repeat(64)}, {step_ids: ['S01']}, {source_text: ''}, {statement: ' '}, {label: '\ud800'}, {source_location: 'x'.repeat(20_001)}]) {
      const graph = proofDagFixture()
      expect(() => parseFaithSieveProofDag({...graph, nodes: [{...graph.nodes[0], ...change}, ...graph.nodes.slice(1)]})).toThrow()
    }
    const graph = proofDagFixture()
    graph.nodes[0].statement = '🧮'.repeat(20_000)
    expect(parseFaithSieveProofDag(graph).nodes[0].statement).toBe(graph.nodes[0].statement)
    graph.nodes[0].statement += 'x'
    expect(() => parseFaithSieveProofDag(graph)).toThrow(/过长/)
  })
  it('合法空依赖可以有独立结论，但总内容和数组有界', () => {
    const graph = proofDagFixture()
    graph.nodes = [graph.nodes.at(-1)!]; graph.edges = []; graph.target_ids = ['N20']
    expect(parseFaithSieveProofDag(graph)).toEqual(graph)
    expect(() => parseFaithSieveProofDag({...graph, nodes: Array(1001).fill(graph.nodes[0])})).toThrow(/1000/)
    expect(() => parseFaithSieveProofDag({...graph, edges: [{id: 'D1', from: 'N20', to: 'N20'}]})).toThrow(/上限/)
    expect(() => parseFaithSieveProofDag({...graph, ambiguities: Array(501).fill('x')})).toThrow(/500/)
    expect(() => parseFaithSieveProofDag({...graph, ambiguities: Array(40).fill('字'.repeat(20_000))})).toThrow(/2 MiB/)
  })
})

describe('原稿图像依赖 DAG v3', () => {
  it('接受独立外部结果及其完整适用范围，当前目标同时依赖题设与外部结果', () => {
    const graph = proofDagExternalFixture()
    expect(parseFaithSieveProofTree(graph)).toEqual(graph)
    expect(parseFaithSieveProofDag(graph)).toEqual(graph)
    expect(faithSieveDagPremises(graph, 'N3').map((node) => [node.id, node.kind])).toEqual([['N1', 'given'], ['N2', 'external']])
    expect(faithSieveDagPremises(graph, 'N2')).toEqual([])
    expect(parseFaithSieveProofDag(graph).nodes[1].statement).toBe(graph.nodes[1].statement)
    const historical = proofDagFixture()
    expect(() => parseFaithSieveProofDag({...historical, nodes: [{...historical.nodes[0], kind: 'external'}, ...historical.nodes.slice(1)]})).toThrow(/kind/)
  })
  it('外部结果不能有入边，也不能替代待验证目标', () => {
    const graph = proofDagExternalFixture()
    expect(() => parseFaithSieveProofDag({...graph, edges: [{id: 'D1', from: 'N1', to: 'N2'}]})).toThrow(/外部结果不能有前驱/)
    expect(() => parseFaithSieveProofDag({...graph, target_ids: ['N2']})).toThrow(/结论节点/)
  })
  it('只接受四字段节点，依赖与宿主传播不依赖原句或步骤映射', () => {
    const graph = proofDagV3Fixture()
    expect(parseFaithSieveProofTree(graph)).toEqual(graph)
    expect(parseFaithSieveProofDag(graph)).toEqual(graph)
    expect(faithSieveDagPremises(graph, 'N9').map((node) => node.statement)).toEqual(['\\((a+b)^2>0\\)', '\\((a+b)^3>0\\)'])
    expect(parseFaithSieveNodeVerification(proofDagVerificationFixture(), graph).N9.status).toBe('blocked')
    for (const node of parseFaithSieveProofDag(graph).nodes) expect(Object.keys(node)).toEqual(['id', 'kind', 'label', 'statement'])
  })
  it.each(['source_type', 'source_location', 'source_text', 'step_ids', 'goal', 'conditions'])('v3拒绝残留的%s且不隐式转录或迁移历史', (field) => {
    const graph = proofDagV3Fixture()
    expect(() => parseFaithSieveProofDag({...graph, nodes: [{...graph.nodes[0], [field]: '原文'}, ...graph.nodes.slice(1)]})).toThrow(/未知字段/)
    expect(() => parseFaithSieveProofDag({...graph, schema_version: 2})).toThrow(/缺少字段/)
  })
  it('v3仍严格校验环、初始条件入边、引用、目标和字符串', () => {
    const graph = proofDagV3Fixture()
    expect(() => parseFaithSieveProofDag({...graph, edges: [...graph.edges, {id: 'D99', from: 'N9', to: 'N7'}]})).toThrow(/包含环/)
    expect(() => parseFaithSieveProofDag({...graph, edges: [{id: 'D1', from: 'N9', to: 'N1'}]})).toThrow(/不能有前驱/)
    expect(() => parseFaithSieveProofDag({...graph, edges: [{id: 'D1', from: 'N99', to: 'N7'}]})).toThrow(/不存在/)
    expect(() => parseFaithSieveProofDag({...graph, target_ids: ['N1']})).toThrow(/结论节点/)
    expect(() => parseFaithSieveProofDag({...graph, nodes: [{...graph.nodes[0], statement: '\ud800'}, ...graph.nodes.slice(1)]})).toThrow(/Unicode/)
    expect(() => parseFaithSieveProofDag({...graph, ambiguities: Array(40).fill('字'.repeat(20_000))})).toThrow(/2 MiB/)
  })
})

describe('宿主节点验证摘要', () => {
  it('外部结果状态只由完整宿主摘要提供，并作为当前局部验证的成立前提', () => {
    const graph = proofDagExternalFixture()
    const verification = proofDagExternalVerificationFixture()
    const parsed = parseFaithSieveNodeVerification(verification, graph)
    expect(parsed).toEqual(verification)
    expect(parsed.N2).toEqual({local_status: 'external', established: true, status: 'established', premise_ids: [], blocking_premise_ids: []})
    expect(parsed.N3.established).toBe(true)
    expect(parseFaithSieveNodeVerification(undefined, graph)).toEqual({})
    expect(parseFaithSieveNodeVerification({}, graph)).toEqual({})
    expect(() => parseFaithSieveNodeVerification({N2: verification.N2}, graph)).toThrow(/不完整/)
    for (const local_status of ['given', 'passed', 'refuted', 'inconclusive', 'not_checked']) expect(() => parseFaithSieveNodeVerification({...verification, N2: {...verification.N2, local_status}}, graph)).toThrow(/节点种类/)
    expect(() => parseFaithSieveNodeVerification({...verification, N3: {...verification.N3, local_status: 'external'}}, graph)).toThrow(/节点种类/)
    expect(() => parseFaithSieveNodeVerification({...verification, N2: {...verification.N2, established: false, status: 'not_checked'}}, graph)).toThrow(/前提成立状态/)
    expect(() => parseFaithSieveNodeVerification({...verification, N2: {...verification.N2, premise_ids: ['N1']}}, graph)).toThrow(/直接依赖/)
  })
  it('已采用外部结果不掩盖其他直接前提尚未成立', () => {
    const graph = proofDagExternalFixture()
    graph.nodes[0].kind = 'claim'
    const verification = proofDagExternalVerificationFixture()
    verification.N1 = {local_status: 'not_checked', established: false, status: 'not_checked', premise_ids: [], blocking_premise_ids: []}
    verification.N3 = {...verification.N3, established: false, status: 'blocked', blocking_premise_ids: ['N1']}
    expect(parseFaithSieveNodeVerification(verification, graph).N3.status).toBe('blocked')
    expect(() => parseFaithSieveNodeVerification({...verification, N3: {...verification.N3, established: true, status: 'established', blocking_premise_ids: []}}, graph)).toThrow(/前提成立状态/)
  })
  it('局部通过仍可被前提阻塞，缺失摘要不从图或文本猜测结果', () => {
    const graph = proofDagFixture()
    const parsed = parseFaithSieveNodeVerification(proofDagVerificationFixture(), graph)
    expect(parsed.N9.established).toBe(false)
    expect(parsed.N9.local_status).toBe('passed')
    expect(parsed.N9.status).toBe('blocked')
    expect(parseFaithSieveNodeVerification(undefined, graph)).toEqual({})
    expect(parseFaithSieveNodeVerification({}, graph)).toEqual({})
  })
  it.each([
    {local_status: 'wrong'}, {local_status: 'given'}, {established: 1}, {established: true}, {status: 'refuted'}, {premise_ids: ['N13', 'N11']}, {premise_ids: ['N7']}, {blocking_premise_ids: ['N7']}, {blocking_premise_ids: ['N11', 'N11']}, {raw_result: 'passed'},
  ])('拒绝与图不一致或未声明字段 $local_status $status', (patch) => {
    const map = proofDagVerificationFixture()
    expect(() => parseFaithSieveNodeVerification({...map, N9: {...map.N9, ...patch}}, proofDagFixture())).toThrow()
  })
  it('拒绝未知节点的摘要', () => expect(() => parseFaithSieveNodeVerification({...proofDagVerificationFixture(), N100: proofDagVerificationFixture().N9}, proofDagFixture())).toThrow(/不存在/))
  it('拒绝缺失或与前提真值矛盾的宿主摘要，不以局部结果补猜成立状态', () => {
    const graph = proofDagFixture(); const map = proofDagVerificationFixture()
    expect(() => parseFaithSieveNodeVerification({N9: map.N9}, graph)).toThrow(/不完整/)
    expect(() => parseFaithSieveNodeVerification({...map, N13: {...map.N13, status: 'blocked'}}, graph)).toThrow(/前提成立状态/)
    expect(() => parseFaithSieveNodeVerification({...map, N9: {...map.N9, status: 'established', established: true, blocking_premise_ids: []}}, graph)).toThrow(/前提成立状态/)
    expect(() => parseFaithSieveNodeVerification({...map, N11: {...map.N11, blocking_premise_ids: []}}, graph)).toThrow(/前提成立状态/)
    expect(() => parseFaithSieveNodeVerification({...map, N20: {...map.N20, local_status: 'refuted'}}, graph)).toThrow(/前提成立状态/)
  })
})
