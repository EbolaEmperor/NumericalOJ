import type {FaithSieveProofDagV2Data, FaithSieveProofDagV3Data, FaithSieveProofNodeVerificationMap} from '../lib/faithSieveProofDag'

/** 多个条件、分支、共享中间结论以及独立结论；编号不依赖数组次序。 */
export function proofDagFixture(): FaithSieveProofDagV2Data {
  const claim = (id: string, label: string, statement: string, step_ids: string[]) => ({id, kind: 'claim' as const, label, statement, source_type: 'submission' as const, step_ids, source_location: `第 2 页 ${step_ids.join('、')}`, source_text: `${statement}\n原文保留 \\nu 与换行。`})
  const given = (id: string, label: string, statement: string) => ({id, kind: 'given' as const, label, statement, source_type: 'problem' as const, step_ids: [], source_location: '题面', source_text: statement})
  return {schema_version: 2, nodes: [claim('N11', '平方', '\\((a+b)^2>0\\)', ['S2']), given('N1', '条件 a', '\\(a>0\\)'), given('N4', '条件 b', '\\(b>0\\)'), claim('N7', '和', '\\(a+b>0\\)', ['S1']), claim('N13', '立方', '\\((a+b)^3>0\\)', ['S3']), claim('N9', '乘积', '\\((a+b)^5>0\\)', ['S4', 'S12']), claim('N20', '恒等式', '\\(1=1\\)', ['S14'])], edges: [{id: 'D5', from: 'N13', to: 'N9'}, {id: 'D1', from: 'N1', to: 'N7'}, {id: 'D8', from: 'N4', to: 'N7'}, {id: 'D3', from: 'N7', to: 'N11'}, {id: 'D9', from: 'N7', to: 'N13'}, {id: 'D2', from: 'N11', to: 'N9'}], target_ids: ['N9', 'N20'], ambiguities: []}
}

export function proofDagV3Fixture(): FaithSieveProofDagV3Data {
  const graph = proofDagFixture()
  return {schema_version: 3, nodes: graph.nodes.map(({id, kind, label, statement}) => ({id, kind, label, statement})), edges: graph.edges, target_ids: graph.target_ids, ambiguities: graph.ambiguities}
}

/** 外部结果是带完整适用范围的独立前提，不与题面条件合并。 */
export function proofDagExternalFixture(): FaithSieveProofDagV3Data {
  return {
    schema_version: 3,
    nodes: [
      {id: 'N1', kind: 'given', label: '条件 x', statement: '\\(x\\in\\mathbb R,\\quad |x|\\le 1\\)'},
      {id: 'N2', kind: 'external', label: '正弦界', statement: '\\(\\forall t\\in\\mathbb R,\\quad |\\sin t|\\le |t|\\)'},
      {id: 'N3', kind: 'claim', label: '目标界', statement: '\\(|\\sin x|\\le 1\\)'},
    ],
    edges: [{id: 'D1', from: 'N1', to: 'N3'}, {id: 'D2', from: 'N2', to: 'N3'}],
    target_ids: ['N3'],
    ambiguities: [],
  }
}

export function proofDagExternalVerificationFixture(): FaithSieveProofNodeVerificationMap {
  return {
    N1: {local_status: 'given', established: true, status: 'established', premise_ids: [], blocking_premise_ids: []},
    N2: {local_status: 'external', established: true, status: 'established', premise_ids: [], blocking_premise_ids: []},
    N3: {local_status: 'passed', established: true, status: 'established', premise_ids: ['N1', 'N2'], blocking_premise_ids: []},
  }
}

export function proofDagVerificationFixture(): FaithSieveProofNodeVerificationMap {
  return {
    N1: {local_status: 'given', established: true, status: 'established', premise_ids: [], blocking_premise_ids: []},
    N4: {local_status: 'given', established: true, status: 'established', premise_ids: [], blocking_premise_ids: []},
    N7: {local_status: 'inconclusive', established: false, status: 'not_established', premise_ids: ['N1', 'N4'], blocking_premise_ids: []},
    N11: {local_status: 'passed', established: false, status: 'blocked', premise_ids: ['N7'], blocking_premise_ids: ['N7']},
    N13: {local_status: 'inconclusive', established: false, status: 'not_established', premise_ids: ['N7'], blocking_premise_ids: ['N7']},
    N9: {local_status: 'passed', established: false, status: 'blocked', premise_ids: ['N11', 'N13'], blocking_premise_ids: ['N11', 'N13']},
    N20: {local_status: 'passed', established: true, status: 'established', premise_ids: [], blocking_premise_ids: []},
  }
}
