import {describe, expect, it} from 'vitest'
import {faithSieveCostDisplay, type FaithSieveCostSummary} from './faithSieveCost'

function cost(cost_rmb: string | null, flags: Partial<FaithSieveCostSummary> = {}): FaithSieveCostSummary {
  return {cost_rmb, currency: 'CNY', complete: true, estimated: false, missing_usage: false, request_count: 1, ...flags}
}

describe('Faith Sieve 费用显示', () => {
  it('没有用量或无效金额时显示未知，真正记录的零费用才显示零', () => {
    for (const value of [undefined, null, cost(null), cost(''), cost('-1'), cost('Infinity'), cost('NaN')]) {
      expect(faithSieveCostDisplay(value)).toEqual({amount: '—', recorded: false, description: '费用尚未记录'})
    }
    expect(faithSieveCostDisplay(cost('0.000000')).amount).toBe('0.00')
  })
  it('金额固定保留两位小数，准确舍入并在说明中保留账本精度', () => {
    expect(faithSieveCostDisplay(cost('0001.230000')).amount).toBe('1.23')
    expect(faithSieveCostDisplay(cost('1.2')).amount).toBe('1.20')
    expect(faithSieveCostDisplay(cost('0.000001'))).toMatchObject({amount: '0.00', description: '人民币0.000001元'})
    expect(faithSieveCostDisplay(cost('9007199254740993.000001')).amount).toBe('9007199254740993.00')
    expect(faithSieveCostDisplay(cost('0.1234567'))).toMatchObject({amount: '0.12', description: '人民币0.1234567元'})
    expect(faithSieveCostDisplay(cost('0.0000001'))).toMatchObject({amount: '0.00', description: '人民币0.0000001元'})
    expect(faithSieveCostDisplay(cost('0.004999999')).amount).toBe('0.00')
    expect(faithSieveCostDisplay(cost('0.005')).amount).toBe('0.01')
    expect(faithSieveCostDisplay(cost('1.005')).amount).toBe('1.01')
    expect(faithSieveCostDisplay(cost('9.995')).amount).toBe('10.00')
  })
  it('部分费用在说明中标注仍在汇总，估算完整费用使用近似符号', () => {
    expect(faithSieveCostDisplay(cost('1.25', {complete: false, missing_usage: true})))
      .toEqual({amount: '1.25', recorded: true, description: '人民币1.25元，费用仍在汇总'})
    expect(faithSieveCostDisplay(cost('1.25', {estimated: true})))
      .toEqual({amount: '≈1.25', recorded: false, description: '人民币1.25元，包含估算费用'})
    expect(faithSieveCostDisplay(cost('1.25', {complete: false, estimated: true})))
      .toEqual({amount: '1.25', recorded: true, description: '人民币1.25元，费用仍在汇总，包含估算费用'})
  })
})
