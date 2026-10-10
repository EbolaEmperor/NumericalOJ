export interface FaithSieveCostSummary {
  cost_rmb: string | null
  currency: 'CNY'
  complete: boolean
  estimated: boolean
  missing_usage: boolean
  request_count: number
}

function amountText(value: string | null | undefined) {
  if (typeof value !== 'string' || !/^\d+(?:\.\d+)?$/.test(value)) return null
  const [integer, fraction = ''] = value.split('.')
  const units = BigInt(integer) * 100n + BigInt(fraction.padEnd(2, '0').slice(0, 2))
  const rounded = units + (Number(fraction[2] || 0) >= 5 ? 1n : 0n)
  const decimals = (rounded % 100n).toString().padStart(2, '0')
  const exactDecimals = fraction.replace(/0+$/, '')
  return {
    amount: `${rounded / 100n}.${decimals}`,
    exactAmount: `${BigInt(integer)}${exactDecimals ? `.${exactDecimals}` : ''}`,
  }
}

export function faithSieveCostDisplay(cost: FaithSieveCostSummary | null | undefined) {
  const formatted = cost?.currency === 'CNY' ? amountText(cost.cost_rmb) : null
  if (!formatted) return {amount: '—', recorded: false, description: '费用尚未记录'}
  const recorded = !cost!.complete
  const estimated = cost!.estimated
  return {
    amount: estimated && !recorded ? `≈${formatted.amount}` : formatted.amount,
    recorded,
    description: `人民币${formatted.exactAmount}元${recorded ? '，费用仍在汇总' : ''}${estimated ? '，包含估算费用' : ''}`,
  }
}
