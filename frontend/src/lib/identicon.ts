const GRID_SIZE = 8
const CELL_COUNT = GRID_SIZE * GRID_SIZE

export type IdenticonAvatar = unknown

export function normalizeIdenticonCells(avatar: IdenticonAvatar) {
  const raw = Array.isArray(avatar)
    ? avatar
    : avatar && typeof avatar === 'object' && 'cells' in avatar && Array.isArray(avatar.cells) ? avatar.cells : []
  const cells = new Set<number>()
  for (const item of raw) {
    let index: number | null = null
    if (Number.isInteger(item)) index = Number(item)
    else if (Array.isArray(item) && item.length >= 2 && Number.isInteger(item[0]) && Number.isInteger(item[1])) {
      index = Number(item[1]) * GRID_SIZE + Number(item[0])
    }
    if (index !== null && index >= 0 && index < CELL_COUNT) cells.add(index)
  }
  return cells
}

export function identiconCellsForSeed(seed: string) {
  const bytes = new TextEncoder().encode(seed || 'numericaloj')
  let hash = 0x811c9dc5
  for (const byte of bytes) {
    hash ^= byte
    hash = Math.imul(hash, 0x01000193) >>> 0
  }
  let randomState = hash || 0x9e3779b9
  const cells: number[] = []
  for (let row = 0; row < GRID_SIZE; row += 1) {
    for (let column = 0; column < GRID_SIZE / 2; column += 1) {
      randomState ^= randomState << 13
      randomState ^= randomState >>> 17
      randomState ^= randomState << 5
      randomState >>>= 0
      if ((randomState & 1) === 1) cells.push(row * GRID_SIZE + column, row * GRID_SIZE + GRID_SIZE - 1 - column)
    }
  }
  return cells.length ? cells.sort((left, right) => left - right) : [27, 28, 35, 36]
}

export function identiconCellFlags(avatar: IdenticonAvatar) {
  const cells = normalizeIdenticonCells(avatar)
  return Array.from({length: CELL_COUNT}, (_, index) => cells.has(index))
}
