const ROUND_CONSTANTS = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

function rotateRight(value: number, amount: number) {return (value >>> amount) | (value << (32 - amount))}
function wordHex(value: number) {return (value >>> 0).toString(16).padStart(8, '0')}

/** 与旧版 Jinja 页面相同的非安全上下文 SHA-256 回退。 */
export function digestSha256Fallback(value: ArrayBuffer) {
  const bytes = new Uint8Array(value)
  const byteLength = bytes.byteLength
  const paddedLength = Math.ceil((byteLength + 9) / 64) * 64
  const message = new Uint8Array(paddedLength)
  message.set(bytes)
  message[byteLength] = 0x80
  const view = new DataView(message.buffer)
  view.setUint32(paddedLength - 8, Math.floor(byteLength / 0x20000000) >>> 0, false)
  view.setUint32(paddedLength - 4, (byteLength << 3) >>> 0, false)
  let hash0 = 0x6a09e667; let hash1 = 0xbb67ae85; let hash2 = 0x3c6ef372; let hash3 = 0xa54ff53a
  let hash4 = 0x510e527f; let hash5 = 0x9b05688c; let hash6 = 0x1f83d9ab; let hash7 = 0x5be0cd19
  const words = new Uint32Array(64)
  for (let offset = 0; offset < paddedLength; offset += 64) {
    let index = 0
    for (; index < 16; index += 1) words[index] = view.getUint32(offset + index * 4, false)
    for (; index < 64; index += 1) {
      const sigma0 = rotateRight(words[index - 15], 7) ^ rotateRight(words[index - 15], 18) ^ (words[index - 15] >>> 3)
      const sigma1 = rotateRight(words[index - 2], 17) ^ rotateRight(words[index - 2], 19) ^ (words[index - 2] >>> 10)
      words[index] = (words[index - 16] + sigma0 + words[index - 7] + sigma1) >>> 0
    }
    let a = hash0; let b = hash1; let c = hash2; let d = hash3
    let e = hash4; let f = hash5; let g = hash6; let h = hash7
    for (index = 0; index < 64; index += 1) {
      const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25)
      const temporary1 = (h + sum1 + ((e & f) ^ (~e & g)) + ROUND_CONSTANTS[index] + words[index]) >>> 0
      const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22)
      const temporary2 = (sum0 + ((a & b) ^ (a & c) ^ (b & c))) >>> 0
      h = g; g = f; f = e; e = (d + temporary1) >>> 0; d = c; c = b; b = a; a = (temporary1 + temporary2) >>> 0
    }
    hash0 = (hash0 + a) >>> 0; hash1 = (hash1 + b) >>> 0; hash2 = (hash2 + c) >>> 0; hash3 = (hash3 + d) >>> 0
    hash4 = (hash4 + e) >>> 0; hash5 = (hash5 + f) >>> 0; hash6 = (hash6 + g) >>> 0; hash7 = (hash7 + h) >>> 0
  }
  return [hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7].map(wordHex).join('')
}

export async function digestSha256(blob: Blob) {
  const buffer = await blob.arrayBuffer()
  if (window.crypto?.subtle) {
    const digest = await window.crypto.subtle.digest('SHA-256', buffer)
    return Array.from(new Uint8Array(digest), (item) => item.toString(16).padStart(2, '0')).join('')
  }
  return digestSha256Fallback(buffer)
}

export type RepositoryUploadDescriptor = {kind: 'file'; relativePath: string; file: File} | {kind: 'directory'; relativePath: string}

type WebkitFileEntry = {name: string; isFile: true; isDirectory: false; file: (done: (file: File) => void, fail: (error: DOMException) => void) => void}
type WebkitDirectoryEntry = {name: string; isFile: false; isDirectory: true; createReader: () => {readEntries: (done: (entries: WebkitEntry[]) => void, fail: (error: DOMException) => void) => void}}
type WebkitEntry = WebkitFileEntry | WebkitDirectoryEntry

function readDirectory(reader: ReturnType<WebkitDirectoryEntry['createReader']>): Promise<WebkitEntry[]> {
  return new Promise((resolve, reject) => {
    const entries: WebkitEntry[] = []
    const next = () => reader.readEntries((batch) => {if (!batch.length) resolve(entries); else {entries.push(...batch); next()}}, reject)
    next()
  })
}

async function walkEntry(entry: WebkitEntry, prefix: string): Promise<RepositoryUploadDescriptor[]> {
  const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name
  if (entry.isFile) return new Promise((resolve, reject) => entry.file((file) => resolve([{kind: 'file', relativePath, file}]), reject))
  const children = await readDirectory(entry.createReader())
  return [{kind: 'directory', relativePath}, ...(await Promise.all(children.map((child) => walkEntry(child, relativePath)))).flat()]
}

export async function extractDropDescriptors(dataTransfer: DataTransfer) {
  const entries: WebkitEntry[] = []
  Array.from(dataTransfer.items || []).forEach((item) => {
    const candidate = item as DataTransferItem & {webkitGetAsEntry?: () => WebkitEntry | null}
    const entry = candidate.webkitGetAsEntry?.() as unknown as WebkitEntry | null | undefined
    if (entry) entries.push(entry)
  })
  if (entries.length) return (await Promise.all(entries.map((entry) => walkEntry(entry, '')))).flat()
  return Array.from(dataTransfer.files || []).map((file) => ({kind: 'file' as const, relativePath: file.name, file}))
}

export function descriptorsFromFiles(files: FileList | File[], preserveFolders = false): RepositoryUploadDescriptor[] {
  return Array.from(files).map((file) => ({
    kind: 'file',
    relativePath: preserveFolders ? (file as File & {webkitRelativePath?: string}).webkitRelativePath || file.name : file.name,
    file,
  }))
}
