import {useEffect, useState, type SyntheticEvent} from 'react'

import type {JsonRecord} from '../../api/types'
import {humanFileSize, statusKey} from './legacyBehavior'

function nodePath(node: JsonRecord) {return String(node.path || node.relative_path || node.name || '')}
function nodeName(node: JsonRecord) {const path = nodePath(node); return String(node.name || node.filename || path.split('/').pop() || path)}
function isDirectory(node: JsonRecord) {return ['directory', 'dir', 'folder'].includes(statusKey(node.type || node.kind)) || Array.isArray(node.children)}

export function normalizeWorkspaceTree(payload: JsonRecord[] | JsonRecord) {
  const raw = Array.isArray(payload) ? payload : payload.tree || payload.entries || payload.files || payload.children || []
  if (!Array.isArray(raw)) return []
  if (raw.some((entry) => entry && typeof entry === 'object' && Array.isArray((entry as JsonRecord).children))) return raw as JsonRecord[]
  const root: JsonRecord = {name: '', path: '', type: 'directory', children: []}
  const directories = new Map<string, JsonRecord>([['', root]])
  raw.forEach((rawEntry) => {
    const entry = typeof rawEntry === 'string' ? {path: rawEntry, type: 'file'} : rawEntry as JsonRecord
    if (!entry || typeof entry !== 'object') return
    const path = nodePath(entry).replace(/^\/+|\/+$/g, '')
    if (!path) return
    const parts = path.split('/').filter(Boolean)
    let parentPath = ''
    parts.forEach((part, index) => {
      const currentPath = parentPath ? `${parentPath}/${part}` : part
      const last = index === parts.length - 1
      const directory = !last || isDirectory(entry)
      const parent = directories.get(parentPath)
      if (!parent) return
      if (directory) {
        if (!directories.has(currentPath)) {
          const created: JsonRecord = {name: part, path: currentPath, type: 'directory', children: []}
          ;(parent.children as JsonRecord[]).push(created)
          directories.set(currentPath, created)
        }
        parentPath = currentPath
      } else {
        ;(parent.children as JsonRecord[]).push({...entry, name: entry.name || part, path: currentPath, type: 'file'})
      }
    })
  })
  return root.children as JsonRecord[]
}

function WorkspaceNode({node, depth, openPaths, setOpen, selectedPath, openFile}: {node: JsonRecord; depth: number; openPaths: Set<string>; setOpen: (path: string, open: boolean) => void; selectedPath: string; openFile: (path: string) => void}) {
  const children = Array.isArray(node.children) ? node.children as JsonRecord[] : []
  const path = nodePath(node)
  const name = nodeName(node)
  if (isDirectory(node)) {
    const open = openPaths.has(path)
    const toggle = (event: SyntheticEvent<HTMLDetailsElement>) => setOpen(path, event.currentTarget.open)
    return <details className="agent-tree-directory" data-tree-path={path} open={open} onToggle={toggle}><summary><i className="fas fa-chevron-right agent-tree-chevron" aria-hidden="true" /><i className="fas fa-folder agent-tree-icon" aria-hidden="true" /><span className="agent-tree-label">{name}</span></summary><div className="agent-tree-children">{children.map((child, index) => <WorkspaceNode node={child} depth={depth + 1} openPaths={openPaths} setOpen={setOpen} selectedPath={selectedPath} openFile={openFile} key={String(child.path || child.relative_path || child.name || index)} />)}</div></details>
  }
  return <button className={`agent-tree-file${path === selectedPath ? ' is-active' : ''}`} type="button" title={path} onClick={() => openFile(path)}><span /><i className="fas fa-file agent-tree-icon" aria-hidden="true" /><span className="agent-tree-label">{name}</span>{node.size != null ? <small className="agent-tree-size">{humanFileSize(node.size)}</small> : null}</button>
}

export function AgentWorkspaceTree({payload, selectedPath, openFile}: {payload: JsonRecord[] | JsonRecord; selectedPath: string; openFile: (path: string) => void}) {
  const tree = normalizeWorkspaceTree(payload)
  const signature = JSON.stringify(tree)
  const [openPaths, setOpenPaths] = useState<Set<string>>(() => new Set(tree.filter(isDirectory).map(nodePath)))
  useEffect(() => {
    setOpenPaths((current) => {
      const next = new Set(current)
      tree.filter(isDirectory).forEach((node) => next.add(nodePath(node)))
      return next
    })
  }, [signature])
  const setOpen = (path: string, open: boolean) => setOpenPaths((current) => {
    const next = new Set(current)
    if (open) next.add(path); else next.delete(path)
    return next
  })
  if (!tree.length) return <div className="agent-workspace-empty">Workspace 还是空的。</div>
  return <>{tree.map((node, index) => <WorkspaceNode node={node} depth={0} openPaths={openPaths} setOpen={setOpen} selectedPath={selectedPath} openFile={openFile} key={String(node.path || node.relative_path || node.name || index)} />)}</>
}
