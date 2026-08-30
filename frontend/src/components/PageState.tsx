import type {PropsWithChildren, ReactNode} from 'react'

export function LoadingState({label = '正在读取最新数据'}: {label?: string}) {
  return (
    <div className="numoj-spa-state" role="status" aria-live="polite">
      <span className="math-curve-loader" data-math-curve-loader data-size="lg">
        <span className="math-curve-loader__label">{label}</span>
      </span>
    </div>
  )
}

export function ErrorState({message, retry}: {message: string; retry?: () => void}) {
  return (
    <div className="numoj-empty-state" role="alert">
      <strong>暂时无法加载</strong>
      <span>{message}</span>
      {retry ? <button className="btn btn-outline-secondary btn-sm" onClick={retry}>重新加载</button> : null}
    </div>
  )
}

export function EmptyState({children, action}: PropsWithChildren<{action?: ReactNode}>) {
  return (
    <div className="numoj-empty-state">
      <strong>{children}</strong>
      {action}
    </div>
  )
}
