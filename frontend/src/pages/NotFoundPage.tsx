import {Link} from 'react-router-dom'

export default function NotFoundPage() {
  return (
    <div className="numoj-empty-state">
      <span className="display-6 text-muted">404</span>
      <strong>页面不存在</strong>
      <p className="text-muted mb-3">路径可能已经迁移，或者你没有访问它的入口。</p>
      <Link className="btn btn-primary" to="/app/problems">返回题目列表</Link>
    </div>
  )
}
