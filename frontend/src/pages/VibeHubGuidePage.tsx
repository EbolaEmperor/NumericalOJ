import {useQuery} from '@tanstack/react-query'
import {useEffect} from 'react'

import {apiFetch} from '../api/client'
import type {ApiEnvelope} from '../api/types'
import {MarkdownContent} from '../components/MarkdownContent'
import {Link} from '../components/PageNavigation'
import {ErrorState, LoadingState} from '../components/PageState'

interface GuideResponse extends ApiEnvelope {html: string; toc_html: string}

export default function VibeHubGuidePage() {
  const guide = useQuery({queryKey: ['vibehub', 'guide'], queryFn: () => apiFetch<GuideResponse>('/api/vibehub/developer-guide/rendered'), staleTime: 5 * 60_000})
  useEffect(() => {document.title = 'VibeHub 开发者手册 - Numerical OJ'}, [])
  if (guide.isPending) return <LoadingState label="正在读取开发者手册" />
  if (guide.isError) return <ErrorState message={guide.error.message} retry={() => void guide.refetch()} />
  return <div className="vibe-guide vibe-guide--markdown"><Link className="vibe-guide-back" to="/vibehub"><i className="fas fa-arrow-left" />返回作品列表</Link><div className="vibe-guide-markdown-layout"><MarkdownContent as="aside" ariaLabel="开发者手册目录" html={guide.data.toc_html} className="vibe-guide-markdown-toc" /><MarkdownContent html={guide.data.html} className="vibe-guide-markdown-body numoj-markdown numoj-problem-code-rendering" /></div></div>
}
