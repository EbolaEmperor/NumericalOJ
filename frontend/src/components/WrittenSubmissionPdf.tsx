import {useEffect, useRef, useState} from 'react'

import {MathCurveLoader} from './MathCurveLoader'

export function WrittenSubmissionPdf({submission}: {submission: {id: number; status?: string}}) {
  const active = ['Pending', 'Waiting', 'Running', 'Generating'].includes(String(submission.status || ''))
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [version, setVersion] = useState(0)
  const [retryVersion, setRetryVersion] = useState(0)
  const activeRef = useRef(active)
  const readyRef = useRef(false)
  const url = `/api/submissions/${submission.id}/file`
  activeRef.current = active
  useEffect(() => {
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | null = null
    let attempts = 0
    let checking = false
    readyRef.current = false
    setState('loading')
    const check = async () => {
      if (cancelled || checking) return
      checking = true
      attempts += 1
      try {
        const response = await fetch(`${url}?check=${Date.now()}`, {method: 'HEAD', cache: 'no-store', credentials: 'same-origin'})
        if (cancelled) return
        if (response.ok) {
          readyRef.current = true
          setVersion(Date.now())
          setState('ready')
          return
        }
      } catch {
        if (cancelled) return
      } finally {
        checking = false
      }
      if (activeRef.current && attempts < 180) {
        setState('loading')
        timer = window.setTimeout(() => {void check()}, 1_000)
      } else setState('error')
    }
    const onFocus = () => {if (readyRef.current && !activeRef.current) setVersion(Date.now()); else {attempts = 0; void check()}}
    window.addEventListener('focus', onFocus)
    void check()
    return () => {cancelled = true; if (timer) window.clearTimeout(timer); window.removeEventListener('focus', onFocus)}
  }, [retryVersion, url])
  return <div className="submission-pdf-surface" id="pdfViewer">{state === 'ready' ? <iframe title="submission-pdf" className="w-100 h-100 border-0" referrerPolicy="no-referrer" src={`${url}?v=${version}`} onError={() => {readyRef.current = false; setState('error')}} /> : <div className={`submission-pdf-hint ${state === 'error' ? 'text-danger' : 'text-muted'}`}>{state === 'error' ? <><span>PDF 不可用</span><button className="submission-button submission-button--ghost" type="button" onClick={() => setRetryVersion((current) => current + 1)}>重新检查</button></> : <MathCurveLoader size="lg" label={active ? 'PDF 生成中…' : '正在加载 PDF…'} />}</div>}</div>
}
