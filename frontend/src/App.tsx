import {lazy, Suspense, useEffect} from 'react'
import {Navigate, Route, Routes, useLocation} from 'react-router-dom'

import {AppShell} from './components/AppShell'
import {LoadingState} from './components/PageState'
import {routeLoaders} from './routeLoaders'
import {useSession} from './session'

const LoginPage = lazy(routeLoaders.login)
const RegisterPage = lazy(routeLoaders.register)
const ForgotPasswordPage = lazy(routeLoaders.forgotPassword)
const ProblemsPage = lazy(routeLoaders.problems)
const ProblemDetailPage = lazy(routeLoaders.problemDetail)
const ProblemEditorPage = lazy(routeLoaders.problemEditor)
const SubmissionsPage = lazy(routeLoaders.submissions)
const SubmissionDetailPage = lazy(routeLoaders.submissionDetail)
const RankingsPage = lazy(routeLoaders.rankings)
const RankingDetailPage = lazy(routeLoaders.rankingDetail)
const RankingAppealReviewPage = lazy(routeLoaders.rankingAppealReview)
const ForumPage = lazy(routeLoaders.forum)
const RepositoryPage = lazy(routeLoaders.repository)
const VibeHubPage = lazy(routeLoaders.vibehub)
const VibeHubGuidePage = lazy(routeLoaders.vibehubGuide)
const VibeHubPlayerPage = lazy(routeLoaders.vibehubPlayer)
const AgentTasksPage = lazy(routeLoaders.agents)
const AgentSessionPage = lazy(routeLoaders.agentSession)
const AdminPage = lazy(routeLoaders.admin)
const HomeworkAdminPage = lazy(routeLoaders.adminHomework)
const AiDetectionPage = lazy(routeLoaders.aiDetection)
const SiteConfigPage = lazy(routeLoaders.siteConfig)
const NotFoundPage = lazy(routeLoaders.notFound)

function ScrollManager() {
  const location = useLocation()
  useEffect(() => {
    window.scrollTo({top: 0, behavior: 'instant'})
  }, [location.pathname])
  return null
}

const staticTitles: Record<string, string> = {
  '/problems': '题目列表 - Numerical OJ',
  '/submissions': '提交记录 - Numerical OJ',
  '/rankings': '打榜赛 - Numerical OJ',
  '/agents': 'Agent 任务 - Numerical OJ',
  '/forum': '讨论区 - Numerical OJ',
  '/repository': '代码仓库 - Numerical OJ',
  '/vibehub': 'VibeHub - Numerical OJ',
  '/admin': '用户管理 - Numerical OJ',
  '/admin/homework': '作业管理 - Numerical OJ',
  '/admin/ai-detection': 'AI 代码检测 - Numerical OJ',
  '/admin/site-config': '全站配置 - Numerical OJ',
}

function RouteTitleManager() {
  const location = useLocation()
  useEffect(() => {
    const title = staticTitles[location.pathname]
    if (title) document.title = title
  }, [location.pathname])
  return null
}

function ProtectedShell() {
  const {session, loading} = useSession()
  if (loading) return <LoadingState label="正在建立安全会话" />
  if (!session?.user) return <Navigate to="/login" replace />
  return <AppShell />
}

export function App() {
  return (
    <Suspense fallback={<LoadingState />}>
      <ScrollManager />
      <RouteTitleManager />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/" element={<ProtectedShell />}>
          <Route index element={<Navigate to="problems" replace />} />
          <Route path="problems" element={<ProblemsPage />} />
          <Route path="problems/:problemId" element={<ProblemDetailPage />} />
          <Route path="admin/problems/new" element={<ProblemEditorPage />} />
          <Route path="admin/problems/:problemId/edit" element={<ProblemEditorPage />} />
          <Route path="submissions" element={<SubmissionsPage />} />
          <Route path="submissions/:submissionId" element={<SubmissionDetailPage />} />
          <Route path="rankings" element={<RankingsPage />} />
          <Route path="rankings/:competitionId" element={<RankingDetailPage />} />
          <Route path="rankings/:competitionId/appeals/:appealId" element={<RankingAppealReviewPage />} />
          <Route path="agents" element={<AgentTasksPage />} />
          <Route path="agents/:sessionId" element={<AgentSessionPage />} />
          <Route path="forum" element={<ForumPage />} />
          <Route path="forum/:threadId" element={<ForumPage />} />
          <Route path="repository" element={<RepositoryPage />} />
          <Route path="vibehub" element={<VibeHubPage />} />
          <Route path="vibehub/guide" element={<VibeHubGuidePage />} />
          <Route path="vibehub/:slug" element={<VibeHubPlayerPage />} />
          <Route path="vibehub/:slug/play" element={<VibeHubPlayerPage />} />
          <Route path="admin" element={<AdminPage />} />
          <Route path="admin/homework" element={<HomeworkAdminPage />} />
          <Route path="admin/ai-detection" element={<AiDetectionPage />} />
          <Route path="admin/ai-detection/problems/:detectionProblemId" element={<AiDetectionPage />} />
          <Route path="admin/ai-detection/students/:detectionUsername" element={<AiDetectionPage />} />
          <Route path="admin/site-config" element={<SiteConfigPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Suspense>
  )
}
