import {lazy, Suspense, useEffect} from 'react'
import {Navigate, Route, Routes, useLocation} from 'react-router-dom'

import {AppShell} from './components/AppShell'
import {LoadingState} from './components/PageState'
import {routeLoaders} from './routeLoaders'
import {useSession} from './session'

const LoginPage = lazy(routeLoaders.login)
const ProblemsPage = lazy(routeLoaders.problems)
const ProblemDetailPage = lazy(routeLoaders.problemDetail)
const SubmissionsPage = lazy(routeLoaders.submissions)
const SubmissionDetailPage = lazy(routeLoaders.submissionDetail)
const RankingsPage = lazy(routeLoaders.rankings)
const RankingDetailPage = lazy(routeLoaders.rankingDetail)
const ForumPage = lazy(routeLoaders.forum)
const RepositoryPage = lazy(routeLoaders.repository)
const VibeHubPage = lazy(routeLoaders.vibehub)
const AgentTasksPage = lazy(routeLoaders.agents)
const AdminPage = lazy(routeLoaders.admin)
const NotFoundPage = lazy(routeLoaders.notFound)

function ScrollManager() {
  const location = useLocation()
  useEffect(() => {
    window.scrollTo({top: 0, behavior: 'instant'})
  }, [location.pathname])
  return null
}

function ProtectedShell() {
  const {session, loading} = useSession()
  if (loading) return <LoadingState label="正在建立安全会话" />
  if (!session?.user) return <Navigate to="/app/login" replace />
  return <AppShell />
}

export function App() {
  return (
    <Suspense fallback={<LoadingState />}>
      <ScrollManager />
      <Routes>
        <Route path="/app/login" element={<LoginPage />} />
        <Route path="/app" element={<ProtectedShell />}>
          <Route index element={<Navigate to="problems" replace />} />
          <Route path="problems" element={<ProblemsPage />} />
          <Route path="problems/:problemId" element={<ProblemDetailPage />} />
          <Route path="submissions" element={<SubmissionsPage />} />
          <Route path="submissions/:submissionId" element={<SubmissionDetailPage />} />
          <Route path="rankings" element={<RankingsPage />} />
          <Route path="rankings/:competitionId" element={<RankingDetailPage />} />
          <Route path="agents" element={<AgentTasksPage />} />
          <Route path="forum" element={<ForumPage />} />
          <Route path="forum/:threadId" element={<ForumPage />} />
          <Route path="repository" element={<RepositoryPage />} />
          <Route path="vibehub" element={<VibeHubPage />} />
          <Route path="admin" element={<AdminPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/app" replace />} />
      </Routes>
    </Suspense>
  )
}
