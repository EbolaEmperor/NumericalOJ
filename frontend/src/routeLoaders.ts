export const routeLoaders = {
  login: () => import('./pages/LoginPage'),
  problems: () => import('./pages/ProblemsPage'),
  problemDetail: () => import('./pages/ProblemDetailPage'),
  submissions: () => import('./pages/SubmissionsPage'),
  submissionDetail: () => import('./pages/SubmissionDetailPage'),
  rankings: () => import('./pages/RankingsPage'),
  rankingDetail: () => import('./pages/RankingDetailPage'),
  forum: () => import('./pages/ForumPage'),
  repository: () => import('./pages/RepositoryPage'),
  vibehub: () => import('./pages/VibeHubPage'),
  agents: () => import('./pages/AgentTasksPage'),
  admin: () => import('./pages/AdminPage'),
  notFound: () => import('./pages/NotFoundPage'),
} as const

const navigationLoaders = {
  problems: routeLoaders.problems,
  submissions: routeLoaders.submissions,
  rankings: routeLoaders.rankings,
  agents: routeLoaders.agents,
  forum: routeLoaders.forum,
  repository: routeLoaders.repository,
  vibehub: routeLoaders.vibehub,
  admin: routeLoaders.admin,
} as const

export function preloadNavigationRoute(id: string) {
  const loader = navigationLoaders[id as keyof typeof navigationLoaders]
  if (loader) void loader()
}
