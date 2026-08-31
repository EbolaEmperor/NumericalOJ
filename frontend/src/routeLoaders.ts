export const routeLoaders = {
  login: () => import('./pages/LoginPage'),
  register: () => import('./pages/RegisterPage'),
  forgotPassword: () => import('./pages/ForgotPasswordPage'),
  problems: () => import('./pages/ProblemsPage'),
  problemDetail: () => import('./pages/ProblemDetailPage'),
  problemEditor: () => import('./pages/ProblemEditorPage'),
  submissions: () => import('./pages/SubmissionsPage'),
  submissionDetail: () => import('./pages/SubmissionDetailPage'),
  rankings: () => import('./pages/RankingsPage'),
  rankingDetail: () => import('./pages/RankingDetailPage'),
  rankingAppealReview: () => import('./pages/RankingAppealReviewPage'),
  forum: () => import('./pages/ForumPage'),
  repository: () => import('./pages/RepositoryPage'),
  vibehub: () => import('./pages/VibeHubPage'),
  vibehubGuide: () => import('./pages/VibeHubGuidePage'),
  vibehubPlayer: () => import('./pages/VibeHubPlayerPage'),
  agents: () => import('./pages/AgentTasksPage'),
  agentSession: () => import('./pages/AgentSessionPage'),
  admin: () => import('./pages/AdminPage'),
  adminHomework: () => import('./pages/HomeworkAdminPage'),
  aiDetection: () => import('./pages/AiDetectionPage'),
  siteConfig: () => import('./pages/SiteConfigPage'),
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
  admin_homework: routeLoaders.adminHomework,
  ai_detection: routeLoaders.aiDetection,
  site_config: routeLoaders.siteConfig,
} as const

export function preloadNavigationRoute(id: string) {
  const loader = navigationLoaders[id as keyof typeof navigationLoaders]
  if (loader) void loader()
}
