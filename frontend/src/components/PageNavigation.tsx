import {forwardRef, useCallback} from 'react'
import {
  Link as RouterLink,
  useNavigate as useRouterNavigate,
  type LinkProps,
  type NavigateFunction,
  type NavigateOptions,
  type To,
} from 'react-router-dom'

export const Link = forwardRef<HTMLAnchorElement, LinkProps>(function PageLink(
  {viewTransition = true, ...props},
  ref,
) {
  return <RouterLink ref={ref} viewTransition={viewTransition} {...props} />
})

export function useNavigate(): NavigateFunction {
  const navigate = useRouterNavigate()
  return useCallback(((to: To | number, options?: NavigateOptions) => {
    if (typeof to === 'number') return navigate(to)
    return navigate(to, {viewTransition: true, ...options})
  }) as NavigateFunction, [navigate])
}
