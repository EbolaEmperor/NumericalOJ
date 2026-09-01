import {defineConfig} from 'vitest/config'
import react from '@vitejs/plugin-react'
import type {ProxyOptions} from 'vite'

const backendOrigin = 'http://127.0.0.1:2025'
const backendProxy = (): ProxyOptions => ({
  target: backendOrigin,
  changeOrigin: true,
  headers: {Origin: backendOrigin},
})

export default defineConfig({
  plugins: [react()],
  test: {
    exclude: ['tests/**', 'node_modules/**', 'dist/**'],
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
    manifest: true,
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': backendProxy(),
      // Agent 工作块仍沿用历史同源 API 路径；本地开发也必须把它交给 Flask，
      // 否则 Vite 会回退到 SPA HTML，展开详情时就会被误判为 JSON 失败。
      '/agent/runs': backendProxy(),
      // 这两类是下载/作品容器代理，不是页面路由。其余页面必须由 Vite
      // 自己回退到 React 入口。
      '/vibehub/runtime': backendProxy(),
    },
  },
})
