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
      // 这两类是下载/作品容器代理，不是页面路由。其余页面必须由 Vite
      // 自己回退到 React 入口。
      '/vibehub/runtime': backendProxy(),
    },
  },
})
