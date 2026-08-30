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
      '/login': backendProxy(),
      '/logout': backendProxy(),
      '/register': backendProxy(),
      '/forgot_password': backendProxy(),
      '/send_code': backendProxy(),
      '/send_password_code': backendProxy(),
      '/change_password': backendProxy(),
      '/me': backendProxy(),
      '/admin': backendProxy(),
      '/ranking': backendProxy(),
      '/problem': backendProxy(),
      '/problems': backendProxy(),
      '/repository': backendProxy(),
      '/vibehub': backendProxy(),
      '/submit': backendProxy(),
      '/agent': backendProxy(),
      '/submission_status_stream': backendProxy(),
    },
  },
})
