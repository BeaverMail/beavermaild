import adapter from '@sveltejs/adapter-static'
import { sveltekit } from '@sveltejs/kit/vite'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// Beaver admin UI: static SPA; /api proxied to beaver serve in dev.
export default defineConfig({
  plugins: [
    tailwindcss(),
    sveltekit({
      compilerOptions: {
        runes: ({ filename }) => (filename.split(/[/\\]/).includes('node_modules') ? undefined : true)
      },
      adapter: adapter({
        pages: '../internal/webui/dist',
        assets: '../internal/webui/dist',
        fallback: 'index.html',
        strict: false
      })
    })
  ],
  server: {
    proxy: {
      '/api': {
        target: process.env.BEAVER_API_PROXY ?? 'http://127.0.0.1:8080',
        changeOrigin: true
      }
    }
  }
})
