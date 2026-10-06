import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Absolute base under the routed prefix: assets resolve to /ssh/assets/*
// whether the page URL has a trailing slash or not (no redirect needed).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: '/ssh/',
})
