import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import path from 'node:path';

// Report Portal Vite build.
//
// outDir: points directly at pkg/server/ui/dist so `//go:embed all:ui/dist`
// in pkg/server/ui.go picks up the Vue bundle without any symlink.
//
// emptyOutDir: false — during phase 1 → phase 4 migration the dist also
// holds the tracked .gitkeep. Wiping would dirty the git index. Stale
// vanilla files (app.js, views/, components/) sit unreferenced by the
// new index.html and are cleaned up in phase 4's cutover.
// (The Manage portal's vanilla subfolder at ui/dist/manage/ was
// removed in Batch I of the manage-portal-vue-ui PR.)
export default defineConfig({
  plugins: [vue()],
  base: '/ui/',
  build: {
    outDir: path.resolve(__dirname, '../../../pkg/server/ui/dist'),
    emptyOutDir: false,
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['vue', 'vue-router', 'pinia'],
        },
      },
    },
  },
  server: {
    port: 5174,
    proxy: {
      '/api': 'http://localhost:8080',
    },
  },
});
