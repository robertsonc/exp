import { defineConfig } from 'vitest/config';
import preact from '@preact/preset-vite';
import { fileURLToPath } from 'node:url';

// The dev server and `vite preview` proxy /api to the manager. By default that is the mock admin API
// (python test/fakes/mock_admin/server.py --listen 127.0.0.1:18080 --no-auth); override with EXP_API_TARGET.
const target = process.env.EXP_API_TARGET ?? 'http://127.0.0.1:18080';
const proxy = { '/api': { target, changeOrigin: false } };
const shared = fileURLToPath(new URL('../../shared/ui', import.meta.url));

export default defineConfig({
  plugins: [preact()],
  resolve: { alias: { '@shared': shared } },
  server: { port: 5173, proxy, fs: { allow: ['../..'] } },
  preview: { port: 4173, proxy },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
    assetsInlineLimit: 8192,
    chunkSizeWarningLimit: 400,
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['tests/setup.ts'],
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx', 'tests/**/*.test.ts'],
  },
});
