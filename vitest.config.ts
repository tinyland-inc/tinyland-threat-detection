/**
 * Vitest Configuration for @tummycrypt/tinyland-threat-detection
 *
 * Works in three modes:
 *   1. Standalone:  cd packages/tinyland-threat-detection && pnpm test
 *   2. Workspace:   vitest run --project=tinyland-threat-detection (from root)
 *   3. Bazel:       bazel test //packages/tinyland-threat-detection:test
 *
 * Security package: 80% coverage thresholds
 */

import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: __dirname,
  test: {
    name: 'tinyland-threat-detection',
    root: __dirname,
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    pool: 'forks',
    isolate: true,
    testTimeout: 10000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      reportsDirectory: './coverage',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.d.ts'],
      thresholds: {
        statements: 80,
        branches: 75,
        functions: 80,
        lines: 80,
      },
    },
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
    },
  },
});
