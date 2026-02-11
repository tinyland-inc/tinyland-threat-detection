/**
 * Configuration injection for tinyland-threat-detection
 *
 * All external dependencies (logger, observability backends) are injected
 * via configuration rather than imported directly, enabling this package
 * to be used standalone without SvelteKit coupling.
 *
 * @module config
 */

import type {
  LokiQueryResult,
  PrometheusQueryResult,
  FingerprintRecord,
} from './types.js';

// ============================================================================
// Logger Interface
// ============================================================================

/**
 * Logger interface compatible with any structured logging library.
 * When not configured, a no-op logger is used.
 */
export interface ThreatDetectionLogger {
  info: (msg: string, meta?: Record<string, unknown>) => void;
  warn: (msg: string, meta?: Record<string, unknown>) => void;
  error: (msg: string, meta?: Record<string, unknown>) => void;
  debug: (msg: string, meta?: Record<string, unknown>) => void;
}

// ============================================================================
// Backend Interfaces
// ============================================================================

/**
 * Backend for querying Loki logs.
 *
 * Implementations should wrap the Loki HTTP API:
 * - `query` maps to `/loki/api/v1/query` (instant) or `/loki/api/v1/query_range`
 *
 * @example
 * ```typescript
 * const lokiBackend: LokiBackend = {
 *   async query(logql, params) {
 *     const response = await fetch(`${lokiUrl}/loki/api/v1/query_range?query=${encodeURIComponent(logql)}`);
 *     return response.json();
 *   }
 * };
 * ```
 */
export interface LokiBackend {
  query: (logql: string, params?: {
    start?: string;
    end?: string;
    limit?: number;
  }) => Promise<LokiQueryResult>;
}

/**
 * Backend for querying Prometheus metrics.
 *
 * Implementations should wrap the Prometheus HTTP API:
 * - `query` maps to `/api/v1/query` (instant)
 * - `queryRange` maps to `/api/v1/query_range` (range)
 *
 * @example
 * ```typescript
 * const prometheusBackend: PrometheusBackend = {
 *   async query(promql) {
 *     const response = await fetch(`${promUrl}/api/v1/query?query=${encodeURIComponent(promql)}`);
 *     return response.json();
 *   },
 *   async queryRange(promql, params) {
 *     const response = await fetch(`${promUrl}/api/v1/query_range?query=${encodeURIComponent(promql)}&start=${params.start}&end=${params.end}&step=${params.step}`);
 *     return response.json();
 *   }
 * };
 * ```
 */
export interface PrometheusBackend {
  query: (promql: string, params?: {
    time?: string;
  }) => Promise<PrometheusQueryResult>;
  queryRange: (promql: string, params: {
    start: string;
    end: string;
    step: string;
  }) => Promise<PrometheusQueryResult>;
}

/**
 * Backend for querying fingerprint records (abstracts Tempo).
 *
 * This replaces the direct dependency on `TempoQueryService` from
 * `@tinyland-inc/tinyland-otel`. Implementations should wrap the
 * Tempo search API and extract fingerprint records from spans.
 *
 * @example
 * ```typescript
 * import { TempoQueryService } from '@tinyland-inc/tinyland-otel';
 *
 * const tempoService = new TempoQueryService();
 * const fingerprintBackend: FingerprintQueryBackend = {
 *   queryFingerprints: (timeRange, tags, limit) =>
 *     tempoService.queryFingerprints(timeRange, tags, limit)
 * };
 * ```
 */
export interface FingerprintQueryBackend {
  queryFingerprints: (
    timeRange: string,
    tags?: Record<string, string>,
    limit?: number,
  ) => Promise<FingerprintRecord[]>;
}

// ============================================================================
// Observability Config
// ============================================================================

/**
 * Observability stack endpoint configuration.
 * Used by SecurityDataService when backend interfaces are not provided.
 */
export interface ObservabilityConfig {
  lokiUrl?: string;
  prometheusUrl?: string;
  tempoUrl?: string;
}

// ============================================================================
// Main Configuration
// ============================================================================

/**
 * Configuration for the tinyland-threat-detection package.
 *
 * All fields are optional. When not provided, sensible defaults are used:
 * - logger: no-op (silent)
 * - backends: operations that require them will throw descriptive errors
 * - haversineDistance: built-in implementation
 *
 * @example
 * ```typescript
 * import { configureThreatDetection } from '@tinyland-inc/tinyland-threat-detection';
 *
 * configureThreatDetection({
 *   logger: myStructuredLogger,
 *   fingerprintQuery: myTempoService,
 *   loki: myLokiBackend,
 *   prometheus: myPrometheusBackend,
 * });
 * ```
 */
export interface ThreatDetectionConfig {
  logger?: ThreatDetectionLogger;
  loki?: LokiBackend;
  prometheus?: PrometheusBackend;
  fingerprintQuery?: FingerprintQueryBackend;
  observabilityConfig?: ObservabilityConfig;
  /** Haversine distance function - defaults to built-in implementation */
  haversineDistance?: (lat1: number, lon1: number, lat2: number, lon2: number) => number;
}

// ============================================================================
// Configuration State
// ============================================================================

const noopLogger: ThreatDetectionLogger = {
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {},
};

let config: ThreatDetectionConfig = {};

/**
 * Configure the threat detection package.
 *
 * Call this once at application startup to inject dependencies.
 * Subsequent calls merge with existing configuration.
 *
 * @param c - Configuration to apply (merged with existing)
 *
 * @example
 * ```typescript
 * configureThreatDetection({
 *   logger: myLogger,
 *   fingerprintQuery: myTempoService,
 *   loki: myLokiBackend,
 *   prometheus: myPrometheusBackend,
 * });
 * ```
 */
export function configureThreatDetection(c: ThreatDetectionConfig): void {
  config = { ...config, ...c };
}

/**
 * Get the current threat detection configuration.
 */
export function getThreatDetectionConfig(): ThreatDetectionConfig {
  return config;
}

/**
 * Reset all configuration to defaults.
 * Primarily useful in tests to ensure clean state.
 */
export function resetThreatDetectionConfig(): void {
  config = {};
}

/**
 * Get the configured logger, or a no-op logger if none was configured.
 */
export function getLogger(): ThreatDetectionLogger {
  return config.logger ?? noopLogger;
}

// ============================================================================
// Built-in Haversine Distance
// ============================================================================

/**
 * Default haversine distance calculation.
 *
 * Calculates the great-circle distance between two points on Earth
 * using the Haversine formula.
 *
 * @param lat1 - Latitude of point 1 in degrees
 * @param lon1 - Longitude of point 1 in degrees
 * @param lat2 - Latitude of point 2 in degrees
 * @param lon2 - Longitude of point 2 in degrees
 * @returns Distance in kilometers
 */
function defaultHaversine(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371; // Earth's radius in km
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

/**
 * Get the configured haversine distance function, or the built-in default.
 */
export function getHaversineDistance(): (lat1: number, lon1: number, lat2: number, lon2: number) => number {
  return config.haversineDistance ?? defaultHaversine;
}
