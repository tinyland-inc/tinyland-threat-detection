/**
 * @tummycrypt/tinyland-threat-detection
 *
 * Threat correlation, security data querying, VPN switching detection,
 * IP rotation analysis, and impossible travel detection.
 *
 * Uses dependency injection for all observability backends (Loki, Prometheus, Tempo)
 * to remain decoupled from any specific framework or HTTP client.
 *
 * Usage:
 * ```typescript
 * import {
 *   configureThreatDetection,
 *   ThreatCorrelationService,
 *   SecurityDataService,
 * } from '@tummycrypt/tinyland-threat-detection';
 *
 * // Configure once at startup
 * configureThreatDetection({
 *   logger: myStructuredLogger,
 * });
 *
 * // Create services with injected backends
 * const threatService = new ThreatCorrelationService(fingerprintQueryBackend);
 * const securityService = new SecurityDataService(lokiBackend, prometheusBackend);
 *
 * // Use services
 * const switchers = await threatService.detectVPNSwitchers('7d');
 * const logs = await securityService.getAuditLogs('24h');
 * ```
 *
 * @module @tummycrypt/tinyland-threat-detection
 */

// Configuration
export {
  configureThreatDetection,
  getThreatDetectionConfig,
  resetThreatDetectionConfig,
  getLogger,
  getHaversineDistance,
} from './config.js';

export type {
  ThreatDetectionConfig,
  ThreatDetectionLogger,
  LokiBackend,
  PrometheusBackend,
  FingerprintQueryBackend,
  ObservabilityConfig,
} from './config.js';

// Services
export { ThreatCorrelationService } from './ThreatCorrelationService.js';
export { SecurityDataService } from './SecurityDataService.js';

// Types - Backend result types
export type {
  LokiStream,
  LokiQueryResult,
  PrometheusMetricResult,
  PrometheusQueryResult,
  TempoSearchResultEntry,
  TempoSearchResult,
  TempoSpan,
  TempoTrace,
} from './types.js';

// Types - Fingerprint record
export type {
  FingerprintRecord,
} from './types.js';

// Types - Threat correlation
export type {
  VPNChange,
  VPNSwitcher,
  IPChange,
  IPRotationPattern,
  LocationPoint,
  ImpossibleTravelEvent,
  FingerprintActivity,
  VPNUsage,
  BrowserInfo,
  DeviceInfo,
  PageVisit,
  FingerprintTimeline,
  HighRequestRateEvidence,
  FailedLoginEvidence,
  AttackEvidence,
  AttackCorrelation,
} from './types.js';

// Types - Security data
export type {
  AuditLog,
  SessionStats,
  SecurityMetrics,
  FingerprintAlert,
  FingerprintAlertEnriched,
  GeoIPAnomaly,
} from './types.js';
