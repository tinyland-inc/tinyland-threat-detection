


































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


export { ThreatCorrelationService } from './ThreatCorrelationService.js';
export { SecurityDataService } from './SecurityDataService.js';


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


export type {
  FingerprintRecord,
} from './types.js';


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


export type {
  AuditLog,
  SessionStats,
  SecurityMetrics,
  FingerprintAlert,
  FingerprintAlertEnriched,
  GeoIPAnomaly,
} from './types.js';
