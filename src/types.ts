/**
 * Type definitions for tinyland-threat-detection
 *
 * Includes:
 * - Loki/Prometheus/Tempo backend result types
 * - Fingerprint record types (matching @tummycrypt/tinyland-otel TempoFingerprintRecord)
 * - Threat correlation types (VPN switching, IP rotation, impossible travel)
 * - Security data types (audit logs, session stats, metrics, alerts)
 *
 * @module types
 */

// ============================================================================
// Backend Result Types (for DI interfaces)
// ============================================================================

/**
 * Loki log stream entry
 */
export interface LokiStream {
  stream: Record<string, string>;
  values: [string, string][];
}

/**
 * Loki query result
 */
export interface LokiQueryResult {
  status: string;
  data?: {
    resultType: string;
    result: LokiStream[];
  };
}

/**
 * Prometheus metric result entry
 */
export interface PrometheusMetricResult {
  metric: Record<string, string>;
  value?: [number, string];
  values?: [number, string][];
}

/**
 * Prometheus query result
 */
export interface PrometheusQueryResult {
  status: string;
  data?: {
    resultType: string;
    result: PrometheusMetricResult[];
  };
}

/**
 * Tempo trace search result entry
 */
export interface TempoSearchResultEntry {
  traceID: string;
  rootServiceName?: string;
  rootTraceName?: string;
  startTimeUnixNano: string;
  durationMs: number;
  spanSets?: Array<{
    spans: Array<{
      spanID: string;
      startTimeUnixNano: string;
      durationNanos: string;
      attributes?: Array<{
        key: string;
        value: { stringValue?: string; intValue?: string; boolValue?: boolean };
      }>;
    }>;
  }>;
}

/**
 * Tempo search result
 */
export interface TempoSearchResult {
  traces: TempoSearchResultEntry[];
  metrics?: Record<string, unknown>;
}

/**
 * Tempo trace span
 */
export interface TempoSpan {
  traceId: string;
  spanId: string;
  operationName: string;
  startTime: number;
  duration: number;
  tags: Array<{ key: string; value: string }>;
}

/**
 * Tempo trace
 */
export interface TempoTrace {
  traceID: string;
  spans: TempoSpan[];
}

// ============================================================================
// Fingerprint Record (minimal type matching TempoFingerprintRecord)
// ============================================================================

/**
 * Fingerprint record extracted from Tempo spans.
 *
 * This is a local type definition that matches the shape of
 * `TempoFingerprintRecord` from `@tummycrypt/tinyland-otel`.
 * Used to decouple this package from the otel package.
 */
export interface FingerprintRecord {
  // Trace context
  traceID: string;
  spanID: string;
  timestamp: string;
  duration: number;

  // Core fingerprint
  fingerprintId: string;
  fingerprintHash?: string;
  eventType: string;

  // Session context
  sessionId?: string;
  userId?: string;
  userHandle?: string;
  userRole?: string;

  // GeoIP data
  geoCountry?: string;
  geoCity?: string;
  geoLatitude?: number;
  geoLongitude?: number;
  geoSource?: string;

  // VPN detection
  vpnDetected?: boolean;
  vpnProvider?: string;
  vpnConfidence?: string;
  vpnMethod?: string;

  // Device context
  deviceType?: string;

  // Browser/OS intelligence
  browserName?: string;
  browserVersion?: string;
  browserMajorVersion?: string;
  osName?: string;
  osVersion?: string;
  engineName?: string;
  engineVersion?: string;

  // Navigation context
  navigationPathname?: string;
  navigationHostname?: string;
  navigationCurrentUrl?: string;
  navigationReferrer?: string;
  navigationReferrerHostname?: string;
  navigationIsExternalReferral?: boolean;

  // Risk scoring
  riskScore?: number;
  riskTier?: string;
  riskFactors?: string[];

  // IP context (hashed only)
  ipHash?: string;
  ipType?: 'private' | 'public' | 'unknown';

  // Consent data
  consentTimestamp?: string;
  consentVersion?: string;
}

/**
 * Interface for querying fingerprint records from Tempo.
 *
 * This abstracts the `TempoQueryService` from `@tummycrypt/tinyland-otel`
 * so this package does not depend on it directly.
 */
export interface FingerprintQueryBackend {
  /**
   * Query fingerprint records from the tracing backend.
   *
   * @param timeRange - Time range string (e.g., "7d", "24h", "1h")
   * @param tags - Tag filters (e.g., \{ "fingerprint.id": "abc123" \})
   * @param limit - Max results (default 1000)
   * @returns Array of fingerprint records extracted from spans
   */
  queryFingerprints(
    timeRange: string,
    tags?: Record<string, string>,
    limit?: number
  ): Promise<FingerprintRecord[]>;
}

// ============================================================================
// ThreatCorrelationService Types
// ============================================================================

/**
 * VPN status change event
 */
export interface VPNChange {
  /** ISO timestamp of the change */
  timestamp: string;
  /** VPN detected state */
  vpnDetected: boolean;
  /** Hashed IP address (SHA-256) */
  ipHash: string;
  /** City name (if available) */
  city?: string;
  /** Country name */
  country?: string;
  /** VPN provider name (if detected) */
  provider?: string;
  /** VPN detection confidence (0.0-1.0) */
  confidence?: number;
}

/**
 * Fingerprint with VPN switching behavior
 */
export interface VPNSwitcher {
  /** Fingerprint ID */
  fingerprintId: string;
  /** First time this fingerprint was seen */
  firstSeen: string;
  /** Most recent activity */
  lastSeen: string;
  /** Timeline of VPN status changes */
  vpnChanges: VPNChange[];
  /** Total number of VPN status changes */
  totalChanges: number;
  /** Calculated risk score (0-100) */
  riskScore: number;
  /** Optional description of suspicious activity */
  suspiciousActivity?: string;
}

/**
 * IP address change event
 */
export interface IPChange {
  /** ISO timestamp of the change */
  timestamp: string;
  /** Hashed IP address (SHA-256) */
  ipHash: string;
  /** City name (if available) */
  city?: string;
  /** Country name */
  country?: string;
  /** VPN detected for this IP */
  vpnDetected: boolean;
}

/**
 * IP rotation pattern for a fingerprint
 */
export interface IPRotationPattern {
  /** Fingerprint ID */
  fingerprintId: string;
  /** Time window analyzed (e.g., "7d") */
  timeWindow: string;
  /** Number of unique IP addresses used */
  uniqueIPs: number;
  /** Timeline of IP changes */
  ipChanges: IPChange[];
  /** Average seconds between IP changes */
  avgTimeBetweenChanges: number;
  /** Suspicion level based on rotation speed */
  suspicionLevel: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Geographic location point
 */
export interface LocationPoint {
  /** ISO timestamp */
  timestamp: string;
  /** Latitude (-90 to 90) */
  latitude: number;
  /** Longitude (-180 to 180) */
  longitude: number;
  /** City name (if available) */
  city?: string;
  /** Country name */
  country?: string;
}

/**
 * Impossible travel detection result
 */
export interface ImpossibleTravelEvent {
  /** Fingerprint ID */
  fingerprintId: string;
  /** Starting location */
  fromLocation: LocationPoint;
  /** Ending location */
  toLocation: LocationPoint;
  /** Distance in kilometers */
  distanceKm: number;
  /** Time elapsed in seconds */
  timeElapsedSeconds: number;
  /** Implied speed in km/h */
  impliedSpeedKmh: number;
  /** Maximum realistic speed (typically 900 km/h for commercial flight) */
  maxRealisticSpeedKmh: number;
  /** How many times faster than realistic (impliedSpeed / maxRealisticSpeed) */
  impossibilityFactor: number;
}

/**
 * Fingerprint activity event
 */
export interface FingerprintActivity {
  /** ISO timestamp */
  timestamp: string;
  /** URL visited (if available) */
  url?: string;
  /** Hashed IP address */
  ipHash: string;
  /** IP type (private = local network, public = internet) */
  ipType?: 'private' | 'public' | 'unknown';
  /** City name (if available) */
  city?: string;
  /** Country name */
  country?: string;
  /** VPN detected */
  vpnDetected: boolean;
  /** Risk score (if calculated) */
  riskScore?: number;
  /** User agent string */
  userAgent?: string;
  /** Session ID */
  sessionId?: string;
  /** User ID (if authenticated) */
  userId?: string;
  /** User handle (if authenticated) */
  userHandle?: string;
}

/**
 * VPN usage statistics
 */
export interface VPNUsage {
  /** Number of visits with VPN */
  vpnVisits: number;
  /** Number of visits without VPN */
  organicVisits: number;
  /** Number of VPN status changes */
  changes: number;
}

/**
 * Browser information
 */
export interface BrowserInfo {
  name: string;
  version?: string;
}

/**
 * Device information
 */
export interface DeviceInfo {
  type: string;
  os?: string;
  osVersion?: string;
}

/**
 * Page visit record
 */
export interface PageVisit {
  url: string;
  timestamp: string;
}

/**
 * Complete timeline of fingerprint activities
 */
export interface FingerprintTimeline {
  /** Fingerprint ID */
  fingerprintId: string;
  /** First time seen */
  firstSeen: string;
  /** Most recent activity */
  lastSeen: string;
  /** Total number of visits */
  totalVisits: number;
  /** Number of unique IP addresses */
  uniqueIPs: number;
  /** Number of unique geographic locations */
  uniqueLocations: number;
  /** VPN usage statistics */
  vpnUsage: VPNUsage;
  /** Chronological list of activities */
  activities: FingerprintActivity[];
  /** Detected suspicious patterns */
  suspiciousPatterns: string[];
  /** Browser information (from most recent visit) */
  browserInfo?: BrowserInfo;
  /** Device information (from most recent visit) */
  deviceInfo?: DeviceInfo;
  /** List of unique IP addresses used */
  ipHistory: string[];
  /** Pages visited with timestamps */
  pageVisits: PageVisit[];
}

/**
 * High request rate evidence
 */
export interface HighRequestRateEvidence {
  /** Requests per minute */
  requestsPerMinute: number;
  /** Threshold that was exceeded */
  threshold: number;
  /** Time window analyzed */
  timeWindow: string;
}

/**
 * Failed login evidence
 */
export interface FailedLoginEvidence {
  /** Number of failed attempts */
  attempts: number;
  /** Time window analyzed */
  timeWindow: string;
  /** URLs where attempts occurred */
  targetPages: string[];
}

/**
 * Attack evidence
 */
export interface AttackEvidence {
  /** High request rate detection (DDoS/scraping) */
  highRequestRate?: HighRequestRateEvidence;
  /** Failed login detection (brute-force) */
  failedLogins?: FailedLoginEvidence;
  /** Suspicious URLs accessed */
  suspiciousURLs?: string[];
}

/**
 * Attack correlation with prior reconnaissance
 */
export interface AttackCorrelation {
  /** Fingerprint ID of attacker */
  fingerprintId: string;
  /** Type of attack detected */
  attackType: 'ddos' | 'scraping' | 'brute-force' | 'unknown';
  /** When attack was detected */
  detectedAt: string;
  /** Evidence of the attack */
  evidence: AttackEvidence;
  /** Prior activity timeline (reconnaissance phase) */
  priorActivity: FingerprintTimeline;
  /** Whether VPN was enabled shortly before attack */
  vpnSwitchedBeforeAttack: boolean;
}

// ============================================================================
// SecurityDataService Types
// ============================================================================

/**
 * Audit log entry from Loki
 */
export interface AuditLog {
  timestamp: string;
  eventType: string;
  userId?: string;
  userHandle?: string;
  details?: unknown;
  severity: 'info' | 'warning' | 'critical';
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Session statistics from Prometheus
 */
export interface SessionStats {
  activeSessions: number;
  recentlyExpired: number;
  averageSessionDuration: number;
}

/**
 * Security metrics summary
 */
export interface SecurityMetrics {
  totalUsers: number;
  activeUsers: number;
  failedLogins24h: number;
  successfulLogins24h: number;
  totpEnabledUsers: number;
  backupCodesUsed: number;
  criticalEvents: number;
  suspiciousActivities: number;
}

/**
 * Fingerprint alert (session hijacking detection)
 */
export interface FingerprintAlert {
  timestamp: string;
  userId?: string;
  userHandle?: string;
  sessionId: string;
  alertType: string;
  details: unknown;
  riskLevel: 'low' | 'medium' | 'high';
  /** Enriched fingerprint data */
  enriched?: FingerprintAlertEnriched;
}

/**
 * Enriched fingerprint data attached to alerts
 */
export interface FingerprintAlertEnriched {
  fingerprintId?: string;
  fingerprintHash?: string;
  clientIp?: string;
  clientIpMasked?: string;
  geoCountry?: string;
  geoCountryCode?: string;
  geoCity?: string;
  geoLatitude?: number;
  geoLongitude?: number;
  geoTimezone?: string;
  vpnDetected?: boolean;
  vpnProvider?: string | null;
  vpnConfidence?: 'low' | 'medium' | 'high';
  vpnMethod?: 'asn' | 'datacenter' | 'unknown';
  userAgent?: string;
  deviceType?: string;
  canvasFingerprint?: string;
  webglFingerprint?: string;
  screenResolution?: string;
  browserTimezone?: string;
  browserLanguage?: string;
  platform?: string;
  cookiesEnabled?: boolean;
  totpEnabled?: boolean;
  userActive?: boolean;
  loginCount?: number;
  failedLoginAttempts?: number;
  eventType?: string;
  severity?: string;
  riskScore?: number;
  riskTier?: 'low' | 'medium' | 'high' | 'critical';
  riskFactors?: string;
  riskRecommendation?: string;
}

/**
 * GeoIP anomaly (impossible travel from Loki)
 */
export interface GeoIPAnomaly {
  timestamp: string;
  userId?: string;
  sessionId: string;
  fromLocation: string;
  toLocation: string;
  distance: number;
  riskLevel: 'low' | 'medium' | 'high';
}
