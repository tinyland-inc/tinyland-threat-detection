


















export interface LokiStream {
  stream: Record<string, string>;
  values: [string, string][];
}




export interface LokiQueryResult {
  status: string;
  data?: {
    resultType: string;
    result: LokiStream[];
  };
}




export interface PrometheusMetricResult {
  metric: Record<string, string>;
  value?: [number, string];
  values?: [number, string][];
}




export interface PrometheusQueryResult {
  status: string;
  data?: {
    resultType: string;
    result: PrometheusMetricResult[];
  };
}




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




export interface TempoSearchResult {
  traces: TempoSearchResultEntry[];
  metrics?: Record<string, unknown>;
}




export interface TempoSpan {
  traceId: string;
  spanId: string;
  operationName: string;
  startTime: number;
  duration: number;
  tags: Array<{ key: string; value: string }>;
}




export interface TempoTrace {
  traceID: string;
  spans: TempoSpan[];
}












export interface FingerprintRecord {
  
  traceID: string;
  spanID: string;
  timestamp: string;
  duration: number;

  
  fingerprintId: string;
  fingerprintHash?: string;
  eventType: string;

  
  sessionId?: string;
  userId?: string;
  userHandle?: string;
  userRole?: string;

  
  geoCountry?: string;
  geoCity?: string;
  geoLatitude?: number;
  geoLongitude?: number;
  geoSource?: string;

  
  vpnDetected?: boolean;
  vpnProvider?: string;
  vpnConfidence?: string;
  vpnMethod?: string;

  
  deviceType?: string;

  
  browserName?: string;
  browserVersion?: string;
  browserMajorVersion?: string;
  osName?: string;
  osVersion?: string;
  engineName?: string;
  engineVersion?: string;

  
  navigationPathname?: string;
  navigationHostname?: string;
  navigationCurrentUrl?: string;
  navigationReferrer?: string;
  navigationReferrerHostname?: string;
  navigationIsExternalReferral?: boolean;

  
  riskScore?: number;
  riskTier?: string;
  riskFactors?: string[];

  
  ipHash?: string;
  ipType?: 'private' | 'public' | 'unknown';

  
  consentTimestamp?: string;
  consentVersion?: string;
}







export interface FingerprintQueryBackend {
  







  queryFingerprints(
    timeRange: string,
    tags?: Record<string, string>,
    limit?: number
  ): Promise<FingerprintRecord[]>;
}








export interface VPNChange {
  
  timestamp: string;
  
  vpnDetected: boolean;
  
  ipHash: string;
  
  city?: string;
  
  country?: string;
  
  provider?: string;
  
  confidence?: number;
}




export interface VPNSwitcher {
  
  fingerprintId: string;
  
  firstSeen: string;
  
  lastSeen: string;
  
  vpnChanges: VPNChange[];
  
  totalChanges: number;
  
  riskScore: number;
  
  suspiciousActivity?: string;
}




export interface IPChange {
  
  timestamp: string;
  
  ipHash: string;
  
  city?: string;
  
  country?: string;
  
  vpnDetected: boolean;
}




export interface IPRotationPattern {
  
  fingerprintId: string;
  
  timeWindow: string;
  
  uniqueIPs: number;
  
  ipChanges: IPChange[];
  
  avgTimeBetweenChanges: number;
  
  suspicionLevel: 'low' | 'medium' | 'high' | 'critical';
}




export interface LocationPoint {
  
  timestamp: string;
  
  latitude: number;
  
  longitude: number;
  
  city?: string;
  
  country?: string;
}




export interface ImpossibleTravelEvent {
  
  fingerprintId: string;
  
  fromLocation: LocationPoint;
  
  toLocation: LocationPoint;
  
  distanceKm: number;
  
  timeElapsedSeconds: number;
  
  impliedSpeedKmh: number;
  
  maxRealisticSpeedKmh: number;
  
  impossibilityFactor: number;
}




export interface FingerprintActivity {
  
  timestamp: string;
  
  url?: string;
  
  ipHash: string;
  
  ipType?: 'private' | 'public' | 'unknown';
  
  city?: string;
  
  country?: string;
  
  vpnDetected: boolean;
  
  riskScore?: number;
  
  userAgent?: string;
  
  sessionId?: string;
  
  userId?: string;
  
  userHandle?: string;
}




export interface VPNUsage {
  
  vpnVisits: number;
  
  organicVisits: number;
  
  changes: number;
}




export interface BrowserInfo {
  name: string;
  version?: string;
}




export interface DeviceInfo {
  type: string;
  os?: string;
  osVersion?: string;
}




export interface PageVisit {
  url: string;
  timestamp: string;
}




export interface FingerprintTimeline {
  
  fingerprintId: string;
  
  firstSeen: string;
  
  lastSeen: string;
  
  totalVisits: number;
  
  uniqueIPs: number;
  
  uniqueLocations: number;
  
  vpnUsage: VPNUsage;
  
  activities: FingerprintActivity[];
  
  suspiciousPatterns: string[];
  
  browserInfo?: BrowserInfo;
  
  deviceInfo?: DeviceInfo;
  
  ipHistory: string[];
  
  pageVisits: PageVisit[];
}




export interface HighRequestRateEvidence {
  
  requestsPerMinute: number;
  
  threshold: number;
  
  timeWindow: string;
}




export interface FailedLoginEvidence {
  
  attempts: number;
  
  timeWindow: string;
  
  targetPages: string[];
}




export interface AttackEvidence {
  
  highRequestRate?: HighRequestRateEvidence;
  
  failedLogins?: FailedLoginEvidence;
  
  suspiciousURLs?: string[];
}




export interface AttackCorrelation {
  
  fingerprintId: string;
  
  attackType: 'ddos' | 'scraping' | 'brute-force' | 'unknown';
  
  detectedAt: string;
  
  evidence: AttackEvidence;
  
  priorActivity: FingerprintTimeline;
  
  vpnSwitchedBeforeAttack: boolean;
}








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




export interface SessionStats {
  activeSessions: number;
  recentlyExpired: number;
  averageSessionDuration: number;
}




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




export interface FingerprintAlert {
  timestamp: string;
  userId?: string;
  userHandle?: string;
  sessionId: string;
  alertType: string;
  details: unknown;
  riskLevel: 'low' | 'medium' | 'high';
  
  enriched?: FingerprintAlertEnriched;
}




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




export interface GeoIPAnomaly {
  timestamp: string;
  userId?: string;
  sessionId: string;
  fromLocation: string;
  toLocation: string;
  distance: number;
  riskLevel: 'low' | 'medium' | 'high';
}
