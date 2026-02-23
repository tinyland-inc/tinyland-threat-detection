





import { describe, it, expect } from 'vitest';
import type {
  
  LokiStream,
  LokiQueryResult,
  PrometheusMetricResult,
  PrometheusQueryResult,
  TempoSearchResult,
  TempoTrace,

  
  FingerprintRecord,

  
  VPNChange,
  VPNSwitcher,
  IPChange,
  IPRotationPattern,
  LocationPoint,
  ImpossibleTravelEvent,
  FingerprintActivity,
  FingerprintTimeline,
  AttackCorrelation,

  
  AuditLog,
  SessionStats,
  SecurityMetrics,
  FingerprintAlert,
  FingerprintAlertEnriched,
  GeoIPAnomaly,
} from '../src/types.js';

describe('Backend result types', () => {
  it('should allow constructing a valid LokiQueryResult', () => {
    const result: LokiQueryResult = {
      status: 'success',
      data: {
        resultType: 'streams',
        result: [
          {
            stream: { component: 'auth-audit' },
            values: [['1234567890000000', '{"event_type":"LOGIN_SUCCESS"}']],
          },
        ],
      },
    };
    expect(result.status).toBe('success');
    expect(result.data?.result).toHaveLength(1);
  });

  it('should allow constructing a valid PrometheusQueryResult', () => {
    const result: PrometheusQueryResult = {
      status: 'success',
      data: {
        resultType: 'vector',
        result: [
          {
            metric: { __name__: 'session_active' },
            value: [1234567890, '42'],
          },
        ],
      },
    };
    expect(result.data?.result[0].value?.[1]).toBe('42');
  });

  it('should allow constructing a valid TempoSearchResult', () => {
    const result: TempoSearchResult = {
      traces: [
        {
          traceID: 'abc123',
          rootServiceName: 'sveltekit-server',
          startTimeUnixNano: '1234567890000000',
          durationMs: 100,
        },
      ],
    };
    expect(result.traces).toHaveLength(1);
  });

  it('should allow constructing a valid TempoTrace', () => {
    const trace: TempoTrace = {
      traceID: 'abc123',
      spans: [
        {
          traceId: 'abc123',
          spanId: 'span-1',
          operationName: 'fingerprint.enrichment',
          startTime: 1234567890,
          duration: 100,
          tags: [{ key: 'fingerprint.id', value: 'fp-001' }],
        },
      ],
    };
    expect(trace.spans).toHaveLength(1);
  });

  it('should allow a LokiStream with empty values', () => {
    const stream: LokiStream = {
      stream: {},
      values: [],
    };
    expect(stream.values).toHaveLength(0);
  });

  it('should allow PrometheusMetricResult with range values', () => {
    const result: PrometheusMetricResult = {
      metric: { __name__: 'rate' },
      values: [[1234567890, '10'], [1234567900, '20']],
    };
    expect(result.values).toHaveLength(2);
  });
});

describe('FingerprintRecord type', () => {
  it('should allow constructing a minimal record', () => {
    const record: FingerprintRecord = {
      traceID: 'trace-001',
      spanID: 'span-001',
      timestamp: '2025-01-01T00:00:00Z',
      duration: 1000000,
      fingerprintId: 'fp-001',
      eventType: 'fingerprint.enrichment',
    };
    expect(record.fingerprintId).toBe('fp-001');
  });

  it('should allow all optional fields', () => {
    const record: FingerprintRecord = {
      traceID: 'trace-001',
      spanID: 'span-001',
      timestamp: '2025-01-01T00:00:00Z',
      duration: 1000000,
      fingerprintId: 'fp-001',
      eventType: 'fingerprint.enrichment',
      fingerprintHash: 'hash-abc',
      sessionId: 'sess-001',
      userId: 'user-001',
      geoCountry: 'US',
      geoCity: 'NYC',
      geoLatitude: 40.7128,
      geoLongitude: -74.006,
      vpnDetected: true,
      vpnProvider: 'NordVPN',
      browserName: 'Chrome',
      browserVersion: '120',
      osName: 'macOS',
      deviceType: 'desktop',
      ipHash: 'ip-hash-123',
      ipType: 'public',
      riskScore: 85,
      navigationCurrentUrl: '/admin',
    };
    expect(record.vpnDetected).toBe(true);
    expect(record.riskScore).toBe(85);
  });
});

describe('Threat correlation types', () => {
  it('should allow constructing a VPNSwitcher', () => {
    const switcher: VPNSwitcher = {
      fingerprintId: 'fp-001',
      firstSeen: '2025-01-01T00:00:00Z',
      lastSeen: '2025-01-07T00:00:00Z',
      vpnChanges: [
        {
          timestamp: '2025-01-01T00:00:00Z',
          vpnDetected: false,
          ipHash: 'ip1',
          city: 'NYC',
          country: 'US',
        },
        {
          timestamp: '2025-01-02T00:00:00Z',
          vpnDetected: true,
          ipHash: 'ip2',
          city: 'Amsterdam',
          country: 'NL',
          provider: 'NordVPN',
          confidence: 0.95,
        },
      ],
      totalChanges: 1,
      riskScore: 70,
      suspiciousActivity: 'VPN enabled within last hour',
    };
    expect(switcher.totalChanges).toBe(1);
    expect(switcher.vpnChanges).toHaveLength(2);
  });

  it('should allow constructing an IPRotationPattern', () => {
    const pattern: IPRotationPattern = {
      fingerprintId: 'fp-001',
      timeWindow: '24h',
      uniqueIPs: 5,
      ipChanges: [],
      avgTimeBetweenChanges: 1200,
      suspicionLevel: 'medium',
    };
    expect(pattern.suspicionLevel).toBe('medium');
  });

  it('should allow constructing an ImpossibleTravelEvent', () => {
    const event: ImpossibleTravelEvent = {
      fingerprintId: 'fp-001',
      fromLocation: { timestamp: '2025-01-01T10:00:00Z', latitude: 40.7128, longitude: -74.006, city: 'NYC', country: 'US' },
      toLocation: { timestamp: '2025-01-01T10:30:00Z', latitude: 35.6762, longitude: 139.6503, city: 'Tokyo', country: 'JP' },
      distanceKm: 10838,
      timeElapsedSeconds: 1800,
      impliedSpeedKmh: 21676,
      maxRealisticSpeedKmh: 900,
      impossibilityFactor: 24.1,
    };
    expect(event.impossibilityFactor).toBeGreaterThan(20);
  });

  it('should allow constructing an AttackCorrelation', () => {
    const timeline: FingerprintTimeline = {
      fingerprintId: 'fp-001',
      firstSeen: '2025-01-01T00:00:00Z',
      lastSeen: '2025-01-07T00:00:00Z',
      totalVisits: 0,
      uniqueIPs: 0,
      uniqueLocations: 0,
      vpnUsage: { vpnVisits: 0, organicVisits: 0, changes: 0 },
      activities: [],
      suspiciousPatterns: [],
      ipHistory: [],
      pageVisits: [],
    };

    const correlation: AttackCorrelation = {
      fingerprintId: 'fp-001',
      attackType: 'ddos',
      detectedAt: '2025-01-07T15:30:00Z',
      evidence: {
        highRequestRate: { requestsPerMinute: 60, threshold: 10, timeWindow: '1m' },
      },
      priorActivity: timeline,
      vpnSwitchedBeforeAttack: true,
    };
    expect(correlation.attackType).toBe('ddos');
  });
});

describe('Security data types', () => {
  it('should allow constructing an AuditLog', () => {
    const log: AuditLog = {
      timestamp: '2025-01-01T00:00:00Z',
      eventType: 'LOGIN_SUCCESS',
      userId: 'user-1',
      severity: 'info',
    };
    expect(log.severity).toBe('info');
  });

  it('should allow constructing SessionStats', () => {
    const stats: SessionStats = {
      activeSessions: 25,
      recentlyExpired: 3,
      averageSessionDuration: 45,
    };
    expect(stats.activeSessions).toBe(25);
  });

  it('should allow constructing SecurityMetrics', () => {
    const metrics: SecurityMetrics = {
      totalUsers: 100,
      activeUsers: 50,
      failedLogins24h: 5,
      successfulLogins24h: 42,
      totpEnabledUsers: 30,
      backupCodesUsed: 2,
      criticalEvents: 1,
      suspiciousActivities: 3,
    };
    expect(metrics.failedLogins24h).toBe(5);
  });

  it('should allow constructing a FingerprintAlert with enriched data', () => {
    const enriched: FingerprintAlertEnriched = {
      fingerprintId: 'fp-001',
      geoCountry: 'US',
      geoCity: 'New York',
      vpnDetected: true,
      riskScore: 85,
      riskTier: 'high',
    };

    const alert: FingerprintAlert = {
      timestamp: '2025-01-01T00:00:00Z',
      sessionId: 'sess-123',
      alertType: 'session_hijacking',
      details: {},
      riskLevel: 'high',
      enriched,
    };
    expect(alert.enriched?.riskScore).toBe(85);
  });

  it('should allow constructing a GeoIPAnomaly', () => {
    const anomaly: GeoIPAnomaly = {
      timestamp: '2025-01-01T00:00:00Z',
      userId: 'user-1',
      sessionId: 'sess-100',
      fromLocation: 'New York, US',
      toLocation: 'Tokyo, JP',
      distance: 10838,
      riskLevel: 'high',
    };
    expect(anomaly.distance).toBe(10838);
  });

  it('should allow VPNChange with optional fields omitted', () => {
    const change: VPNChange = {
      timestamp: '2025-01-01T00:00:00Z',
      vpnDetected: true,
      ipHash: 'ip-hash-1',
    };
    expect(change.city).toBeUndefined();
    expect(change.provider).toBeUndefined();
  });

  it('should allow LocationPoint with optional fields', () => {
    const point: LocationPoint = {
      timestamp: '2025-01-01T00:00:00Z',
      latitude: 0,
      longitude: 0,
    };
    expect(point.city).toBeUndefined();
    expect(point.country).toBeUndefined();
  });

  it('should allow FingerprintActivity with minimal fields', () => {
    const activity: FingerprintActivity = {
      timestamp: '2025-01-01T00:00:00Z',
      ipHash: 'ip-hash',
      vpnDetected: false,
    };
    expect(activity.url).toBeUndefined();
    expect(activity.riskScore).toBeUndefined();
  });
});
