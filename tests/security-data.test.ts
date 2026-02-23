


import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SecurityDataService } from '../src/SecurityDataService.js';
import { resetThreatDetectionConfig, configureThreatDetection } from '../src/config.js';
import type { LokiBackend, PrometheusBackend } from '../src/config.js';
import type { LokiQueryResult, PrometheusQueryResult } from '../src/types.js';





function createEmptyLokiResult(): LokiQueryResult {
  return {
    status: 'success',
    data: {
      resultType: 'streams',
      result: [],
    },
  };
}

function createEmptyPrometheusResult(): PrometheusQueryResult {
  return {
    status: 'success',
    data: {
      resultType: 'vector',
      result: [],
    },
  };
}

function createLokiResult(logEntries: Array<{ timestamp: number; data: Record<string, unknown> }>): LokiQueryResult {
  return {
    status: 'success',
    data: {
      resultType: 'streams',
      result: [
        {
          stream: { component: 'auth-audit' },
          values: logEntries.map(entry => [
            String(entry.timestamp * 1000000), 
            JSON.stringify(entry.data),
          ]),
        },
      ],
    },
  };
}

function createPrometheusResult(value: number): PrometheusQueryResult {
  return {
    status: 'success',
    data: {
      resultType: 'vector',
      result: [
        {
          metric: {},
          value: [Date.now() / 1000, String(value)],
        },
      ],
    },
  };
}

function createMockLoki(defaultResult?: LokiQueryResult): LokiBackend {
  return {
    query: vi.fn().mockResolvedValue(defaultResult ?? createEmptyLokiResult()),
  };
}

function createMockPrometheus(defaultResult?: PrometheusQueryResult): PrometheusBackend {
  return {
    query: vi.fn().mockResolvedValue(defaultResult ?? createEmptyPrometheusResult()),
    queryRange: vi.fn().mockResolvedValue(defaultResult ?? createEmptyPrometheusResult()),
  };
}





describe('SecurityDataService', () => {
  beforeEach(() => {
    resetThreatDetectionConfig();
  });

  
  
  

  describe('getAuditLogs', () => {
    it('should return empty array when no logs exist', async () => {
      const loki = createMockLoki();
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getAuditLogs('24h');
      expect(result).toEqual([]);
      expect(loki.query).toHaveBeenCalled();
    });

    it('should parse audit log entries from Loki', async () => {
      const now = Date.now();
      const lokiResult = createLokiResult([
        {
          timestamp: now,
          data: {
            event_type: 'LOGIN_SUCCESS',
            user_id: 'user-1',
            user_handle: 'testuser',
            level: 'info',
            ip_address: '192.168.1.1',
            user_agent: 'Mozilla/5.0',
          },
        },
      ]);

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getAuditLogs('24h');
      expect(result).toHaveLength(1);
      expect(result[0].eventType).toBe('LOGIN_SUCCESS');
      expect(result[0].userId).toBe('user-1');
      expect(result[0].userHandle).toBe('testuser');
      expect(result[0].severity).toBe('info');
      expect(result[0].ipAddress).toBe('192.168.1.1');
    });

    it('should sort logs by timestamp descending', async () => {
      const now = Date.now();
      const lokiResult = createLokiResult([
        { timestamp: now - 10000, data: { event_type: 'FIRST', level: 'info' } },
        { timestamp: now, data: { event_type: 'SECOND', level: 'info' } },
        { timestamp: now - 5000, data: { event_type: 'MIDDLE', level: 'info' } },
      ]);

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getAuditLogs('24h');
      expect(result).toHaveLength(3);
      expect(result[0].eventType).toBe('SECOND');
      expect(result[2].eventType).toBe('FIRST');
    });

    it('should map error level to critical severity', async () => {
      const lokiResult = createLokiResult([
        { timestamp: Date.now(), data: { event_type: 'LOGIN_FAILURE', level: 'error' } },
      ]);

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getAuditLogs('24h');
      expect(result[0].severity).toBe('critical');
    });

    it('should map warn level to warning severity', async () => {
      const lokiResult = createLokiResult([
        { timestamp: Date.now(), data: { event_type: 'SUSPICIOUS', level: 'warn' } },
      ]);

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getAuditLogs('24h');
      expect(result[0].severity).toBe('warning');
    });

    it('should return empty array on Loki query failure', async () => {
      const loki: LokiBackend = {
        query: vi.fn().mockRejectedValue(new Error('Connection refused')),
      };
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getAuditLogs('24h');
      expect(result).toEqual([]);
    });

    it('should handle malformed log lines gracefully', async () => {
      const lokiResult: LokiQueryResult = {
        status: 'success',
        data: {
          resultType: 'streams',
          result: [
            {
              stream: { component: 'auth-audit' },
              values: [
                [String(Date.now() * 1000000), 'not-valid-json'],
                [String(Date.now() * 1000000), JSON.stringify({ event_type: 'VALID', level: 'info' })],
              ],
            },
          ],
        },
      };

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getAuditLogs('24h');
      
      expect(result).toHaveLength(1);
      expect(result[0].eventType).toBe('VALID');
    });
  });

  
  
  

  describe('getFailedLogins24h', () => {
    it('should return 0 when no failed logins', async () => {
      const loki = createMockLoki();
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getFailedLogins24h();
      expect(result).toBe(0);
    });

    it('should return count from Loki result', async () => {
      const lokiResult: LokiQueryResult = {
        status: 'success',
        data: {
          resultType: 'vector',
          result: [
            {
              stream: {},
              values: [
                [String(Date.now()), '15'],
              ],
            },
          ],
        },
      };

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getFailedLogins24h();
      expect(result).toBe(15);
    });

    it('should return 0 on error', async () => {
      const loki: LokiBackend = {
        query: vi.fn().mockRejectedValue(new Error('Loki unavailable')),
      };
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getFailedLogins24h();
      expect(result).toBe(0);
    });
  });

  
  
  

  describe('getSuccessfulLogins24h', () => {
    it('should return 0 when no successful logins', async () => {
      const loki = createMockLoki();
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getSuccessfulLogins24h();
      expect(result).toBe(0);
    });

    it('should return count from Loki result', async () => {
      const lokiResult: LokiQueryResult = {
        status: 'success',
        data: {
          resultType: 'vector',
          result: [
            {
              stream: {},
              values: [[String(Date.now()), '42']],
            },
          ],
        },
      };

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getSuccessfulLogins24h();
      expect(result).toBe(42);
    });
  });

  
  
  

  describe('getSessionStats', () => {
    it('should return zero stats when Prometheus has no data', async () => {
      const service = new SecurityDataService(createMockLoki(), createMockPrometheus());

      const result = await service.getSessionStats();
      expect(result.activeSessions).toBe(0);
      expect(result.recentlyExpired).toBe(0);
      expect(result.averageSessionDuration).toBe(0);
    });

    it('should parse active sessions from Prometheus', async () => {
      const prometheus: PrometheusBackend = {
        query: vi.fn().mockImplementation((promql: string) => {
          if (promql === 'session_active') {
            return Promise.resolve(createPrometheusResult(25));
          }
          return Promise.resolve(createEmptyPrometheusResult());
        }),
        queryRange: vi.fn().mockResolvedValue(createEmptyPrometheusResult()),
      };
      const service = new SecurityDataService(createMockLoki(), prometheus);

      const result = await service.getSessionStats();
      expect(result.activeSessions).toBe(25);
    });

    it('should calculate average session duration', async () => {
      const prometheus: PrometheusBackend = {
        query: vi.fn().mockImplementation((promql: string) => {
          if (promql === 'session_duration_seconds_sum') {
            return Promise.resolve(createPrometheusResult(36000)); 
          }
          if (promql === 'session_duration_seconds_count') {
            return Promise.resolve(createPrometheusResult(10)); 
          }
          return Promise.resolve(createEmptyPrometheusResult());
        }),
        queryRange: vi.fn().mockResolvedValue(createEmptyPrometheusResult()),
      };
      const service = new SecurityDataService(createMockLoki(), prometheus);

      const result = await service.getSessionStats();
      
      expect(result.averageSessionDuration).toBe(60);
    });

    it('should handle Prometheus errors gracefully', async () => {
      const prometheus: PrometheusBackend = {
        query: vi.fn().mockRejectedValue(new Error('Prometheus down')),
        queryRange: vi.fn().mockRejectedValue(new Error('Prometheus down')),
      };
      const service = new SecurityDataService(createMockLoki(), prometheus);

      const result = await service.getSessionStats();
      expect(result.activeSessions).toBe(0);
      expect(result.recentlyExpired).toBe(0);
      expect(result.averageSessionDuration).toBe(0);
    });
  });

  
  
  

  describe('getCriticalEvents', () => {
    it('should return empty array when no critical events', async () => {
      const service = new SecurityDataService(createMockLoki(), createMockPrometheus());

      const result = await service.getCriticalEvents();
      expect(result).toEqual([]);
    });

    it('should parse critical events from Loki', async () => {
      const lokiResult = createLokiResult([
        {
          timestamp: Date.now(),
          data: {
            event_type: 'SECURITY_VIOLATION',
            user_id: 'attacker-1',
            user_handle: 'badactor',
            severity: 'critical',
            ip_address: '10.0.0.1',
            user_agent: 'curl/7.81.0',
          },
        },
      ]);

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getCriticalEvents(10);
      expect(result).toHaveLength(1);
      expect(result[0].eventType).toBe('SECURITY_VIOLATION');
      expect(result[0].severity).toBe('critical');
    });

    it('should respect limit parameter', async () => {
      const lokiResult = createLokiResult(
        Array.from({ length: 5 }, (_, i) => ({
          timestamp: Date.now() - i * 1000,
          data: { event_type: `EVENT_${i}`, severity: 'critical' },
        }))
      );

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getCriticalEvents(3);
      expect(result).toHaveLength(3);
    });
  });

  
  
  

  describe('getSecurityMetrics', () => {
    it('should aggregate metrics from multiple sources', async () => {
      const lokiResult: LokiQueryResult = {
        status: 'success',
        data: {
          resultType: 'vector',
          result: [
            {
              stream: {},
              values: [[String(Date.now()), '5']],
            },
          ],
        },
      };
      
      const loki: LokiBackend = {
        query: vi.fn()
          .mockResolvedValueOnce(lokiResult) 
          .mockResolvedValueOnce(lokiResult), 
      };
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getSecurityMetrics();
      expect(result.failedLogins24h).toBe(5);
      expect(result.successfulLogins24h).toBe(5);
      expect(result.totalUsers).toBe(0); 
    });

    it('should return zeroed metrics on error', async () => {
      const loki: LokiBackend = {
        query: vi.fn().mockRejectedValue(new Error('Failed')),
      };
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getSecurityMetrics();
      expect(result.failedLogins24h).toBe(0);
      expect(result.successfulLogins24h).toBe(0);
      expect(result.criticalEvents).toBe(0);
    });
  });

  
  
  

  describe('getRecentFingerprintAlerts', () => {
    it('should return empty array when no alerts exist', async () => {
      const service = new SecurityDataService(createMockLoki(), createMockPrometheus());

      const result = await service.getRecentFingerprintAlerts();
      expect(result).toEqual([]);
    });

    it('should parse session hijacking alerts', async () => {
      const lokiResult = createLokiResult([
        {
          timestamp: Date.now(),
          data: {
            alert_type: 'session_hijacking',
            user_id: 'user-1',
            session_id: 'sess-123',
            risk_level: 'high',
            details: { reason: 'fingerprint mismatch' },
          },
        },
      ]);

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getRecentFingerprintAlerts();
      expect(result).toHaveLength(1);
      expect(result[0].alertType).toBe('session_hijacking');
      expect(result[0].riskLevel).toBe('high');
      expect(result[0].sessionId).toBe('sess-123');
    });

    it('should parse enriched fingerprint data', async () => {
      const lokiResult = createLokiResult([
        {
          timestamp: Date.now(),
          data: {
            component: 'fingerprint-enrichment',
            event_type: 'fingerprint_mismatch',
            session_id: 'sess-456',
            fingerprint_id: 'fp-001',
            geo_country: 'US',
            geo_city: 'New York',
            vpn_detected: true,
            vpn_provider: 'NordVPN',
            risk_score: 85,
            risk_tier: 'high',
          },
        },
      ]);

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getRecentFingerprintAlerts();
      expect(result).toHaveLength(1);
      expect(result[0].enriched).toBeDefined();
      expect(result[0].enriched?.fingerprintId).toBe('fp-001');
      expect(result[0].enriched?.geoCountry).toBe('US');
      expect(result[0].enriched?.vpnDetected).toBe(true);
      expect(result[0].enriched?.vpnProvider).toBe('NordVPN');
      expect(result[0].enriched?.riskScore).toBe(85);
    });

    it('should not include enriched data for non-enrichment logs', async () => {
      const lokiResult = createLokiResult([
        {
          timestamp: Date.now(),
          data: {
            alert_type: 'session_hijacking',
            session_id: 'sess-789',
          },
        },
      ]);

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getRecentFingerprintAlerts();
      expect(result).toHaveLength(1);
      expect(result[0].enriched).toBeUndefined();
    });

    it('should respect limit parameter', async () => {
      const lokiResult = createLokiResult(
        Array.from({ length: 10 }, (_, i) => ({
          timestamp: Date.now() - i * 1000,
          data: {
            alert_type: 'session_hijacking',
            session_id: `sess-${i}`,
          },
        }))
      );

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getRecentFingerprintAlerts(5);
      expect(result).toHaveLength(5);
    });

    it('should return empty array on Loki error', async () => {
      const loki: LokiBackend = {
        query: vi.fn().mockRejectedValue(new Error('Loki crashed')),
      };
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getRecentFingerprintAlerts();
      expect(result).toEqual([]);
    });
  });

  
  
  

  describe('getGeoIPAnomalies', () => {
    it('should return empty array when no anomalies exist', async () => {
      const service = new SecurityDataService(createMockLoki(), createMockPrometheus());

      const result = await service.getGeoIPAnomalies();
      expect(result).toEqual([]);
    });

    it('should parse impossible travel alerts', async () => {
      const lokiResult = createLokiResult([
        {
          timestamp: Date.now(),
          data: {
            alert_type: 'impossible_travel',
            user_id: 'user-1',
            session_id: 'sess-100',
            from_location: 'New York, US',
            to_location: 'Tokyo, JP',
            distance: 10838,
            risk_level: 'high',
          },
        },
      ]);

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getGeoIPAnomalies();
      expect(result).toHaveLength(1);
      expect(result[0].fromLocation).toBe('New York, US');
      expect(result[0].toLocation).toBe('Tokyo, JP');
      expect(result[0].distance).toBe(10838);
      expect(result[0].riskLevel).toBe('high');
    });

    it('should map risk levels correctly', async () => {
      const lokiResult = createLokiResult([
        {
          timestamp: Date.now(),
          data: { event_type: 'GEOIP_ANOMALY', session_id: 's1', risk_level: 'critical' },
        },
        {
          timestamp: Date.now() - 1000,
          data: { event_type: 'GEOIP_ANOMALY', session_id: 's2', risk_level: 'medium' },
        },
        {
          timestamp: Date.now() - 2000,
          data: { event_type: 'GEOIP_ANOMALY', session_id: 's3', risk_level: 'low' },
        },
      ]);

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getGeoIPAnomalies();
      expect(result).toHaveLength(3);
      expect(result[0].riskLevel).toBe('high'); 
      expect(result[1].riskLevel).toBe('medium');
      expect(result[2].riskLevel).toBe('low');
    });

    it('should return empty array on Loki error', async () => {
      const loki: LokiBackend = {
        query: vi.fn().mockRejectedValue(new Error('Network error')),
      };
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getGeoIPAnomalies();
      expect(result).toEqual([]);
    });

    it('should default to medium risk when level is missing', async () => {
      const lokiResult = createLokiResult([
        {
          timestamp: Date.now(),
          data: { event_type: 'GEOIP_ANOMALY', session_id: 's1' },
        },
      ]);

      const loki = createMockLoki(lokiResult);
      const service = new SecurityDataService(loki, createMockPrometheus());

      const result = await service.getGeoIPAnomalies();
      expect(result[0].riskLevel).toBe('medium');
    });
  });
});
