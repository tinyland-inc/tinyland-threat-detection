

















import { getLogger } from './config.js';
import type { LokiBackend, PrometheusBackend } from './config.js';
import type {
  AuditLog,
  SessionStats,
  SecurityMetrics,
  FingerprintAlert,
  GeoIPAnomaly,
} from './types.js';
























export class SecurityDataService {
  private loki: LokiBackend;
  private prometheus: PrometheusBackend;

  constructor(loki: LokiBackend, prometheus: PrometheusBackend) {
    this.loki = loki;
    this.prometheus = prometheus;
    const logger = getLogger();
    logger.info('SecurityDataService initialized');
  }

  






  async getAuditLogs(timeRange: string = '24h', limit: number = 100): Promise<AuditLog[]> {
    const logger = getLogger();
    try {
      const end = Date.now();
      const start = end - this.parseTimeRange(timeRange);

      
      const query = `{component="auth-audit"} | json | event_type=~"LOGIN.*|TOTP.*|INVITATION.*|USER.*|PERMISSION.*|BACKUP.*"`;

      logger.info('Fetching audit logs from Loki', { timeRange, limit });

      const data = await this.loki.query(query, {
        start: `${start}000000`,
        end: `${end}000000`,
        limit
      });

      
      const logs: AuditLog[] = [];
      if (data.data?.result) {
        for (const stream of data.data.result) {
          for (const [timestamp, logLine] of stream.values) {
            try {
              const parsed = JSON.parse(logLine);
              logs.push({
                timestamp: new Date(parseInt(timestamp) / 1000000).toISOString(),
                eventType: parsed.event_type || parsed.eventType || 'UNKNOWN',
                userId: parsed.user_id || parsed.userId,
                userHandle: parsed.user_handle || parsed.userHandle,
                details: parsed.details || parsed,
                severity: this.mapSeverity(parsed.level || 'info'),
                ipAddress: parsed.ip_address || parsed.ipAddress,
                userAgent: parsed.user_agent || parsed.userAgent
              });
            } catch (err) {
              logger.warn('Failed to parse log line', { logLine, error: err });
            }
          }
        }
      }

      logger.info('Fetched audit logs from Loki', { count: logs.length });
      return logs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    } catch (error) {
      logger.error('Failed to fetch audit logs from Loki', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  




  async getFailedLogins24h(): Promise<number> {
    const logger = getLogger();
    try {
      const end = Date.now();

      const query = `count_over_time({component="auth-audit"} | json | event_type=~"LOGIN_FAILURE|TOTP_FAILURE" [24h])`;

      const data = await this.loki.query(query, {
        end: `${end}`,
      });

      let total = 0;
      if (data.data?.result) {
        for (const result of data.data.result) {
          const value = result.values?.[0]?.[1] ?? (result as unknown as { value?: [number, string] }).value?.[1];
          if (value) {
            total += parseInt(value, 10);
          }
        }
      }

      return total;
    } catch (error) {
      logger.error('Failed to get failed logins from Loki', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return 0;
    }
  }

  




  async getSuccessfulLogins24h(): Promise<number> {
    const logger = getLogger();
    try {
      const end = Date.now();

      const query = `count_over_time({component="auth-audit"} | json | event_type="LOGIN_SUCCESS" [24h])`;

      const data = await this.loki.query(query, {
        end: `${end}`,
      });

      let total = 0;
      if (data.data?.result) {
        for (const result of data.data.result) {
          const value = result.values?.[0]?.[1] ?? (result as unknown as { value?: [number, string] }).value?.[1];
          if (value) {
            total += parseInt(value, 10);
          }
        }
      }

      return total;
    } catch (error) {
      logger.error('Failed to get successful logins from Loki', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return 0;
    }
  }

  




  async getSessionStats(): Promise<SessionStats> {
    const logger = getLogger();
    try {
      const queries = {
        active: 'session_active',
        created: 'session_created_total',
        expired: 'session_expired_total'
      };

      const results = await Promise.all(
        Object.entries(queries).map(async ([key, query]) => {
          try {
            const data = await this.prometheus.query(query);
            const value = data.data?.result?.[0]?.value?.[1];
            return { key, value: value ? parseFloat(value) : 0 };
          } catch {
            return { key, value: 0 };
          }
        })
      );

      const metrics = Object.fromEntries(results.map(r => [r.key, r.value]));

      
      let recentlyExpired = 0;
      try {
        const expiredData = await this.prometheus.query('increase(session_expired_total[1h])');
        const expiredValue = expiredData.data?.result?.[0]?.value?.[1];
        recentlyExpired = expiredValue ? Math.floor(parseFloat(expiredValue)) : 0;
      } catch (err) {
        logger.warn('Failed to fetch recently expired sessions', { error: err });
      }

      
      let averageSessionDuration = 0;
      try {
        const [sumData, countData] = await Promise.all([
          this.prometheus.query('session_duration_seconds_sum'),
          this.prometheus.query('session_duration_seconds_count')
        ]);

        const sum = sumData.data?.result?.[0]?.value?.[1];
        const count = countData.data?.result?.[0]?.value?.[1];

        if (sum && count && parseFloat(count) > 0) {
          
          averageSessionDuration = Math.floor((parseFloat(sum) / parseFloat(count)) / 60);
        }
      } catch (err) {
        logger.warn('Failed to calculate average session duration', { error: err });
      }

      return {
        activeSessions: Math.floor(metrics.active || 0),
        recentlyExpired,
        averageSessionDuration
      };
    } catch (error) {
      logger.error('Failed to get session stats from Prometheus', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return {
        activeSessions: 0,
        recentlyExpired: 0,
        averageSessionDuration: 0
      };
    }
  }

  





  async getCriticalEvents(limit: number = 10): Promise<AuditLog[]> {
    const logger = getLogger();
    try {
      const end = Date.now();
      const start = end - (7 * 24 * 60 * 60 * 1000); 

      const query = `{component="auth-audit"} | json | severity="critical" or event_type=~"UNAUTHORIZED.*|SECURITY_VIOLATION|PERMISSION_DENIED"`;

      const data = await this.loki.query(query, {
        start: `${start}000000`,
        end: `${end}000000`,
        limit
      });

      const events: AuditLog[] = [];
      if (data.data?.result) {
        for (const stream of data.data.result) {
          for (const [timestamp, logLine] of stream.values) {
            try {
              const parsed = JSON.parse(logLine);
              events.push({
                timestamp: new Date(parseInt(timestamp) / 1000000).toISOString(),
                eventType: parsed.event_type || 'UNKNOWN',
                userId: parsed.user_id,
                userHandle: parsed.user_handle,
                details: parsed.details || parsed,
                severity: 'critical',
                ipAddress: parsed.ip_address,
                userAgent: parsed.user_agent
              });
            } catch (err) {
              logger.warn('Failed to parse critical event', { logLine: String(logLine) });
            }
          }
        }
      }

      return events.slice(0, limit);
    } catch (error) {
      logger.error('Failed to get critical events from Loki', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  




  async getSecurityMetrics(): Promise<SecurityMetrics> {
    const logger = getLogger();
    try {
      const [failedLogins, successfulLogins] = await Promise.all([
        this.getFailedLogins24h(),
        this.getSuccessfulLogins24h()
      ]);

      return {
        totalUsers: 0,
        activeUsers: 0,
        failedLogins24h: failedLogins,
        successfulLogins24h: successfulLogins,
        totpEnabledUsers: 0,
        backupCodesUsed: 0,
        criticalEvents: 0,
        suspiciousActivities: 0
      };
    } catch (error) {
      logger.error('Failed to get security metrics', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return {
        totalUsers: 0,
        activeUsers: 0,
        failedLogins24h: 0,
        successfulLogins24h: 0,
        totpEnabledUsers: 0,
        backupCodesUsed: 0,
        criticalEvents: 0,
        suspiciousActivities: 0
      };
    }
  }

  






  async getRecentFingerprintAlerts(limit: number = 10): Promise<FingerprintAlert[]> {
    const logger = getLogger();
    try {
      const end = Date.now();
      const start = end - (24 * 60 * 60 * 1000); 

      
      const query = `{job="stonewall-observability"} | json | alert_type="session_hijacking" or event_type="FINGERPRINT_MISMATCH" or event_type="fingerprint_mismatch" or component="fingerprint-enrichment"`;

      logger.info('Fetching fingerprint alerts from Loki', { limit });

      const data = await this.loki.query(query, {
        start: `${start}000000`,
        end: `${end}000000`,
        limit: limit * 2
      });

      const alerts: FingerprintAlert[] = [];
      if (data.data?.result) {
        for (const stream of data.data.result) {
          for (const [timestamp, logLine] of stream.values) {
            try {
              const parsed = JSON.parse(logLine);

              
              const isEnriched = parsed.component === 'fingerprint-enrichment';

              
              const isAlert = parsed.alert_type === 'session_hijacking' ||
                             parsed.event_type === 'FINGERPRINT_MISMATCH' ||
                             parsed.event_type === 'fingerprint_mismatch' ||
                             (isEnriched && parsed.event_type === 'fingerprint_mismatch');

              if (isAlert) {
                alerts.push({
                  timestamp: new Date(parseInt(timestamp) / 1000000).toISOString(),
                  userId: parsed.user_id || parsed.userId,
                  userHandle: parsed.user_handle || parsed.userHandle,
                  sessionId: parsed.session_id || parsed.sessionId || 'unknown',
                  alertType: parsed.alert_type || parsed.event_type || 'session_hijacking',
                  details: parsed.details || parsed,
                  riskLevel: this.mapRiskLevel(parsed.risk_level || parsed.severity),
                  enriched: isEnriched ? {
                    fingerprintId: parsed.fingerprint_id,
                    fingerprintHash: parsed.fingerprint_hash,
                    clientIp: parsed.client_ip,
                    clientIpMasked: parsed.client_ip_masked,
                    geoCountry: parsed.geo_country,
                    geoCountryCode: parsed.geo_country_code,
                    geoCity: parsed.geo_city,
                    geoLatitude: parsed.geo_latitude,
                    geoLongitude: parsed.geo_longitude,
                    geoTimezone: parsed.geo_timezone,
                    vpnDetected: parsed.vpn_detected,
                    vpnProvider: parsed.vpn_provider,
                    vpnConfidence: parsed.vpn_confidence,
                    vpnMethod: parsed.vpn_method,
                    userAgent: parsed.user_agent,
                    deviceType: parsed.device_type,
                    canvasFingerprint: parsed.canvas_fingerprint,
                    webglFingerprint: parsed.webgl_fingerprint,
                    screenResolution: parsed.screen_resolution,
                    browserTimezone: parsed.browser_timezone,
                    browserLanguage: parsed.browser_language,
                    platform: parsed.platform,
                    cookiesEnabled: parsed.cookies_enabled,
                    totpEnabled: parsed.totp_enabled,
                    userActive: parsed.user_active,
                    loginCount: parsed.login_count,
                    failedLoginAttempts: parsed.failed_login_attempts,
                    eventType: parsed.event_type,
                    severity: parsed.severity,
                    riskScore: parsed.risk_score,
                    riskTier: parsed.risk_tier,
                    riskFactors: parsed.risk_factors,
                    riskRecommendation: parsed.risk_recommendation
                  } : undefined
                });
              }
            } catch (err) {
              logger.warn('Failed to parse fingerprint alert', { logLine: String(logLine), error: err });
            }
          }
        }
      }

      logger.info('Fetched fingerprint alerts from Loki', { count: alerts.length });
      return alerts.slice(0, limit);
    } catch (error) {
      logger.error('Failed to fetch fingerprint alerts from Loki', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  





  async getGeoIPAnomalies(limit: number = 10): Promise<GeoIPAnomaly[]> {
    const logger = getLogger();
    try {
      const end = Date.now();
      const start = end - (24 * 60 * 60 * 1000); 

      const query = `{job="stonewall-observability"} | json | alert_type="impossible_travel" or event_type="GEOIP_ANOMALY"`;

      logger.info('Fetching GeoIP anomalies from Loki', { limit });

      const data = await this.loki.query(query, {
        start: `${start}000000`,
        end: `${end}000000`,
        limit
      });

      const anomalies: GeoIPAnomaly[] = [];
      if (data.data?.result) {
        for (const stream of data.data.result) {
          for (const [timestamp, logLine] of stream.values) {
            try {
              const parsed = JSON.parse(logLine);
              anomalies.push({
                timestamp: new Date(parseInt(timestamp) / 1000000).toISOString(),
                userId: parsed.user_id || parsed.userId,
                sessionId: parsed.session_id || parsed.sessionId || 'unknown',
                fromLocation: parsed.from_location || parsed.fromLocation || 'Unknown',
                toLocation: parsed.to_location || parsed.toLocation || 'Unknown',
                distance: parsed.distance || 0,
                riskLevel: this.mapRiskLevel(parsed.risk_level || parsed.severity)
              });
            } catch (err) {
              logger.warn('Failed to parse GeoIP anomaly', { logLine: String(logLine), error: err });
            }
          }
        }
      }

      logger.info('Fetched GeoIP anomalies from Loki', { count: anomalies.length });
      return anomalies.slice(0, limit);
    } catch (error) {
      logger.error('Failed to fetch GeoIP anomalies from Loki', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return [];
    }
  }

  


  private parseTimeRange(timeRange: string): number {
    const match = timeRange.match(/^(\d+)([smhd])$/);
    if (!match) return 24 * 60 * 60 * 1000; 

    const [, value, unit] = match;
    const num = parseInt(value!, 10);

    switch (unit) {
      case 's': return num * 1000;
      case 'm': return num * 60 * 1000;
      case 'h': return num * 60 * 60 * 1000;
      case 'd': return num * 24 * 60 * 60 * 1000;
      default: return 24 * 60 * 60 * 1000;
    }
  }

  


  private mapSeverity(level: string): 'info' | 'warning' | 'critical' {
    const lowercaseLevel = level.toLowerCase();
    if (lowercaseLevel.includes('error') || lowercaseLevel.includes('critical')) {
      return 'critical';
    }
    if (lowercaseLevel.includes('warn')) {
      return 'warning';
    }
    return 'info';
  }

  


  private mapRiskLevel(level?: string): 'low' | 'medium' | 'high' {
    if (!level) return 'medium';
    const lowercaseLevel = level.toLowerCase();
    if (lowercaseLevel.includes('high') || lowercaseLevel.includes('critical')) {
      return 'high';
    }
    if (lowercaseLevel.includes('medium') || lowercaseLevel.includes('warn')) {
      return 'medium';
    }
    return 'low';
  }
}
