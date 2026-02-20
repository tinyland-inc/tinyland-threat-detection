/**
 * Security Data Service
 *
 * Fetches security data from Loki and Prometheus backends.
 * Replaces direct HTTP calls with injected backend interfaces.
 *
 * **Key Capabilities**:
 * - Audit log queries (Loki)
 * - Failed/successful login counts (Loki)
 * - Session statistics (Prometheus)
 * - Critical event retrieval (Loki)
 * - Security metrics aggregation
 * - Fingerprint alert retrieval with enrichment data
 * - GeoIP anomaly detection
 *
 * @module SecurityDataService
 */

import { getLogger } from './config.js';
import type { LokiBackend, PrometheusBackend } from './config.js';
import type {
  AuditLog,
  SessionStats,
  SecurityMetrics,
  FingerprintAlert,
  GeoIPAnomaly,
} from './types.js';

// ============================================================================
// Service Implementation
// ============================================================================

/**
 * Service for fetching security data from Loki and Prometheus.
 *
 * Uses injected backend interfaces instead of direct HTTP calls,
 * allowing this package to work with any observability stack.
 *
 * @example
 * ```typescript
 * import { SecurityDataService } from '@tummycrypt/tinyland-threat-detection';
 *
 * const service = new SecurityDataService(lokiBackend, prometheusBackend);
 *
 * // Fetch audit logs
 * const logs = await service.getAuditLogs('24h', 100);
 *
 * // Get security metrics
 * const metrics = await service.getSecurityMetrics();
 * ```
 */
export class SecurityDataService {
  private loki: LokiBackend;
  private prometheus: PrometheusBackend;

  constructor(loki: LokiBackend, prometheus: PrometheusBackend) {
    this.loki = loki;
    this.prometheus = prometheus;
    const logger = getLogger();
    logger.info('SecurityDataService initialized');
  }

  /**
   * Query Loki for audit logs
   *
   * @param timeRange - How far back to search (e.g., '24h', '7d')
   * @param limit - Maximum number of logs to return (default: 100)
   * @returns Array of AuditLog entries sorted by timestamp descending
   */
  async getAuditLogs(timeRange: string = '24h', limit: number = 100): Promise<AuditLog[]> {
    const logger = getLogger();
    try {
      const end = Date.now();
      const start = end - this.parseTimeRange(timeRange);

      // LogQL query for auth events
      const query = `{component="auth-audit"} | json | event_type=~"LOGIN.*|TOTP.*|INVITATION.*|USER.*|PERMISSION.*|BACKUP.*"`;

      logger.info('Fetching audit logs from Loki', { timeRange, limit });

      const data = await this.loki.query(query, {
        start: `${start}000000`,
        end: `${end}000000`,
        limit
      });

      // Parse Loki response into AuditLog format
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

  /**
   * Get failed login count from Loki
   *
   * @returns Number of failed login attempts in the last 24 hours
   */
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

  /**
   * Get successful login count from Loki
   *
   * @returns Number of successful logins in the last 24 hours
   */
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

  /**
   * Get session statistics from Prometheus
   *
   * @returns Session statistics including active sessions, recently expired, and average duration
   */
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

      // Calculate recently expired sessions (last hour)
      let recentlyExpired = 0;
      try {
        const expiredData = await this.prometheus.query('increase(session_expired_total[1h])');
        const expiredValue = expiredData.data?.result?.[0]?.value?.[1];
        recentlyExpired = expiredValue ? Math.floor(parseFloat(expiredValue)) : 0;
      } catch (err) {
        logger.warn('Failed to fetch recently expired sessions', { error: err });
      }

      // Calculate average session duration from histogram
      let averageSessionDuration = 0;
      try {
        const [sumData, countData] = await Promise.all([
          this.prometheus.query('session_duration_seconds_sum'),
          this.prometheus.query('session_duration_seconds_count')
        ]);

        const sum = sumData.data?.result?.[0]?.value?.[1];
        const count = countData.data?.result?.[0]?.value?.[1];

        if (sum && count && parseFloat(count) > 0) {
          // Convert to minutes
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

  /**
   * Get critical events from Loki
   *
   * @param limit - Maximum number of events to return (default: 10)
   * @returns Array of critical AuditLog entries
   */
  async getCriticalEvents(limit: number = 10): Promise<AuditLog[]> {
    const logger = getLogger();
    try {
      const end = Date.now();
      const start = end - (7 * 24 * 60 * 60 * 1000); // Last 7 days

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

  /**
   * Get security metrics summary from Prometheus and Loki
   *
   * @returns Aggregated SecurityMetrics object
   */
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

  /**
   * Get recent fingerprint alerts (session hijacking detection)
   * Includes enriched fingerprint data (IP, geo, VPN, browser, user stats)
   *
   * @param limit - Maximum number of alerts to return (default: 10)
   * @returns Array of FingerprintAlert entries
   */
  async getRecentFingerprintAlerts(limit: number = 10): Promise<FingerprintAlert[]> {
    const logger = getLogger();
    try {
      const end = Date.now();
      const start = end - (24 * 60 * 60 * 1000); // Last 24 hours

      // Query for session hijacking alerts AND enriched fingerprint logs
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

              // Check if this is an enriched fingerprint log
              const isEnriched = parsed.component === 'fingerprint-enrichment';

              // Only process logs with session hijacking/mismatch events
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

  /**
   * Get GeoIP anomalies (impossible travel detection from Loki)
   *
   * @param limit - Maximum number of anomalies to return (default: 10)
   * @returns Array of GeoIPAnomaly entries
   */
  async getGeoIPAnomalies(limit: number = 10): Promise<GeoIPAnomaly[]> {
    const logger = getLogger();
    try {
      const end = Date.now();
      const start = end - (24 * 60 * 60 * 1000); // Last 24 hours

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

  /**
   * Parse time range string to milliseconds
   */
  private parseTimeRange(timeRange: string): number {
    const match = timeRange.match(/^(\d+)([smhd])$/);
    if (!match) return 24 * 60 * 60 * 1000; // Default to 24h

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

  /**
   * Map log level to severity
   */
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

  /**
   * Map risk level string to standard values
   */
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
