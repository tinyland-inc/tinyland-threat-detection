/**
 * Tests for ThreatCorrelationService
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ThreatCorrelationService } from '../src/ThreatCorrelationService.js';
import { resetThreatDetectionConfig, configureThreatDetection } from '../src/config.js';
import type { FingerprintQueryBackend } from '../src/config.js';
import type { FingerprintRecord } from '../src/types.js';

// ============================================================================
// Test Helpers
// ============================================================================

function createRecord(overrides: Partial<FingerprintRecord> = {}): FingerprintRecord {
  return {
    traceID: 'trace-001',
    spanID: 'span-001',
    timestamp: new Date().toISOString(),
    duration: 1000000,
    fingerprintId: 'fp-001',
    eventType: 'fingerprint.enrichment',
    ...overrides,
  };
}

function createMockBackend(records: FingerprintRecord[] = []): FingerprintQueryBackend {
  return {
    queryFingerprints: vi.fn().mockResolvedValue(records),
  };
}

function hoursAgo(hours: number): string {
  return new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
}

function minutesAgo(minutes: number): string {
  return new Date(Date.now() - minutes * 60 * 1000).toISOString();
}

// ============================================================================
// VPN Switching Detection Tests
// ============================================================================

describe('ThreatCorrelationService', () => {
  beforeEach(() => {
    resetThreatDetectionConfig();
  });

  describe('detectVPNSwitchers', () => {
    it('should return empty array when no records exist', async () => {
      const backend = createMockBackend([]);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectVPNSwitchers('7d');
      expect(result).toEqual([]);
    });

    it('should not flag fingerprints with no VPN changes', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(5), vpnDetected: false, ipHash: 'ip1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(4), vpnDetected: false, ipHash: 'ip1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(3), vpnDetected: false, ipHash: 'ip1' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectVPNSwitchers('7d');
      expect(result).toHaveLength(0);
    });

    it('should detect single VPN status change', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(5), vpnDetected: false, ipHash: 'ip1', geoCity: 'NYC', geoCountry: 'US' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(3), vpnDetected: true, ipHash: 'ip2', geoCity: 'Amsterdam', geoCountry: 'NL' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectVPNSwitchers('7d', 1);
      expect(result).toHaveLength(1);
      expect(result[0].fingerprintId).toBe('fp-1');
      expect(result[0].totalChanges).toBe(1);
    });

    it('should detect multiple VPN status changes', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(10), vpnDetected: false, ipHash: 'ip1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(8), vpnDetected: true, ipHash: 'ip2' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(6), vpnDetected: false, ipHash: 'ip3' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(4), vpnDetected: true, ipHash: 'ip4' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectVPNSwitchers('7d', 1);
      expect(result).toHaveLength(1);
      expect(result[0].totalChanges).toBe(3);
    });

    it('should filter by minimum changes threshold', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(5), vpnDetected: false, ipHash: 'ip1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(3), vpnDetected: true, ipHash: 'ip2' }),
        createRecord({ fingerprintId: 'fp-2', timestamp: hoursAgo(5), vpnDetected: false, ipHash: 'ip3' }),
        createRecord({ fingerprintId: 'fp-2', timestamp: hoursAgo(4), vpnDetected: true, ipHash: 'ip4' }),
        createRecord({ fingerprintId: 'fp-2', timestamp: hoursAgo(3), vpnDetected: false, ipHash: 'ip5' }),
        createRecord({ fingerprintId: 'fp-2', timestamp: hoursAgo(2), vpnDetected: true, ipHash: 'ip6' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      // minChanges=3 should only match fp-2 (3 changes)
      const result = await service.detectVPNSwitchers('7d', 3);
      expect(result).toHaveLength(1);
      expect(result[0].fingerprintId).toBe('fp-2');
    });

    it('should calculate risk score correctly - base score', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(48), vpnDetected: false, ipHash: 'ip1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(46), vpnDetected: true, ipHash: 'ip2' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectVPNSwitchers('7d', 1);
      expect(result).toHaveLength(1);
      // Base: 30 + 1 change * 10 = 40
      // VPN last change was 46h ago, not within 24h, so no +30 bonus
      expect(result[0].riskScore).toBe(40);
    });

    it('should add bonus risk score for recent VPN enable', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(5), vpnDetected: false, ipHash: 'ip1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: minutesAgo(30), vpnDetected: true, ipHash: 'ip2' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectVPNSwitchers('7d', 1);
      expect(result).toHaveLength(1);
      // Base: 30 + 1*10 = 40, + 30 (VPN in last 24h) = 70
      expect(result[0].riskScore).toBe(70);
    });

    it('should cap risk score at 100', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(6), vpnDetected: false, ipHash: 'ip1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(5), vpnDetected: true, ipHash: 'ip2' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(4), vpnDetected: false, ipHash: 'ip3' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(3), vpnDetected: true, ipHash: 'ip4' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(2), vpnDetected: false, ipHash: 'ip5' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: minutesAgo(5), vpnDetected: true, ipHash: 'ip6' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectVPNSwitchers('7d', 1);
      expect(result[0].riskScore).toBeLessThanOrEqual(100);
    });

    it('should sort results by risk score descending', async () => {
      const records = [
        // fp-1: 1 change, no recent VPN = score 40
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(48), vpnDetected: false, ipHash: 'ip1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(46), vpnDetected: true, ipHash: 'ip2' }),
        // fp-2: 1 change, recent VPN = score 70
        createRecord({ fingerprintId: 'fp-2', timestamp: hoursAgo(5), vpnDetected: false, ipHash: 'ip3' }),
        createRecord({ fingerprintId: 'fp-2', timestamp: minutesAgo(30), vpnDetected: true, ipHash: 'ip4' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectVPNSwitchers('7d', 1);
      expect(result).toHaveLength(2);
      expect(result[0].fingerprintId).toBe('fp-2'); // Higher risk
      expect(result[1].fingerprintId).toBe('fp-1'); // Lower risk
    });

    it('should detect suspicious activity description for recent VPN', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(5), vpnDetected: false, ipHash: 'ip1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: minutesAgo(20), vpnDetected: true, ipHash: 'ip2' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectVPNSwitchers('7d', 1);
      expect(result[0].suspiciousActivity).toBe('VPN enabled within last hour');
    });

    it('should describe frequent switching for 3+ changes', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(48), vpnDetected: false, ipHash: 'ip1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(47), vpnDetected: true, ipHash: 'ip2' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(46), vpnDetected: false, ipHash: 'ip3' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(45), vpnDetected: true, ipHash: 'ip4' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectVPNSwitchers('7d', 1);
      expect(result[0].suspiciousActivity).toContain('Frequent VPN switching');
    });

    it('should skip records without fingerprintId', async () => {
      const records = [
        createRecord({ fingerprintId: '', timestamp: hoursAgo(5), vpnDetected: false }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(5), vpnDetected: false, ipHash: 'ip1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(3), vpnDetected: true, ipHash: 'ip2' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectVPNSwitchers('7d', 1);
      expect(result).toHaveLength(1);
      expect(result[0].fingerprintId).toBe('fp-1');
    });

    it('should propagate backend errors', async () => {
      const backend: FingerprintQueryBackend = {
        queryFingerprints: vi.fn().mockRejectedValue(new Error('Backend unavailable')),
      };
      const service = new ThreatCorrelationService(backend);

      await expect(service.detectVPNSwitchers('7d')).rejects.toThrow('Backend unavailable');
    });

    it('should handle multiple fingerprints independently', async () => {
      const records = [
        // fp-1: switches VPN
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(5), vpnDetected: false, ipHash: 'ip1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(3), vpnDetected: true, ipHash: 'ip2' }),
        // fp-2: no switches
        createRecord({ fingerprintId: 'fp-2', timestamp: hoursAgo(5), vpnDetected: false, ipHash: 'ip3' }),
        createRecord({ fingerprintId: 'fp-2', timestamp: hoursAgo(3), vpnDetected: false, ipHash: 'ip4' }),
        // fp-3: switches VPN
        createRecord({ fingerprintId: 'fp-3', timestamp: hoursAgo(5), vpnDetected: true, ipHash: 'ip5' }),
        createRecord({ fingerprintId: 'fp-3', timestamp: hoursAgo(3), vpnDetected: false, ipHash: 'ip6' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectVPNSwitchers('7d', 1);
      expect(result).toHaveLength(2);
      const ids = result.map(r => r.fingerprintId);
      expect(ids).toContain('fp-1');
      expect(ids).toContain('fp-3');
      expect(ids).not.toContain('fp-2');
    });
  });

  // ============================================================================
  // IP Rotation Detection Tests
  // ============================================================================

  describe('detectIPRotation', () => {
    it('should return empty array when no records exist', async () => {
      const backend = createMockBackend([]);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectIPRotation('7d');
      expect(result).toEqual([]);
    });

    it('should not flag fingerprints with fewer than minUniqueIPs', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(5), ipHash: 'ip1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(3), ipHash: 'ip2' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectIPRotation('7d', 3);
      expect(result).toHaveLength(0);
    });

    it('should detect fingerprints with 3+ unique IPs', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(5), ipHash: 'ip1', fingerprintHash: 'hash1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(4), ipHash: 'ip2', fingerprintHash: 'hash2' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(3), ipHash: 'ip3', fingerprintHash: 'hash3' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectIPRotation('7d', 3);
      expect(result).toHaveLength(1);
      expect(result[0].fingerprintId).toBe('fp-1');
      expect(result[0].uniqueIPs).toBe(3);
    });

    it('should classify low suspicion for 3-4 IPs over long window', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(100), ipHash: 'ip1', fingerprintHash: 'h1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(80), ipHash: 'ip2', fingerprintHash: 'h2' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(60), ipHash: 'ip3', fingerprintHash: 'h3' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectIPRotation('7d', 3);
      expect(result).toHaveLength(1);
      // Over 7d window (168h > 24h), 3 IPs = low
      expect(result[0].suspicionLevel).toBe('low');
    });

    it('should classify medium suspicion for 3+ IPs in 24h', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(10), ipHash: 'ip1', fingerprintHash: 'h1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(8), ipHash: 'ip2', fingerprintHash: 'h2' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(5), ipHash: 'ip3', fingerprintHash: 'h3' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectIPRotation('24h', 3);
      expect(result).toHaveLength(1);
      expect(result[0].suspicionLevel).toBe('medium');
    });

    it('should classify medium suspicion for 5-7 IPs', async () => {
      const records = Array.from({ length: 5 }, (_, i) =>
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: hoursAgo(10 - i),
          ipHash: `ip${i}`,
          fingerprintHash: `h${i}`,
        })
      );
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectIPRotation('7d', 3);
      expect(result).toHaveLength(1);
      expect(result[0].suspicionLevel).toBe('medium');
    });

    it('should classify high suspicion for 8-14 IPs', async () => {
      const records = Array.from({ length: 10 }, (_, i) =>
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: hoursAgo(20 - i),
          ipHash: `ip${i}`,
          fingerprintHash: `h${i}`,
        })
      );
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectIPRotation('7d', 3);
      expect(result).toHaveLength(1);
      expect(result[0].suspicionLevel).toBe('high');
    });

    it('should classify critical suspicion for 15+ IPs', async () => {
      const records = Array.from({ length: 16 }, (_, i) =>
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: hoursAgo(30 - i),
          ipHash: `ip${i}`,
          fingerprintHash: `h${i}`,
        })
      );
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectIPRotation('7d', 3);
      expect(result).toHaveLength(1);
      expect(result[0].suspicionLevel).toBe('critical');
    });

    it('should calculate average time between IP changes', async () => {
      const now = Date.now();
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: new Date(now - 3600000).toISOString(), ipHash: 'ip1', fingerprintHash: 'h1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: new Date(now - 2400000).toISOString(), ipHash: 'ip2', fingerprintHash: 'h2' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: new Date(now - 1200000).toISOString(), ipHash: 'ip3', fingerprintHash: 'h3' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectIPRotation('24h', 3);
      expect(result).toHaveLength(1);
      // 3 changes with hash changes, avg ~1200s between = 20 minutes
      expect(result[0].avgTimeBetweenChanges).toBeGreaterThan(0);
    });

    it('should sort by suspicion level then by IP count', async () => {
      const makeRecords = (fpId: string, count: number) =>
        Array.from({ length: count }, (_, i) =>
          createRecord({
            fingerprintId: fpId,
            timestamp: hoursAgo(20 - i),
            ipHash: `${fpId}-ip${i}`,
            fingerprintHash: `${fpId}-h${i}`,
          })
        );

      const records = [
        ...makeRecords('fp-low', 4),    // low/medium
        ...makeRecords('fp-high', 10),   // high
        ...makeRecords('fp-crit', 16),   // critical
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectIPRotation('7d', 3);
      expect(result.length).toBeGreaterThanOrEqual(3);
      expect(result[0].suspicionLevel).toBe('critical');
      expect(result[1].suspicionLevel).toBe('high');
    });

    it('should propagate backend errors', async () => {
      const backend: FingerprintQueryBackend = {
        queryFingerprints: vi.fn().mockRejectedValue(new Error('Tempo down')),
      };
      const service = new ThreatCorrelationService(backend);

      await expect(service.detectIPRotation('7d')).rejects.toThrow('Tempo down');
    });
  });

  // ============================================================================
  // Impossible Travel Detection Tests
  // ============================================================================

  describe('detectImpossibleTravel', () => {
    it('should return empty array when no records exist', async () => {
      const backend = createMockBackend([]);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectImpossibleTravel();
      expect(result).toEqual([]);
    });

    it('should not flag records without geo coordinates', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(2), ipHash: 'ip1' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(1), ipHash: 'ip2' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectImpossibleTravel();
      expect(result).toHaveLength(0);
    });

    it('should detect impossible travel between NYC and Tokyo in 30 minutes', async () => {
      const now = Date.now();
      const records = [
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: new Date(now - 30 * 60 * 1000).toISOString(), // 30 min ago
          geoLatitude: 40.7128,
          geoLongitude: -74.006,
          geoCity: 'New York',
          geoCountry: 'US',
        }),
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: new Date(now).toISOString(), // now
          geoLatitude: 35.6762,
          geoLongitude: 139.6503,
          geoCity: 'Tokyo',
          geoCountry: 'JP',
        }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectImpossibleTravel(undefined, 900);
      expect(result).toHaveLength(1);
      expect(result[0].fingerprintId).toBe('fp-1');
      expect(result[0].distanceKm).toBeGreaterThan(10000);
      expect(result[0].impliedSpeedKmh).toBeGreaterThan(20000);
      expect(result[0].impossibilityFactor).toBeGreaterThan(20);
      expect(result[0].fromLocation.city).toBe('New York');
      expect(result[0].toLocation.city).toBe('Tokyo');
    });

    it('should not flag travel within realistic speed', async () => {
      const now = Date.now();
      const records = [
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: new Date(now - 8 * 60 * 60 * 1000).toISOString(), // 8 hours ago
          geoLatitude: 40.7128,
          geoLongitude: -74.006,
          geoCity: 'New York',
          geoCountry: 'US',
        }),
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: new Date(now).toISOString(), // now
          geoLatitude: 51.5074,
          geoLongitude: -0.1278,
          geoCity: 'London',
          geoCountry: 'UK',
        }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      // NYC to London is ~5500km, 8 hours = ~688 km/h (under 900)
      const result = await service.detectImpossibleTravel(undefined, 900);
      expect(result).toHaveLength(0);
    });

    it('should filter by specific fingerprint ID', async () => {
      const now = Date.now();
      const records = [
        createRecord({
          fingerprintId: 'fp-target',
          timestamp: new Date(now - 30 * 60 * 1000).toISOString(),
          geoLatitude: 40.7128,
          geoLongitude: -74.006,
        }),
        createRecord({
          fingerprintId: 'fp-target',
          timestamp: new Date(now).toISOString(),
          geoLatitude: 35.6762,
          geoLongitude: 139.6503,
        }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectImpossibleTravel('fp-target', 900);
      expect(result).toHaveLength(1);

      // Verify backend was called with fingerprint filter
      expect(backend.queryFingerprints).toHaveBeenCalledWith(
        '7d',
        { 'fingerprint.id': 'fp-target' }
      );
    });

    it('should sort by impossibility factor descending', async () => {
      const now = Date.now();
      const records = [
        // fp-1: NYC to London in 1 minute (~330,000 km/h)
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: new Date(now - 60 * 1000).toISOString(),
          geoLatitude: 40.7128, geoLongitude: -74.006,
        }),
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: new Date(now).toISOString(),
          geoLatitude: 51.5074, geoLongitude: -0.1278,
        }),
        // fp-2: NYC to Tokyo in 1 minute (even further)
        createRecord({
          fingerprintId: 'fp-2',
          timestamp: new Date(now - 60 * 1000).toISOString(),
          geoLatitude: 40.7128, geoLongitude: -74.006,
        }),
        createRecord({
          fingerprintId: 'fp-2',
          timestamp: new Date(now).toISOString(),
          geoLatitude: 35.6762, geoLongitude: 139.6503,
        }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectImpossibleTravel(undefined, 900);
      expect(result.length).toBeGreaterThanOrEqual(2);
      // Tokyo (farther) should have higher impossibility factor
      expect(result[0].impossibilityFactor).toBeGreaterThanOrEqual(result[1].impossibilityFactor);
    });

    it('should handle records with NaN coordinates gracefully', async () => {
      const records = [
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: hoursAgo(2),
          geoLatitude: NaN,
          geoLongitude: NaN,
        }),
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: hoursAgo(1),
          geoLatitude: 40.7128,
          geoLongitude: -74.006,
        }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectImpossibleTravel();
      // NaN records are filtered out, so only 1 valid location = no pair to compare
      expect(result).toHaveLength(0);
    });

    it('should require at least 2 locations per fingerprint', async () => {
      const records = [
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: hoursAgo(2),
          geoLatitude: 40.7128,
          geoLongitude: -74.006,
        }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.detectImpossibleTravel();
      expect(result).toHaveLength(0);
    });

    it('should respect custom maxSpeedKmh', async () => {
      const now = Date.now();
      const records = [
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: new Date(now - 8 * 60 * 60 * 1000).toISOString(),
          geoLatitude: 40.7128, geoLongitude: -74.006,
        }),
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: new Date(now).toISOString(),
          geoLatitude: 51.5074, geoLongitude: -0.1278,
        }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      // At 900 km/h max, NYC->London in 8h is fine (~688 km/h)
      const result900 = await service.detectImpossibleTravel(undefined, 900);
      expect(result900).toHaveLength(0);

      // At 500 km/h max, same trip would be impossible
      const result500 = await service.detectImpossibleTravel(undefined, 500);
      expect(result500).toHaveLength(1);
    });

    it('should propagate backend errors', async () => {
      const backend: FingerprintQueryBackend = {
        queryFingerprints: vi.fn().mockRejectedValue(new Error('Tempo timeout')),
      };
      const service = new ThreatCorrelationService(backend);

      await expect(service.detectImpossibleTravel()).rejects.toThrow('Tempo timeout');
    });
  });

  // ============================================================================
  // Fingerprint Timeline Tests
  // ============================================================================

  describe('getFingerprintTimeline', () => {
    it('should return empty timeline when no records found', async () => {
      const backend = createMockBackend([]);
      const service = new ThreatCorrelationService(backend);

      const result = await service.getFingerprintTimeline('fp-1');
      expect(result.fingerprintId).toBe('fp-1');
      expect(result.totalVisits).toBe(0);
      expect(result.activities).toEqual([]);
      expect(result.suspiciousPatterns).toEqual([]);
    });

    it('should build complete timeline from records', async () => {
      const records = [
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: hoursAgo(5),
          ipHash: 'ip1',
          geoCity: 'NYC',
          geoCountry: 'US',
          vpnDetected: false,
          navigationCurrentUrl: '/home',
          browserName: 'Chrome',
          browserVersion: '120',
          osName: 'macOS',
          osVersion: '14.0',
          deviceType: 'desktop',
        }),
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: hoursAgo(3),
          ipHash: 'ip2',
          geoCity: 'Boston',
          geoCountry: 'US',
          vpnDetected: false,
          navigationCurrentUrl: '/about',
          browserName: 'Chrome',
          browserVersion: '120',
          osName: 'macOS',
          osVersion: '14.0',
          deviceType: 'desktop',
        }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.getFingerprintTimeline('fp-1', '7d');
      expect(result.fingerprintId).toBe('fp-1');
      expect(result.totalVisits).toBe(2);
      expect(result.uniqueIPs).toBe(2);
      expect(result.uniqueLocations).toBe(2);
      expect(result.vpnUsage.organicVisits).toBe(2);
      expect(result.vpnUsage.vpnVisits).toBe(0);
      expect(result.vpnUsage.changes).toBe(0);
      expect(result.activities).toHaveLength(2);
      expect(result.browserInfo?.name).toBe('Chrome');
      expect(result.deviceInfo?.type).toBe('desktop');
      expect(result.pageVisits).toHaveLength(2);
    });

    it('should detect VPN switching pattern', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(5), ipHash: 'ip1', vpnDetected: false }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(3), ipHash: 'ip2', vpnDetected: true }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.getFingerprintTimeline('fp-1', '7d');
      expect(result.vpnUsage.changes).toBe(1);
      expect(result.suspiciousPatterns).toContain('VPN switching (1 changes)');
    });

    it('should detect IP rotation pattern', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(5), ipHash: 'ip1', vpnDetected: false }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(4), ipHash: 'ip2', vpnDetected: false }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(3), ipHash: 'ip3', vpnDetected: false }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.getFingerprintTimeline('fp-1', '7d');
      expect(result.uniqueIPs).toBe(3);
      expect(result.suspiciousPatterns.some(p => p.includes('IP rotation'))).toBe(true);
    });

    it('should detect high risk score pattern', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(5), ipHash: 'ip1', vpnDetected: false, riskScore: 85 }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(4), ipHash: 'ip1', vpnDetected: false, riskScore: 90 }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.getFingerprintTimeline('fp-1', '7d');
      expect(result.suspiciousPatterns.some(p => p.includes('High risk scores'))).toBe(true);
    });

    it('should clamp time window to 7d maximum', async () => {
      const backend = createMockBackend([]);
      const service = new ThreatCorrelationService(backend);

      await service.getFingerprintTimeline('fp-1', '30d');

      // Should be called with '7d' (clamped from '30d')
      expect(backend.queryFingerprints).toHaveBeenCalledWith(
        '7d',
        { 'fingerprint.id': 'fp-1' }
      );
    });

    it('should not clamp time window under 7d', async () => {
      const backend = createMockBackend([]);
      const service = new ThreatCorrelationService(backend);

      await service.getFingerprintTimeline('fp-1', '3d');

      expect(backend.queryFingerprints).toHaveBeenCalledWith(
        '3d',
        { 'fingerprint.id': 'fp-1' }
      );
    });

    it('should build user agent from browser and OS fields', async () => {
      const records = [
        createRecord({
          fingerprintId: 'fp-1',
          timestamp: hoursAgo(1),
          ipHash: 'ip1',
          vpnDetected: false,
          browserName: 'Firefox',
          browserVersion: '121',
          osName: 'Linux',
          osVersion: '6.1',
        }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.getFingerprintTimeline('fp-1', '7d');
      expect(result.activities[0].userAgent).toBe('Firefox 121 on Linux 6.1');
    });

    it('should exclude root URL from page visits', async () => {
      const records = [
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(3), ipHash: 'ip1', vpnDetected: false, navigationCurrentUrl: '/' }),
        createRecord({ fingerprintId: 'fp-1', timestamp: hoursAgo(2), ipHash: 'ip1', vpnDetected: false, navigationCurrentUrl: '/about' }),
      ];
      const backend = createMockBackend(records);
      const service = new ThreatCorrelationService(backend);

      const result = await service.getFingerprintTimeline('fp-1', '7d');
      expect(result.pageVisits).toHaveLength(1);
      expect(result.pageVisits[0].url).toBe('/about');
    });

    it('should propagate backend errors', async () => {
      const backend: FingerprintQueryBackend = {
        queryFingerprints: vi.fn().mockRejectedValue(new Error('Query failed')),
      };
      const service = new ThreatCorrelationService(backend);

      await expect(service.getFingerprintTimeline('fp-1')).rejects.toThrow('Query failed');
    });
  });

  // ============================================================================
  // Time Window Parsing Tests
  // ============================================================================

  describe('parseTimeWindow', () => {
    it('should parse seconds', () => {
      const service = new ThreatCorrelationService(createMockBackend());
      expect(service.parseTimeWindow('60s')).toBe(60000);
    });

    it('should parse minutes', () => {
      const service = new ThreatCorrelationService(createMockBackend());
      expect(service.parseTimeWindow('30m')).toBe(30 * 60 * 1000);
    });

    it('should parse hours', () => {
      const service = new ThreatCorrelationService(createMockBackend());
      expect(service.parseTimeWindow('24h')).toBe(24 * 60 * 60 * 1000);
    });

    it('should parse days', () => {
      const service = new ThreatCorrelationService(createMockBackend());
      expect(service.parseTimeWindow('7d')).toBe(7 * 24 * 60 * 60 * 1000);
    });

    it('should default to 7d for invalid format', () => {
      const service = new ThreatCorrelationService(createMockBackend());
      expect(service.parseTimeWindow('invalid')).toBe(7 * 24 * 60 * 60 * 1000);
    });
  });

  describe('clampTimeWindow', () => {
    it('should not clamp when under max', () => {
      const service = new ThreatCorrelationService(createMockBackend());
      expect(service.clampTimeWindow('3d', '7d')).toBe('3d');
    });

    it('should clamp when over max', () => {
      const service = new ThreatCorrelationService(createMockBackend());
      expect(service.clampTimeWindow('30d', '7d')).toBe('7d');
    });

    it('should not clamp when exactly at max', () => {
      const service = new ThreatCorrelationService(createMockBackend());
      expect(service.clampTimeWindow('7d', '7d')).toBe('7d');
    });
  });
});
