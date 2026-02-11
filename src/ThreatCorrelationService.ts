/**
 * Threat Correlation Service
 *
 * Provides temporal threat detection and actor tracking by analyzing fingerprint behavior over time.
 *
 * **Key Capabilities**:
 * - VPN switching detection (organic -> VPN before attack)
 * - IP rotation detection (botnet/proxy patterns)
 * - Impossible travel detection (geographic anomalies)
 * - Attack correlation (link attacks with reconnaissance)
 * - Fingerprint timeline aggregation
 *
 * **Architecture**:
 * - Queries fingerprint backend (Tempo) for historical fingerprint data
 * - Performs temporal correlation analysis (no state stored in service)
 * - Returns structured threat intelligence for dashboards
 *
 * @module ThreatCorrelationService
 */

import { getLogger, getHaversineDistance } from './config.js';
import type { FingerprintQueryBackend } from './config.js';
import type {
  VPNChange,
  VPNSwitcher,
  IPChange,
  IPRotationPattern,
  ImpossibleTravelEvent,
  FingerprintActivity,
  FingerprintTimeline,
  BrowserInfo,
  DeviceInfo,
  PageVisit,
} from './types.js';

// ============================================================================
// Service Implementation
// ============================================================================

/**
 * Threat Correlation Service
 *
 * Analyzes fingerprint behavior over time to detect threat actors and attack patterns.
 *
 * **Example Usage**:
 * ```typescript
 * import { ThreatCorrelationService, configureThreatDetection } from '@tinyland-inc/tinyland-threat-detection';
 *
 * // Configure backends
 * configureThreatDetection({ logger: myLogger });
 *
 * const threatService = new ThreatCorrelationService(fingerprintQueryBackend);
 *
 * // Detect VPN switchers (actor visits organic, then switches to VPN)
 * const switchers = await threatService.detectVPNSwitchers('7d', 1);
 *
 * // Detect IP rotation (botnet/proxy patterns)
 * const rotators = await threatService.detectIPRotation('7d', 3);
 *
 * // Detect impossible travel
 * const impossibleTravel = await threatService.detectImpossibleTravel(undefined, 900, '7d');
 *
 * // Get complete timeline for a fingerprint
 * const timeline = await threatService.getFingerprintTimeline('abc123', '30d');
 * ```
 */
export class ThreatCorrelationService {
  private fingerprintBackend: FingerprintQueryBackend;

  constructor(fingerprintBackend: FingerprintQueryBackend) {
    this.fingerprintBackend = fingerprintBackend;
    const logger = getLogger();
    logger.info('ThreatCorrelationService initialized');
  }

  /**
   * Detect fingerprints that switched VPN status over time
   *
   * **Use Case**: Identify threat actors who visit the site organically (to avoid detection),
   * then enable VPN before launching an attack.
   *
   * **Example Scenario**:
   * - Day 1 10:00 AM: Actor visits from home IP (no VPN) - fingerprinted
   * - Day 2 09:00 AM: Same fingerprint returns with VPN enabled
   * - Day 2 09:05 AM: DDoS attack begins from VPN IP
   * - **Detection**: VPN switching detected, correlated with attack timing
   *
   * **Algorithm**:
   * 1. Query all fingerprints from backend within time window
   * 2. Group records by fingerprint_id
   * 3. For each fingerprint, check if vpn_detected changes true <-> false
   * 4. Flag fingerprints with 1+ change
   * 5. Calculate risk score based on change frequency and timing
   *
   * @param timeWindow - How far back to search (e.g., '7d', '30d')
   * @param minChanges - Minimum VPN status changes to flag (default: 1)
   * @returns Array of VPNSwitcher objects sorted by risk score (descending)
   *
   * @example
   * ```typescript
   * // Find all fingerprints that switched VPN in last 7 days
   * const switchers = await threatService.detectVPNSwitchers('7d', 1);
   *
   * switchers.forEach(switcher => {
   *   console.log(`Fingerprint ${switcher.fingerprintId}:`);
   *   console.log(`  VPN changes: ${switcher.totalChanges}`);
   *   console.log(`  Risk score: ${switcher.riskScore}`);
   *   switcher.vpnChanges.forEach(change => {
   *     console.log(`  ${change.timestamp}: VPN=${change.vpnDetected} (${change.city}, ${change.country})`);
   *   });
   * });
   * ```
   */
  async detectVPNSwitchers(
    timeWindow: string = '7d',
    minChanges: number = 1
  ): Promise<VPNSwitcher[]> {
    const logger = getLogger();
    logger.info('Detecting VPN switchers', { timeWindow, minChanges });

    try {
      const allRecords = await this.fingerprintBackend.queryFingerprints(
        timeWindow,
        {},
        10000
      );

      // Group by fingerprintId
      const grouped = new Map<string, typeof allRecords>();
      for (const record of allRecords) {
        if (!record.fingerprintId) continue;
        if (!grouped.has(record.fingerprintId)) {
          grouped.set(record.fingerprintId, []);
        }
        grouped.get(record.fingerprintId)!.push(record);
      }

      // Sort each group by timestamp
      for (const records of grouped.values()) {
        records.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
      }

      const vpnSwitchers: VPNSwitcher[] = [];

      for (const [fingerprintId, records] of grouped.entries()) {
        // Build VPN change timeline
        const vpnChanges: VPNChange[] = [];
        let previousVpnState: boolean | null = null;

        for (const record of records) {
          // Track every VPN status change
          if (previousVpnState !== null && record.vpnDetected !== previousVpnState) {
            vpnChanges.push({
              timestamp: record.timestamp,
              vpnDetected: record.vpnDetected || false,
              ipHash: record.ipHash ?? '',
              city: record.geoCity,
              country: record.geoCountry,
              provider: record.vpnProvider,
              confidence: record.vpnConfidence ? parseFloat(record.vpnConfidence) : undefined
            });
          } else if (previousVpnState === null) {
            // First visit - record initial state
            vpnChanges.push({
              timestamp: record.timestamp,
              vpnDetected: record.vpnDetected || false,
              ipHash: record.ipHash ?? '',
              city: record.geoCity,
              country: record.geoCountry,
              provider: record.vpnProvider,
              confidence: record.vpnConfidence ? parseFloat(record.vpnConfidence) : undefined
            });
          }

          previousVpnState = record.vpnDetected || false;
        }

        // Count actual changes (exclude first visit)
        const totalChanges = vpnChanges.length - 1;

        // Filter by minChanges threshold
        if (totalChanges < minChanges) {
          continue;
        }

        // Calculate risk score (0-100)
        // Base score: 30 points for any VPN switching
        // +10 points per additional change (max 40)
        // +30 points if VPN enabled recently (last 24h)
        let riskScore = 30;
        riskScore += Math.min(totalChanges * 10, 40);

        // Check if VPN was enabled recently
        const lastChange = vpnChanges[vpnChanges.length - 1];
        const lastChangeTime = new Date(lastChange.timestamp).getTime();
        const now = Date.now();
        const hoursSinceLastChange = (now - lastChangeTime) / (1000 * 60 * 60);

        if (lastChange.vpnDetected && hoursSinceLastChange < 24) {
          riskScore += 30;
        }

        // Cap at 100
        riskScore = Math.min(riskScore, 100);

        // Determine suspicious activity description
        let suspiciousActivity: string | undefined;
        if (lastChange.vpnDetected && hoursSinceLastChange < 1) {
          suspiciousActivity = 'VPN enabled within last hour';
        } else if (totalChanges >= 3) {
          suspiciousActivity = `Frequent VPN switching (${totalChanges} changes)`;
        }

        vpnSwitchers.push({
          fingerprintId,
          firstSeen: records[0].timestamp,
          lastSeen: records[records.length - 1].timestamp,
          vpnChanges,
          totalChanges,
          riskScore,
          suspiciousActivity
        });
      }

      // Sort by risk score descending
      vpnSwitchers.sort((a, b) => b.riskScore - a.riskScore);

      logger.info('VPN switching detection complete', {
        timeWindow,
        totalFingerprints: grouped.size,
        vpnSwitchers: vpnSwitchers.length,
        minChanges,
      });

      return vpnSwitchers;
    } catch (error) {
      const logger = getLogger();
      logger.error('Failed to detect VPN switchers', {
        error: error instanceof Error ? error.message : String(error),
        timeWindow,
        minChanges
      });
      throw error;
    }
  }

  /**
   * Detect fingerprints rotating through multiple IP addresses
   *
   * **Use Case**: Identify botnet operators, proxy users, or attackers using IP rotation
   * to evade rate limiting or blacklists.
   *
   * **Example Scenario**:
   * - Fingerprint abc123 visits from 5 different IPs within 1 hour
   * - All IPs are from different countries (proxy network)
   * - Average time between changes: 12 minutes
   * - **Detection**: High suspicion IP rotation pattern
   *
   * **Algorithm**:
   * 1. Query all fingerprint records within time window
   * 2. Group by fingerprint_id
   * 3. Count unique ip_hash values per fingerprint
   * 4. Calculate average time between IP changes
   * 5. Flag fingerprints with >= minUniqueIPs
   * 6. Classify suspicion level based on rotation speed:
   *    - low: 3-4 IPs over 24h (could be mobile + home + work)
   *    - medium: 5-7 IPs over 24h (suspicious)
   *    - high: 8-15 IPs over 24h (very suspicious)
   *    - critical: 15+ IPs over 24h (botnet/proxy network)
   *
   * @param timeWindow - How far back to search (e.g., '7d', '24h')
   * @param minUniqueIPs - Minimum unique IPs to flag as rotation (default: 3)
   * @returns Array of IPRotationPattern objects sorted by suspicion level
   *
   * @example
   * ```typescript
   * // Find fingerprints using 3+ IPs in last 24 hours
   * const rotators = await threatService.detectIPRotation('24h', 3);
   *
   * rotators.forEach(pattern => {
   *   console.log(`Fingerprint ${pattern.fingerprintId}:`);
   *   console.log(`  Unique IPs: ${pattern.uniqueIPs}`);
   *   console.log(`  Suspicion: ${pattern.suspicionLevel}`);
   *   console.log(`  Avg change interval: ${pattern.avgTimeBetweenChanges}s`);
   * });
   * ```
   */
  async detectIPRotation(
    timeWindow: string = '7d',
    minUniqueIPs: number = 3
  ): Promise<IPRotationPattern[]> {
    const logger = getLogger();
    logger.info('Detecting IP rotation', { timeWindow, minUniqueIPs });

    try {
      const allRecords = await this.fingerprintBackend.queryFingerprints(
        timeWindow,
        {},
        10000
      );

      // Group by fingerprint_id
      const grouped = new Map<string, typeof allRecords>();
      for (const record of allRecords) {
        if (!record.fingerprintId) continue;

        if (!grouped.has(record.fingerprintId)) {
          grouped.set(record.fingerprintId, []);
        }
        grouped.get(record.fingerprintId)!.push(record);
      }

      const ipRotationPatterns: IPRotationPattern[] = [];

      for (const [fingerprintId, records] of grouped.entries()) {
        // Sort by timestamp
        records.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

        // Extract unique IPs (using ipHash)
        const ipHashes = records.map(r => r.ipHash).filter(Boolean) as string[];
        const uniqueIPSet = new Set(ipHashes);
        const uniqueIPs = uniqueIPSet.size;

        // Filter by minUniqueIPs threshold
        if (uniqueIPs < minUniqueIPs) {
          continue;
        }

        // Build IP change timeline
        const ipChanges: IPChange[] = [];
        let previousIPHash: string | null = null;

        for (const record of records) {
          const currentIPHash = record.fingerprintHash;

          if (currentIPHash && currentIPHash !== previousIPHash) {
            ipChanges.push({
              timestamp: record.timestamp,
              ipHash: currentIPHash,
              city: record.geoCity,
              country: record.geoCountry,
              vpnDetected: record.vpnDetected ?? false
            });

            previousIPHash = currentIPHash;
          }
        }

        // Calculate average time between IP changes
        let totalTimeDiff = 0;
        for (let i = 1; i < ipChanges.length; i++) {
          const prevTime = new Date(ipChanges[i - 1].timestamp).getTime();
          const currTime = new Date(ipChanges[i].timestamp).getTime();
          totalTimeDiff += (currTime - prevTime) / 1000; // seconds
        }
        const avgTimeBetweenChanges = ipChanges.length > 1
          ? totalTimeDiff / (ipChanges.length - 1)
          : 0;

        // Classify suspicion level based on count and speed
        let suspicionLevel: 'low' | 'medium' | 'high' | 'critical';

        const timeWindowMs = this.parseTimeWindow(timeWindow);
        const hoursInWindow = timeWindowMs / (1000 * 60 * 60);

        if (uniqueIPs >= 15) {
          suspicionLevel = 'critical';
        } else if (uniqueIPs >= 8) {
          suspicionLevel = 'high';
        } else if (uniqueIPs >= 5) {
          suspicionLevel = 'medium';
        } else {
          if (hoursInWindow <= 24 && uniqueIPs >= 3) {
            suspicionLevel = 'medium';
          } else {
            suspicionLevel = 'low';
          }
        }

        ipRotationPatterns.push({
          fingerprintId,
          timeWindow,
          uniqueIPs,
          ipChanges,
          avgTimeBetweenChanges,
          suspicionLevel
        });
      }

      // Sort by suspicion level (critical > high > medium > low) then by unique IP count
      const suspicionOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      ipRotationPatterns.sort((a, b) => {
        const levelDiff = suspicionOrder[a.suspicionLevel] - suspicionOrder[b.suspicionLevel];
        if (levelDiff !== 0) return levelDiff;
        return b.uniqueIPs - a.uniqueIPs;
      });

      logger.info('IP rotation detection complete', {
        timeWindow,
        totalFingerprints: grouped.size,
        ipRotationPatterns: ipRotationPatterns.length,
        minUniqueIPs
      });

      return ipRotationPatterns;
    } catch (error) {
      const logger = getLogger();
      logger.error('Failed to detect IP rotation', {
        error: error instanceof Error ? error.message : String(error),
        timeWindow,
        minUniqueIPs
      });
      throw error;
    }
  }

  /**
   * Detect impossible travel - same fingerprint in distant locations too quickly
   *
   * **Use Case**: Identify account sharing, stolen fingerprints, or VPN switching
   * by detecting physically impossible location changes.
   *
   * **Example Scenario**:
   * - 10:00 AM: Fingerprint in New York City (40.7128 N, 74.0060 W)
   * - 10:30 AM: Same fingerprint in Tokyo (35.6762 N, 139.6503 E)
   * - Distance: ~13,000 km
   * - Time: 30 minutes
   * - Implied speed: 26,000 km/h
   * - Max realistic (commercial flight): 900 km/h
   * - **Detection**: Impossible travel (impossibility factor: 28.9x)
   *
   * **Algorithm**:
   * 1. Query fingerprint records with geographic coordinates
   * 2. If fingerprintId specified, filter to that fingerprint only
   * 3. Sort by timestamp for each fingerprint
   * 4. For each consecutive pair of locations:
   *    a. Calculate distance using Haversine formula
   *    b. Calculate time elapsed in seconds
   *    c. Calculate implied speed (km/h)
   *    d. If speed > maxSpeedKmh, flag as impossible travel
   *    e. Calculate impossibility factor (impliedSpeed / maxSpeed)
   * 5. Return ImpossibleTravelEvent[] sorted by impossibility factor
   *
   * @param fingerprintId - Specific fingerprint to analyze (undefined = check all)
   * @param maxSpeedKmh - Maximum realistic speed in km/h (default: 900 = commercial flight)
   * @param timeWindow - How far back to search (default: '7d')
   * @returns Array of ImpossibleTravelEvent objects sorted by impossibility factor (descending)
   *
   * @example
   * ```typescript
   * // Check all fingerprints for impossible travel in last 7 days
   * const events = await threatService.detectImpossibleTravel(undefined, 900, '7d');
   *
   * events.forEach(event => {
   *   console.log(`Fingerprint ${event.fingerprintId}:`);
   *   console.log(`  From: ${event.fromLocation.city} (${event.fromLocation.timestamp})`);
   *   console.log(`  To: ${event.toLocation.city} (${event.toLocation.timestamp})`);
   *   console.log(`  Distance: ${event.distanceKm} km`);
   *   console.log(`  Speed: ${event.impliedSpeedKmh} km/h (${event.impossibilityFactor}x impossible)`);
   * });
   * ```
   */
  async detectImpossibleTravel(
    fingerprintId?: string,
    maxSpeedKmh: number = 900,
    timeWindow: string = '7d'
  ): Promise<ImpossibleTravelEvent[]> {
    const logger = getLogger();
    logger.info('Detecting impossible travel', { fingerprintId, maxSpeedKmh, timeWindow });

    try {
      const records = fingerprintId
        ? await this.fingerprintBackend.queryFingerprints(
            timeWindow,
            { 'fingerprint.id': fingerprintId }
          )
        : await this.fingerprintBackend.queryFingerprints(
            timeWindow,
            {},
            10000
          );

      // Filter to records with geographic coordinates
      const recordsWithLocation = records.filter(
        r => r.geoLatitude !== null &&
             r.geoLatitude !== undefined &&
             r.geoLongitude !== null &&
             r.geoLongitude !== undefined &&
             typeof r.geoLatitude === 'number' &&
             typeof r.geoLongitude === 'number' &&
             !isNaN(r.geoLatitude) &&
             !isNaN(r.geoLongitude)
      );

      // Group by fingerprint_id
      const grouped = new Map<string, typeof recordsWithLocation>();
      for (const record of recordsWithLocation) {
        if (!record.fingerprintId) continue;

        if (!grouped.has(record.fingerprintId)) {
          grouped.set(record.fingerprintId, []);
        }
        grouped.get(record.fingerprintId)!.push(record);
      }

      const haversineDistance = getHaversineDistance();
      const impossibleTravelEvents: ImpossibleTravelEvent[] = [];

      for (const [fpId, fpRecords] of grouped.entries()) {
        // Need at least 2 locations to detect travel
        if (fpRecords.length < 2) continue;

        // Sort by timestamp
        fpRecords.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

        // Check each consecutive pair of locations
        for (let i = 1; i < fpRecords.length; i++) {
          const prevRecord = fpRecords[i - 1];
          const currRecord = fpRecords[i];

          // Extract coordinates (already validated as non-null)
          const lat1 = prevRecord.geoLatitude!;
          const lng1 = prevRecord.geoLongitude!;
          const lat2 = currRecord.geoLatitude!;
          const lng2 = currRecord.geoLongitude!;

          // Calculate distance using Haversine formula
          const distanceKm = haversineDistance(lat1, lng1, lat2, lng2);

          // Calculate time elapsed
          const time1 = new Date(prevRecord.timestamp).getTime();
          const time2 = new Date(currRecord.timestamp).getTime();
          const timeElapsedSeconds = (time2 - time1) / 1000;

          // Calculate implied speed (km/h)
          const timeElapsedHours = timeElapsedSeconds / 3600;
          const impliedSpeedKmh = timeElapsedHours > 0 ? distanceKm / timeElapsedHours : 0;

          // Check if travel is impossible
          if (impliedSpeedKmh > maxSpeedKmh) {
            const impossibilityFactor = impliedSpeedKmh / maxSpeedKmh;

            impossibleTravelEvents.push({
              fingerprintId: fpId,
              fromLocation: {
                timestamp: prevRecord.timestamp,
                latitude: lat1,
                longitude: lng1,
                city: prevRecord.geoCity,
                country: prevRecord.geoCountry
              },
              toLocation: {
                timestamp: currRecord.timestamp,
                latitude: lat2,
                longitude: lng2,
                city: currRecord.geoCity,
                country: currRecord.geoCountry
              },
              distanceKm,
              timeElapsedSeconds,
              impliedSpeedKmh,
              maxRealisticSpeedKmh: maxSpeedKmh,
              impossibilityFactor
            });
          }
        }
      }

      // Sort by impossibility factor descending (most impossible first)
      impossibleTravelEvents.sort((a, b) => b.impossibilityFactor - a.impossibilityFactor);

      logger.info('Impossible travel detection complete', {
        fingerprintId,
        timeWindow,
        maxSpeedKmh,
        totalFingerprints: grouped.size,
        impossibleTravelEvents: impossibleTravelEvents.length
      });

      return impossibleTravelEvents;
    } catch (error) {
      const logger = getLogger();
      logger.error('Failed to detect impossible travel', {
        error: error instanceof Error ? error.message : String(error),
        fingerprintId,
        maxSpeedKmh,
        timeWindow
      });
      throw error;
    }
  }

  /**
   * Get complete activity timeline for a fingerprint
   *
   * **Use Case**: Investigate a specific fingerprint's behavior over time.
   * Shows every visit with IP changes, location changes, VPN usage, and suspicious patterns.
   *
   * **Algorithm**:
   * 1. Query all records for fingerprint_id within time window
   * 2. Sort by timestamp (oldest first)
   * 3. Extract unique IPs (ip_hash) and locations (city, country)
   * 4. Count VPN vs organic visits
   * 5. Detect VPN status changes
   * 6. Build chronological activities array
   * 7. Detect suspicious patterns:
   *    - VPN switching
   *    - IP rotation
   *    - High request rate
   *    - High risk scores
   * 8. Return FingerprintTimeline object
   *
   * @param fingerprintId - Fingerprint to track
   * @param timeWindow - How far back to search (default: '7d')
   * @returns FingerprintTimeline object with complete activity history
   *
   * @example
   * ```typescript
   * // Get 7-day timeline for a fingerprint
   * const timeline = await threatService.getFingerprintTimeline('abc123', '7d');
   *
   * console.log(`Fingerprint: ${timeline.fingerprintId}`);
   * console.log(`Total visits: ${timeline.totalVisits}`);
   * console.log(`VPN usage: ${timeline.vpnUsage.vpnVisits} VPN, ${timeline.vpnUsage.organicVisits} organic`);
   * console.log(`Suspicious patterns: ${timeline.suspiciousPatterns.join(', ')}`);
   *
   * timeline.activities.forEach(activity => {
   *   console.log(`${activity.timestamp}: ${activity.url} (${activity.city}) [VPN: ${activity.vpnDetected}]`);
   * });
   * ```
   */
  async getFingerprintTimeline(
    fingerprintId: string,
    timeWindow: string = '7d'
  ): Promise<FingerprintTimeline> {
    // Clamp to backend limit (7d / 168h for Tempo)
    const clampedTimeWindow = this.clampTimeWindow(timeWindow, '7d');

    const logger = getLogger();
    logger.info('Getting fingerprint timeline', {
      fingerprintId,
      requestedTimeWindow: timeWindow,
      clampedTimeWindow
    });

    try {
      logger.info('Querying backend for fingerprint timeline', { fingerprintId, timeWindow: clampedTimeWindow });
      const tempoRecords = await this.fingerprintBackend.queryFingerprints(
        clampedTimeWindow,
        { 'fingerprint.id': fingerprintId }
      );

      logger.info('Backend records returned', {
        fingerprintId,
        recordCount: tempoRecords.length,
      });

      // Handle empty result
      if (tempoRecords.length === 0) {
        logger.warn('No records found for fingerprint', { fingerprintId, timeWindow });
        return {
          fingerprintId,
          firstSeen: new Date().toISOString(),
          lastSeen: new Date().toISOString(),
          totalVisits: 0,
          uniqueIPs: 0,
          uniqueLocations: 0,
          vpnUsage: { vpnVisits: 0, organicVisits: 0, changes: 0 },
          activities: [],
          suspiciousPatterns: [],
          browserInfo: undefined,
          deviceInfo: undefined,
          ipHistory: [],
          pageVisits: []
        };
      }

      // Records are sorted by timestamp from backend query
      const firstSeen = tempoRecords[0].timestamp;
      const lastSeen = tempoRecords[tempoRecords.length - 1].timestamp;
      const totalVisits = tempoRecords.length;

      // Calculate unique IPs (using ipHash)
      const ipHashes = tempoRecords
        .map(r => r.ipHash)
        .filter(Boolean) as string[];
      const uniqueIPs = new Set(ipHashes).size;

      // Calculate unique locations
      const locations = tempoRecords
        .filter(r => r.geoCity && r.geoCountry)
        .map(r => `${r.geoCity},${r.geoCountry}`);
      const uniqueLocations = new Set(locations).size;

      // Calculate VPN usage
      const vpnVisits = tempoRecords.filter(r => r.vpnDetected === true).length;
      const organicVisits = tempoRecords.filter(r => r.vpnDetected === false).length;

      // Count VPN status changes
      let vpnChanges = 0;
      for (let i = 1; i < tempoRecords.length; i++) {
        if (tempoRecords[i].vpnDetected !== tempoRecords[i - 1].vpnDetected) {
          vpnChanges++;
        }
      }

      // Build activities array
      const activities: FingerprintActivity[] = tempoRecords.map(record => ({
        timestamp: record.timestamp,
        url: record.navigationCurrentUrl,
        ipHash: record.ipHash ?? '',
        ipType: record.ipType,
        city: record.geoCity,
        country: record.geoCountry,
        vpnDetected: record.vpnDetected || false,
        riskScore: record.riskScore,
        userAgent: record.browserName && record.osName
          ? `${record.browserName}${record.browserVersion ? ' ' + record.browserVersion : ''} on ${record.osName}${record.osVersion ? ' ' + record.osVersion : ''}`
          : undefined,
        sessionId: record.sessionId,
        userId: record.userId,
        userHandle: record.userHandle
      }));

      // Detect suspicious patterns
      const suspiciousPatterns: string[] = [];

      // Pattern 1: VPN switching
      if (vpnChanges > 0) {
        suspiciousPatterns.push(`VPN switching (${vpnChanges} changes)`);
      }

      // Pattern 2: IP rotation (3+ unique IPs is suspicious)
      if (uniqueIPs >= 3) {
        suspiciousPatterns.push(`IP rotation (${uniqueIPs} unique IPs)`);
      }

      // Pattern 3: High request rate (naive check - >10 requests/minute)
      const timeWindowMs = this.parseTimeWindow(timeWindow);
      const requestsPerMinute = (totalVisits / (timeWindowMs / 60000));
      if (requestsPerMinute > 10) {
        suspiciousPatterns.push(`High request rate (${requestsPerMinute.toFixed(1)} requests/min)`);
      }

      // Pattern 4: High risk scores
      const highRiskCount = tempoRecords.filter(r => r.riskScore && r.riskScore > 70).length;
      if (highRiskCount > 0) {
        suspiciousPatterns.push(`High risk scores (${highRiskCount}/${totalVisits} visits)`);
      }

      // Extract browser info from most recent record
      const latestRecord = tempoRecords[tempoRecords.length - 1];
      const browserInfo: BrowserInfo | undefined = latestRecord.browserName
        ? {
            name: latestRecord.browserName,
            version: latestRecord.browserVersion
          }
        : undefined;

      // Extract device info from most recent record
      const deviceInfo: DeviceInfo | undefined = latestRecord.deviceType
        ? {
            type: latestRecord.deviceType,
            os: latestRecord.osName,
            osVersion: latestRecord.osVersion
          }
        : undefined;

      // Build IP history (unique IP hashes)
      const ipHistory = Array.from(ipHashes);

      // Build page visits from navigation URLs
      const pageVisits: PageVisit[] = tempoRecords
        .filter(r => r.navigationCurrentUrl && r.navigationCurrentUrl !== '/')
        .map(r => ({
          url: r.navigationCurrentUrl!,
          timestamp: r.timestamp
        }));

      const timeline: FingerprintTimeline = {
        fingerprintId,
        firstSeen,
        lastSeen,
        totalVisits,
        uniqueIPs,
        uniqueLocations,
        vpnUsage: {
          vpnVisits,
          organicVisits,
          changes: vpnChanges
        },
        activities,
        suspiciousPatterns,
        browserInfo,
        deviceInfo,
        ipHistory,
        pageVisits
      };

      logger.info('Fingerprint timeline generated', {
        fingerprintId,
        totalVisits,
        uniqueIPs,
        vpnChanges,
        suspiciousPatternsCount: suspiciousPatterns.length
      });

      return timeline;
    } catch (error) {
      const logger = getLogger();
      logger.error('Failed to get fingerprint timeline', {
        error: error instanceof Error ? error.message : String(error),
        fingerprintId,
        timeWindow
      });
      throw error;
    }
  }

  /**
   * Parse time window string to milliseconds
   *
   * @param timeWindow - Time window string (e.g., "7d", "24h", "30m", "60s")
   * @returns Duration in milliseconds
   */
  parseTimeWindow(timeWindow: string): number {
    const logger = getLogger();
    const match = timeWindow.match(/^(\d+)([smhd])$/);
    if (!match) {
      logger.warn('Invalid time window format, defaulting to 7d', { timeWindow });
      return 7 * 24 * 60 * 60 * 1000;
    }

    const value = parseInt(match[1]);
    const unit = match[2];

    const multipliers: Record<string, number> = {
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000
    };

    return value * multipliers[unit];
  }

  /**
   * Clamp time window to a maximum query limit
   *
   * Tempo returns 400 Bad Request if the time range exceeds 168 hours.
   * This method ensures we never exceed that limit.
   *
   * @param requested - Requested time window (e.g., "30d", "14d")
   * @param maxWindow - Maximum allowed (default: "7d" = 168h)
   * @returns Clamped time window string
   */
  clampTimeWindow(requested: string, maxWindow: string = '7d'): string {
    const requestedMs = this.parseTimeWindow(requested);
    const maxMs = this.parseTimeWindow(maxWindow);

    if (requestedMs <= maxMs) {
      return requested;
    }

    const logger = getLogger();
    logger.warn('Time window exceeds backend limit, clamping', {
      requested,
      requestedMs,
      maxWindow,
      maxMs
    });

    return maxWindow;
  }
}
