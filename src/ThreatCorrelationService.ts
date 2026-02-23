



















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
































export class ThreatCorrelationService {
  private fingerprintBackend: FingerprintQueryBackend;

  constructor(fingerprintBackend: FingerprintQueryBackend) {
    this.fingerprintBackend = fingerprintBackend;
    const logger = getLogger();
    logger.info('ThreatCorrelationService initialized');
  }

  





































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

      
      const grouped = new Map<string, typeof allRecords>();
      for (const record of allRecords) {
        if (!record.fingerprintId) continue;
        if (!grouped.has(record.fingerprintId)) {
          grouped.set(record.fingerprintId, []);
        }
        grouped.get(record.fingerprintId)!.push(record);
      }

      
      for (const records of grouped.values()) {
        records.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
      }

      const vpnSwitchers: VPNSwitcher[] = [];

      for (const [fingerprintId, records] of grouped.entries()) {
        
        const vpnChanges: VPNChange[] = [];
        let previousVpnState: boolean | null = null;

        for (const record of records) {
          
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

        
        const totalChanges = vpnChanges.length - 1;

        
        if (totalChanges < minChanges) {
          continue;
        }

        
        
        
        
        let riskScore = 30;
        riskScore += Math.min(totalChanges * 10, 40);

        
        const lastChange = vpnChanges[vpnChanges.length - 1];
        const lastChangeTime = new Date(lastChange.timestamp).getTime();
        const now = Date.now();
        const hoursSinceLastChange = (now - lastChangeTime) / (1000 * 60 * 60);

        if (lastChange.vpnDetected && hoursSinceLastChange < 24) {
          riskScore += 30;
        }

        
        riskScore = Math.min(riskScore, 100);

        
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
        
        records.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

        
        const ipHashes = records.map(r => r.ipHash).filter(Boolean) as string[];
        const uniqueIPSet = new Set(ipHashes);
        const uniqueIPs = uniqueIPSet.size;

        
        if (uniqueIPs < minUniqueIPs) {
          continue;
        }

        
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

        
        let totalTimeDiff = 0;
        for (let i = 1; i < ipChanges.length; i++) {
          const prevTime = new Date(ipChanges[i - 1].timestamp).getTime();
          const currTime = new Date(ipChanges[i].timestamp).getTime();
          totalTimeDiff += (currTime - prevTime) / 1000; 
        }
        const avgTimeBetweenChanges = ipChanges.length > 1
          ? totalTimeDiff / (ipChanges.length - 1)
          : 0;

        
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
        
        if (fpRecords.length < 2) continue;

        
        fpRecords.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

        
        for (let i = 1; i < fpRecords.length; i++) {
          const prevRecord = fpRecords[i - 1];
          const currRecord = fpRecords[i];

          
          const lat1 = prevRecord.geoLatitude!;
          const lng1 = prevRecord.geoLongitude!;
          const lat2 = currRecord.geoLatitude!;
          const lng2 = currRecord.geoLongitude!;

          
          const distanceKm = haversineDistance(lat1, lng1, lat2, lng2);

          
          const time1 = new Date(prevRecord.timestamp).getTime();
          const time2 = new Date(currRecord.timestamp).getTime();
          const timeElapsedSeconds = (time2 - time1) / 1000;

          
          const timeElapsedHours = timeElapsedSeconds / 3600;
          const impliedSpeedKmh = timeElapsedHours > 0 ? distanceKm / timeElapsedHours : 0;

          
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

  






































  async getFingerprintTimeline(
    fingerprintId: string,
    timeWindow: string = '7d'
  ): Promise<FingerprintTimeline> {
    
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

      
      const firstSeen = tempoRecords[0].timestamp;
      const lastSeen = tempoRecords[tempoRecords.length - 1].timestamp;
      const totalVisits = tempoRecords.length;

      
      const ipHashes = tempoRecords
        .map(r => r.ipHash)
        .filter(Boolean) as string[];
      const uniqueIPs = new Set(ipHashes).size;

      
      const locations = tempoRecords
        .filter(r => r.geoCity && r.geoCountry)
        .map(r => `${r.geoCity},${r.geoCountry}`);
      const uniqueLocations = new Set(locations).size;

      
      const vpnVisits = tempoRecords.filter(r => r.vpnDetected === true).length;
      const organicVisits = tempoRecords.filter(r => r.vpnDetected === false).length;

      
      let vpnChanges = 0;
      for (let i = 1; i < tempoRecords.length; i++) {
        if (tempoRecords[i].vpnDetected !== tempoRecords[i - 1].vpnDetected) {
          vpnChanges++;
        }
      }

      
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

      
      const suspiciousPatterns: string[] = [];

      
      if (vpnChanges > 0) {
        suspiciousPatterns.push(`VPN switching (${vpnChanges} changes)`);
      }

      
      if (uniqueIPs >= 3) {
        suspiciousPatterns.push(`IP rotation (${uniqueIPs} unique IPs)`);
      }

      
      const timeWindowMs = this.parseTimeWindow(timeWindow);
      const requestsPerMinute = (totalVisits / (timeWindowMs / 60000));
      if (requestsPerMinute > 10) {
        suspiciousPatterns.push(`High request rate (${requestsPerMinute.toFixed(1)} requests/min)`);
      }

      
      const highRiskCount = tempoRecords.filter(r => r.riskScore && r.riskScore > 70).length;
      if (highRiskCount > 0) {
        suspiciousPatterns.push(`High risk scores (${highRiskCount}/${totalVisits} visits)`);
      }

      
      const latestRecord = tempoRecords[tempoRecords.length - 1];
      const browserInfo: BrowserInfo | undefined = latestRecord.browserName
        ? {
            name: latestRecord.browserName,
            version: latestRecord.browserVersion
          }
        : undefined;

      
      const deviceInfo: DeviceInfo | undefined = latestRecord.deviceType
        ? {
            type: latestRecord.deviceType,
            os: latestRecord.osName,
            osVersion: latestRecord.osVersion
          }
        : undefined;

      
      const ipHistory = Array.from(ipHashes);

      
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
