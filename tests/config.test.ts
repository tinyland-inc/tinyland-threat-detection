/**
 * Tests for threat detection configuration and DI
 */
import { describe, it, expect, beforeEach } from 'vitest';
import {
  configureThreatDetection,
  getThreatDetectionConfig,
  resetThreatDetectionConfig,
  getLogger,
  getHaversineDistance,
} from '../src/config.js';
import type { ThreatDetectionLogger } from '../src/config.js';

describe('configureThreatDetection', () => {
  beforeEach(() => {
    resetThreatDetectionConfig();
  });

  it('should start with empty configuration', () => {
    const config = getThreatDetectionConfig();
    expect(config).toEqual({});
  });

  it('should merge configuration on each call', () => {
    const logger: ThreatDetectionLogger = {
      info: () => {},
      warn: () => {},
      error: () => {},
      debug: () => {},
    };

    configureThreatDetection({ logger });
    expect(getThreatDetectionConfig().logger).toBe(logger);

    configureThreatDetection({ observabilityConfig: { lokiUrl: 'http://loki:3100' } });
    // Logger should still be there after merging
    expect(getThreatDetectionConfig().logger).toBe(logger);
    expect(getThreatDetectionConfig().observabilityConfig?.lokiUrl).toBe('http://loki:3100');
  });

  it('should allow overriding existing config values', () => {
    const logger1: ThreatDetectionLogger = {
      info: () => {},
      warn: () => {},
      error: () => {},
      debug: () => {},
    };

    const logger2: ThreatDetectionLogger = {
      info: () => {},
      warn: () => {},
      error: () => {},
      debug: () => {},
    };

    configureThreatDetection({ logger: logger1 });
    expect(getThreatDetectionConfig().logger).toBe(logger1);

    configureThreatDetection({ logger: logger2 });
    expect(getThreatDetectionConfig().logger).toBe(logger2);
  });
});

describe('resetThreatDetectionConfig', () => {
  it('should clear all configuration', () => {
    configureThreatDetection({
      logger: {
        info: () => {},
        warn: () => {},
        error: () => {},
        debug: () => {},
      },
      observabilityConfig: { lokiUrl: 'http://loki:3100' },
    });

    resetThreatDetectionConfig();

    const config = getThreatDetectionConfig();
    expect(config).toEqual({});
    expect(config.logger).toBeUndefined();
    expect(config.observabilityConfig).toBeUndefined();
  });
});

describe('getLogger', () => {
  beforeEach(() => {
    resetThreatDetectionConfig();
  });

  it('should return no-op logger when none configured', () => {
    const logger = getLogger();
    expect(logger).toBeDefined();
    // Should not throw when called
    expect(() => logger.info('test')).not.toThrow();
    expect(() => logger.warn('test')).not.toThrow();
    expect(() => logger.error('test')).not.toThrow();
    expect(() => logger.debug('test')).not.toThrow();
  });

  it('should return no-op logger that accepts metadata', () => {
    const logger = getLogger();
    expect(() => logger.info('test', { key: 'value' })).not.toThrow();
    expect(() => logger.error('test', { error: 'details' })).not.toThrow();
  });

  it('should return configured logger when one is provided', () => {
    const messages: string[] = [];
    const customLogger: ThreatDetectionLogger = {
      info: (msg) => messages.push(`INFO: ${msg}`),
      warn: (msg) => messages.push(`WARN: ${msg}`),
      error: (msg) => messages.push(`ERROR: ${msg}`),
      debug: (msg) => messages.push(`DEBUG: ${msg}`),
    };

    configureThreatDetection({ logger: customLogger });
    const logger = getLogger();

    logger.info('hello');
    logger.warn('caution');
    logger.error('failure');
    logger.debug('verbose');

    expect(messages).toEqual([
      'INFO: hello',
      'WARN: caution',
      'ERROR: failure',
      'DEBUG: verbose',
    ]);
  });

  it('should fall back to no-op after reset', () => {
    const messages: string[] = [];
    configureThreatDetection({
      logger: {
        info: (msg) => messages.push(msg),
        warn: () => {},
        error: () => {},
        debug: () => {},
      },
    });

    getLogger().info('before reset');
    expect(messages).toHaveLength(1);

    resetThreatDetectionConfig();
    getLogger().info('after reset');
    // Should not add to messages since logger was reset to no-op
    expect(messages).toHaveLength(1);
  });
});

describe('getHaversineDistance', () => {
  beforeEach(() => {
    resetThreatDetectionConfig();
  });

  it('should return built-in haversine function by default', () => {
    const haversine = getHaversineDistance();
    expect(typeof haversine).toBe('function');
  });

  it('should calculate distance between New York and London accurately', () => {
    const haversine = getHaversineDistance();
    // NYC: 40.7128, -74.0060
    // London: 51.5074, -0.1278
    const distance = haversine(40.7128, -74.006, 51.5074, -0.1278);
    // Known distance: ~5570 km
    expect(distance).toBeGreaterThan(5500);
    expect(distance).toBeLessThan(5600);
  });

  it('should calculate distance between Tokyo and Sydney accurately', () => {
    const haversine = getHaversineDistance();
    // Tokyo: 35.6762, 139.6503
    // Sydney: -33.8688, 151.2093
    const distance = haversine(35.6762, 139.6503, -33.8688, 151.2093);
    // Known distance: ~7823 km
    expect(distance).toBeGreaterThan(7750);
    expect(distance).toBeLessThan(7900);
  });

  it('should return 0 for same point', () => {
    const haversine = getHaversineDistance();
    const distance = haversine(40.7128, -74.006, 40.7128, -74.006);
    expect(distance).toBe(0);
  });

  it('should calculate antipodal distance accurately', () => {
    const haversine = getHaversineDistance();
    // North Pole to South Pole
    const distance = haversine(90, 0, -90, 0);
    // Half earth circumference: ~20015 km
    expect(distance).toBeGreaterThan(20000);
    expect(distance).toBeLessThan(20100);
  });

  it('should use custom haversine when configured', () => {
    const customHaversine = (_lat1: number, _lon1: number, _lat2: number, _lon2: number) => 42;
    configureThreatDetection({ haversineDistance: customHaversine });

    const haversine = getHaversineDistance();
    expect(haversine(0, 0, 90, 180)).toBe(42);
  });

  it('should revert to default haversine after reset', () => {
    configureThreatDetection({
      haversineDistance: () => 42,
    });

    expect(getHaversineDistance()(0, 0, 90, 0)).toBe(42);

    resetThreatDetectionConfig();
    const distance = getHaversineDistance()(0, 0, 90, 0);
    expect(distance).toBeGreaterThan(9900);
    expect(distance).toBeLessThan(10100);
  });
});
