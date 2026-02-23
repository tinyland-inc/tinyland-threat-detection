









import type {
  LokiQueryResult,
  PrometheusQueryResult,
  FingerprintRecord,
} from './types.js';









export interface ThreatDetectionLogger {
  info: (msg: string, meta?: Record<string, unknown>) => void;
  warn: (msg: string, meta?: Record<string, unknown>) => void;
  error: (msg: string, meta?: Record<string, unknown>) => void;
  debug: (msg: string, meta?: Record<string, unknown>) => void;
}





















export interface LokiBackend {
  query: (logql: string, params?: {
    start?: string;
    end?: string;
    limit?: number;
  }) => Promise<LokiQueryResult>;
}






















export interface PrometheusBackend {
  query: (promql: string, params?: {
    time?: string;
  }) => Promise<PrometheusQueryResult>;
  queryRange: (promql: string, params: {
    start: string;
    end: string;
    step: string;
  }) => Promise<PrometheusQueryResult>;
}



















export interface FingerprintQueryBackend {
  queryFingerprints: (
    timeRange: string,
    tags?: Record<string, string>,
    limit?: number,
  ) => Promise<FingerprintRecord[]>;
}









export interface ObservabilityConfig {
  lokiUrl?: string;
  prometheusUrl?: string;
  tempoUrl?: string;
}

























export interface ThreatDetectionConfig {
  logger?: ThreatDetectionLogger;
  loki?: LokiBackend;
  prometheus?: PrometheusBackend;
  fingerprintQuery?: FingerprintQueryBackend;
  observabilityConfig?: ObservabilityConfig;
  
  haversineDistance?: (lat1: number, lon1: number, lat2: number, lon2: number) => number;
}





const noopLogger: ThreatDetectionLogger = {
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {},
};

let config: ThreatDetectionConfig = {};



















export function configureThreatDetection(c: ThreatDetectionConfig): void {
  config = { ...config, ...c };
}




export function getThreatDetectionConfig(): ThreatDetectionConfig {
  return config;
}





export function resetThreatDetectionConfig(): void {
  config = {};
}




export function getLogger(): ThreatDetectionLogger {
  return config.logger ?? noopLogger;
}

















function defaultHaversine(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371; 
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}




export function getHaversineDistance(): (lat1: number, lon1: number, lat2: number, lon2: number) => number {
  return config.haversineDistance ?? defaultHaversine;
}
