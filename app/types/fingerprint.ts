export interface DeviceFingerprint {
  visitorId: string;
  confidence: number;
  components: Record<string, any>;
  timestamp: number;
}

export interface IncognitoDetection {
  isIncognito: boolean;
  confidence: number;
  method: string;
  details: Record<string, any>;
}

export interface IPAnalysis {
  ip: string;
  country: string;
  region: string;
  city: string;
  isp: string;
  isVPN: boolean;
  isTor: boolean;
  isProxy: boolean;
  riskScore: number;
  threatTypes: string[];
}

export interface BehaviorAnalysis {
  mouseMovements: number;
  keystrokes: number;
  scrollEvents: number;
  timeOnPage: number;
  interactionSpeed: number;
  suspiciousPatterns: string[];
}

export interface FingerprintSession {
  id: string;
  deviceFingerprint: DeviceFingerprint;
  incognitoDetection: IncognitoDetection;
  ipAnalysis: IPAnalysis | null;
  behaviorAnalysis: BehaviorAnalysis;
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  timestamp: number;
  userAgent: string;
  screenResolution: string;
  timezone: string;
  language: string;
}

export interface StoredFingerprints {
  sessions: FingerprintSession[];
  deviceHistory: Record<string, number>;
  ipHistory: Record<string, number>;
  lastUpdated: number;
}