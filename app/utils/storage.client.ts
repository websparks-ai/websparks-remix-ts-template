import type { FingerprintSession, StoredFingerprints } from '~/types/fingerprint';

const STORAGE_KEY = 'fingerprint-demo-data';

export function getStoredFingerprints(): StoredFingerprints {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      return JSON.parse(stored);
    }
  } catch (error) {
    console.error('Error reading stored fingerprints:', error);
  }
  
  return {
    sessions: [],
    deviceHistory: {},
    ipHistory: {},
    lastUpdated: Date.now()
  };
}

export function saveFingerprint(session: FingerprintSession): void {
  try {
    const stored = getStoredFingerprints();
    
    // Add new session
    stored.sessions.unshift(session);
    
    // Keep only last 50 sessions
    if (stored.sessions.length > 50) {
      stored.sessions = stored.sessions.slice(0, 50);
    }
    
    // Update device history
    const deviceId = session.deviceFingerprint.visitorId;
    stored.deviceHistory[deviceId] = (stored.deviceHistory[deviceId] || 0) + 1;
    
    // Update IP history
    if (session.ipAnalysis) {
      const ip = session.ipAnalysis.ip;
      stored.ipHistory[ip] = (stored.ipHistory[ip] || 0) + 1;
    }
    
    stored.lastUpdated = Date.now();
    
    localStorage.setItem(STORAGE_KEY, JSON.stringify(stored));
  } catch (error) {
    console.error('Error saving fingerprint:', error);
  }
}

export function clearStoredFingerprints(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (error) {
    console.error('Error clearing stored fingerprints:', error);
  }
}

export function getDeviceCount(deviceId: string): number {
  const stored = getStoredFingerprints();
  return stored.deviceHistory[deviceId] || 0;
}

export function getIPCount(ip: string): number {
  const stored = getStoredFingerprints();
  return stored.ipHistory[ip] || 0;
}