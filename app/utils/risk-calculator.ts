import type { FingerprintSession } from '~/types/fingerprint';
import { getDeviceCount, getIPCount } from './storage.client';

export function calculateRiskScore(session: Omit<FingerprintSession, 'riskScore' | 'riskLevel'>): { riskScore: number; riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' } {
  let score = 0;
  
  // Device fingerprint confidence (lower confidence = higher risk)
  const fpConfidence = session.deviceFingerprint.confidence;
  if (fpConfidence < 0.5) score += 30;
  else if (fpConfidence < 0.7) score += 15;
  
  // Incognito mode detection
  if (session.incognitoDetection.isIncognito) {
    score += 25;
  }
  
  // IP analysis
  if (session.ipAnalysis) {
    score += session.ipAnalysis.riskScore * 0.3; // Scale down IP risk
    if (session.ipAnalysis.isVPN) score += 20;
    if (session.ipAnalysis.isTor) score += 40;
    if (session.ipAnalysis.isProxy) score += 15;
  }
  
  // Behavior analysis
  const behavior = session.behaviorAnalysis;
  
  // Suspicious patterns
  score += behavior.suspiciousPatterns.length * 10;
  
  // Interaction speed (too fast or too slow is suspicious)
  if (behavior.interactionSpeed > 1000) score += 20; // Too fast
  if (behavior.interactionSpeed < 10 && behavior.timeOnPage > 30000) score += 15; // Too slow
  
  // Time on page (very short time with many interactions is suspicious)
  if (behavior.timeOnPage < 5000 && (behavior.mouseMovements + behavior.keystrokes) > 50) {
    score += 25;
  }
  
  // Historical data (if available in client-side context)
  try {
    const deviceCount = getDeviceCount(session.deviceFingerprint.visitorId);
    if (deviceCount > 5) score += 10; // Frequent visitor
    
    if (session.ipAnalysis) {
      const ipCount = getIPCount(session.ipAnalysis.ip);
      if (ipCount > 10) score += 15; // IP used frequently
    }
  } catch (error) {
    // Ignore storage errors
  }
  
  // Browser/device inconsistencies
  const ua = session.userAgent.toLowerCase();
  if (ua.includes('headless') || ua.includes('phantom') || ua.includes('selenium')) {
    score += 50;
  }
  
  // Ensure score is within bounds
  score = Math.max(0, Math.min(100, score));
  
  // Determine risk level
  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  if (score >= 80) riskLevel = 'CRITICAL';
  else if (score >= 60) riskLevel = 'HIGH';
  else if (score >= 30) riskLevel = 'MEDIUM';
  else riskLevel = 'LOW';
  
  return { riskScore: score, riskLevel };
}