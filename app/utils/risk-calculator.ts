import type { FingerprintSession } from '~/types/fingerprint';
import { getDeviceCount, getIPCount } from './storage.client';

export function calculateRiskScore(session: Omit<FingerprintSession, 'riskScore' | 'riskLevel'>): { riskScore: number; riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' } {
  let score = 0;
  const riskFactors: string[] = [];
  
  // Device fingerprint confidence (lower confidence = higher risk)
  const fpConfidence = session.deviceFingerprint.confidence;
  if (fpConfidence < 0.3) {
    score += 40;
    riskFactors.push('very-low-fingerprint-confidence');
  } else if (fpConfidence < 0.5) {
    score += 25;
    riskFactors.push('low-fingerprint-confidence');
  } else if (fpConfidence < 0.7) {
    score += 10;
    riskFactors.push('medium-fingerprint-confidence');
  }
  
  // Incognito mode detection (major red flag for SaaS abuse)
  if (session.incognitoDetection.isIncognito) {
    const confidence = session.incognitoDetection.confidence;
    if (confidence > 0.8) {
      score += 35;
      riskFactors.push('confirmed-incognito');
    } else if (confidence > 0.5) {
      score += 25;
      riskFactors.push('likely-incognito');
    } else {
      score += 15;
      riskFactors.push('possible-incognito');
    }
  }
  
  // IP analysis - Critical for SaaS protection
  if (session.ipAnalysis) {
    const ipRisk = session.ipAnalysis.riskScore;
    score += ipRisk * 0.4; // Scale IP risk appropriately
    
    // VPN Detection - High priority for SaaS abuse prevention
    if (session.ipAnalysis.isVPN) {
      score += 30;
      riskFactors.push('vpn-detected');
    }
    
    // Tor Detection - Critical threat
    if (session.ipAnalysis.isTor) {
      score += 50;
      riskFactors.push('tor-detected');
    }
    
    // Proxy Detection
    if (session.ipAnalysis.isProxy) {
      score += 20;
      riskFactors.push('proxy-detected');
    }
    
    // Threat type analysis
    const threats = session.ipAnalysis.threatTypes;
    if (threats.includes('hosting-provider')) {
      score += 15;
      riskFactors.push('hosting-provider');
    }
    if (threats.includes('known-vpn')) {
      score += 25;
      riskFactors.push('known-vpn-service');
    }
    if (threats.includes('blacklisted')) {
      score += 40;
      riskFactors.push('blacklisted-ip');
    }
    if (threats.includes('high-risk')) {
      score += 30;
      riskFactors.push('high-risk-ip');
    }
  }
  
  // Behavior analysis - Key for detecting automated abuse
  const behavior = session.behaviorAnalysis;
  
  // Suspicious patterns (bots, automation)
  const suspiciousPatterns = behavior.suspiciousPatterns;
  score += suspiciousPatterns.length * 12;
  
  if (suspiciousPatterns.includes('inhuman-mouse-speed')) {
    score += 20;
    riskFactors.push('bot-like-mouse-movement');
  }
  if (suspiciousPatterns.includes('inhuman-typing-speed')) {
    score += 25;
    riskFactors.push('bot-like-typing');
  }
  if (suspiciousPatterns.includes('consistent-keystroke-timing')) {
    score += 30;
    riskFactors.push('automated-input');
  }
  if (suspiciousPatterns.includes('straight-mouse-lines')) {
    score += 15;
    riskFactors.push('scripted-mouse-movement');
  }
  
  // Interaction speed analysis
  const interactionSpeed = behavior.interactionSpeed;
  if (interactionSpeed > 2000) {
    score += 25;
    riskFactors.push('superhuman-interaction-speed');
  } else if (interactionSpeed > 1000) {
    score += 15;
    riskFactors.push('very-fast-interactions');
  }
  
  // Time on page vs interactions (rapid fire abuse detection)
  const timeOnPage = behavior.timeOnPage;
  const totalInteractions = behavior.mouseMovements + behavior.keystrokes + behavior.scrollEvents;
  
  if (timeOnPage < 3000 && totalInteractions > 100) {
    score += 35;
    riskFactors.push('rapid-fire-interactions');
  } else if (timeOnPage < 5000 && totalInteractions > 50) {
    score += 20;
    riskFactors.push('fast-interaction-burst');
  }
  
  // Lack of human-like behavior
  if (timeOnPage > 30000 && totalInteractions < 5) {
    score += 20;
    riskFactors.push('minimal-interaction');
  }
  
  // Historical data analysis (repeat offenders)
  try {
    const deviceId = session.deviceFingerprint.visitorId;
    const deviceCount = getDeviceCount(deviceId);
    
    if (deviceCount > 20) {
      score += 25;
      riskFactors.push('frequent-device-reuse');
    } else if (deviceCount > 10) {
      score += 15;
      riskFactors.push('repeated-device-usage');
    }
    
    if (session.ipAnalysis) {
      const ipCount = getIPCount(session.ipAnalysis.ip);
      if (ipCount > 50) {
        score += 30;
        riskFactors.push('ip-abuse-pattern');
      } else if (ipCount > 20) {
        score += 20;
        riskFactors.push('frequent-ip-usage');
      }
    }
  } catch (error) {
    // Ignore storage errors in demo
  }
  
  // Browser/User Agent analysis
  const ua = session.userAgent.toLowerCase();
  
  // Headless browser detection (major red flag)
  if (ua.includes('headless') || ua.includes('phantom') || ua.includes('selenium') || ua.includes('chromedriver')) {
    score += 60;
    riskFactors.push('headless-browser');
  }
  
  // Automation tools
  if (ua.includes('puppeteer') || ua.includes('playwright') || ua.includes('webdriver')) {
    score += 55;
    riskFactors.push('automation-tool');
  }
  
  // Suspicious user agents
  if (ua.includes('bot') || ua.includes('crawler') || ua.includes('spider')) {
    score += 40;
    riskFactors.push('bot-user-agent');
  }
  
  // Very old or unusual browsers
  if (ua.includes('msie') || ua.includes('internet explorer')) {
    score += 10;
    riskFactors.push('outdated-browser');
  }
  
  // Device consistency checks
  const screenRes = session.screenResolution;
  if (screenRes === '0x0' || screenRes === '1x1') {
    score += 45;
    riskFactors.push('invalid-screen-resolution');
  }
  
  // Timezone consistency (basic check)
  const timezone = session.timezone;
  if (!timezone || timezone === 'UTC') {
    score += 10;
    riskFactors.push('suspicious-timezone');
  }
  
  // Language consistency
  const language = session.language;
  if (!language || language === 'en' || language === 'en-US') {
    // Default languages are slightly suspicious but common
    score += 2;
  }
  
  // Ensure score is within bounds
  score = Math.max(0, Math.min(100, Math.round(score)));
  
  // Determine risk level with SaaS-focused thresholds
  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  if (score >= 85) {
    riskLevel = 'CRITICAL'; // Block immediately
  } else if (score >= 65) {
    riskLevel = 'HIGH'; // Require additional verification
  } else if (score >= 35) {
    riskLevel = 'MEDIUM'; // Monitor closely
  } else {
    riskLevel = 'LOW'; // Allow with normal monitoring
  }
  
  return { riskScore: score, riskLevel };
}

// Helper function to get risk recommendations for SaaS protection
export function getRiskRecommendations(riskLevel: string, riskScore: number): string[] {
  const recommendations: string[] = [];
  
  switch (riskLevel) {
    case 'CRITICAL':
      recommendations.push('🚫 Block access immediately');
      recommendations.push('🔒 Require phone verification');
      recommendations.push('📧 Send security alert to admins');
      recommendations.push('🕐 Implement temporary IP ban');
      break;
      
    case 'HIGH':
      recommendations.push('⚠️ Require additional verification');
      recommendations.push('📱 Request SMS verification');
      recommendations.push('🔍 Enable enhanced monitoring');
      recommendations.push('⏱️ Rate limit API requests');
      break;
      
    case 'MEDIUM':
      recommendations.push('👀 Monitor user behavior closely');
      recommendations.push('📊 Track usage patterns');
      recommendations.push('🔔 Set up alerts for unusual activity');
      recommendations.push('⏳ Implement soft rate limiting');
      break;
      
    case 'LOW':
      recommendations.push('✅ Allow normal access');
      recommendations.push('📈 Continue standard monitoring');
      break;
  }
  
  return recommendations;
}