import FingerprintJS from '@fingerprintjs/fingerprintjs';
import type { DeviceFingerprint } from '~/types/fingerprint';

export async function generateDeviceFingerprint(): Promise<DeviceFingerprint> {
  try {
    const fp = await FingerprintJS.load();
    const result = await fp.get();
    
    return {
      visitorId: result.visitorId,
      confidence: result.confidence.score,
      components: result.components,
      timestamp: Date.now()
    };
  } catch (error) {
    console.error('Error generating device fingerprint:', error);
    // Fallback fingerprint
    return {
      visitorId: 'fallback-' + Math.random().toString(36).substr(2, 9),
      confidence: 0.1,
      components: {},
      timestamp: Date.now()
    };
  }
}

export function getDeviceInfo() {
  return {
    userAgent: navigator.userAgent,
    screenResolution: `${screen.width}x${screen.height}`,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: navigator.language,
    platform: navigator.platform,
    cookieEnabled: navigator.cookieEnabled,
    doNotTrack: navigator.doNotTrack,
    hardwareConcurrency: navigator.hardwareConcurrency,
    maxTouchPoints: navigator.maxTouchPoints,
    colorDepth: screen.colorDepth,
    pixelDepth: screen.pixelDepth
  };
}