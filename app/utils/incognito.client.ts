import type { IncognitoDetection } from '~/types/fingerprint';

export async function detectIncognito(): Promise<IncognitoDetection> {
  const tests: Array<() => Promise<{ isIncognito: boolean; method: string; details: any }>> = [
    testQuotaAPI,
    testRequestFileSystem,
    testIndexedDB,
    testLocalStorage,
    testWebRTC,
    testBatteryAPI,
    testPermissions
  ];

  const results = await Promise.allSettled(tests.map(test => test()));
  const validResults = results
    .filter((result): result is PromiseFulfilledResult<any> => result.status === 'fulfilled')
    .map(result => result.value);

  const incognitoCount = validResults.filter(r => r.isIncognito).length;
  const totalTests = validResults.length;
  const confidence = totalTests > 0 ? incognitoCount / totalTests : 0;

  return {
    isIncognito: confidence > 0.5,
    confidence,
    method: 'multi-test',
    details: {
      tests: validResults,
      incognitoCount,
      totalTests
    }
  };
}

async function testQuotaAPI(): Promise<{ isIncognito: boolean; method: string; details: any }> {
  try {
    const estimate = await navigator.storage.estimate();
    const quota = estimate.quota || 0;
    // In incognito mode, quota is typically much smaller
    const isIncognito = quota < 120000000; // Less than ~120MB
    
    return {
      isIncognito,
      method: 'quota-api',
      details: { quota, usage: estimate.usage }
    };
  } catch (error) {
    return {
      isIncognito: false,
      method: 'quota-api',
      details: { error: error instanceof Error ? error.message : 'Unknown error' }
    };
  }
}

async function testRequestFileSystem(): Promise<{ isIncognito: boolean; method: string; details: any }> {
  return new Promise((resolve) => {
    const webkitRequestFileSystem = (window as any).webkitRequestFileSystem || (window as any).requestFileSystem;
    
    if (!webkitRequestFileSystem) {
      resolve({
        isIncognito: false,
        method: 'filesystem-api',
        details: { supported: false }
      });
      return;
    }

    webkitRequestFileSystem(
      0, // TEMPORARY
      1,
      () => resolve({
        isIncognito: false,
        method: 'filesystem-api',
        details: { granted: true }
      }),
      () => resolve({
        isIncognito: true,
        method: 'filesystem-api',
        details: { granted: false }
      })
    );
  });
}

async function testIndexedDB(): Promise<{ isIncognito: boolean; method: string; details: any }> {
  return new Promise((resolve) => {
    try {
      const db = indexedDB.open('test', 1);
      db.onerror = () => resolve({
        isIncognito: true,
        method: 'indexeddb',
        details: { accessible: false }
      });
      db.onsuccess = () => {
        db.result.close();
        resolve({
          isIncognito: false,
          method: 'indexeddb',
          details: { accessible: true }
        });
      };
    } catch (error) {
      resolve({
        isIncognito: true,
        method: 'indexeddb',
        details: { error: error instanceof Error ? error.message : 'Unknown error' }
      });
    }
  });
}

async function testLocalStorage(): Promise<{ isIncognito: boolean; method: string; details: any }> {
  try {
    const testKey = 'incognito-test';
    localStorage.setItem(testKey, 'test');
    localStorage.removeItem(testKey);
    
    return {
      isIncognito: false,
      method: 'localstorage',
      details: { accessible: true }
    };
  } catch (error) {
    return {
      isIncognito: true,
      method: 'localstorage',
      details: { accessible: false, error: error instanceof Error ? error.message : 'Unknown error' }
    };
  }
}

async function testWebRTC(): Promise<{ isIncognito: boolean; method: string; details: any }> {
  return new Promise((resolve) => {
    try {
      const pc = new RTCPeerConnection();
      pc.createDataChannel('test');
      
      pc.createOffer().then(() => {
        resolve({
          isIncognito: false,
          method: 'webrtc',
          details: { supported: true }
        });
      }).catch(() => {
        resolve({
          isIncognito: true,
          method: 'webrtc',
          details: { supported: false }
        });
      });
    } catch (error) {
      resolve({
        isIncognito: false,
        method: 'webrtc',
        details: { error: error instanceof Error ? error.message : 'Unknown error' }
      });
    }
  });
}

async function testBatteryAPI(): Promise<{ isIncognito: boolean; method: string; details: any }> {
  try {
    const battery = await (navigator as any).getBattery?.();
    return {
      isIncognito: !battery,
      method: 'battery-api',
      details: { supported: !!battery }
    };
  } catch (error) {
    return {
      isIncognito: true,
      method: 'battery-api',
      details: { supported: false }
    };
  }
}

async function testPermissions(): Promise<{ isIncognito: boolean; method: string; details: any }> {
  try {
    const result = await navigator.permissions.query({ name: 'notifications' as PermissionName });
    // In some browsers, permissions behave differently in incognito
    return {
      isIncognito: false,
      method: 'permissions',
      details: { state: result.state }
    };
  } catch (error) {
    return {
      isIncognito: false,
      method: 'permissions',
      details: { error: error instanceof Error ? error.message : 'Unknown error' }
    };
  }
}