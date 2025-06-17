import type { IPAnalysis } from '~/types/fingerprint';

export async function analyzeIP(): Promise<IPAnalysis | null> {
  try {
    // Get user's IP address from multiple sources for reliability
    const ip = await getClientIP();
    if (!ip) return null;

    // Run multiple VPN/proxy detection services in parallel
    const [geoData, vpnData, additionalChecks] = await Promise.allSettled([
      getGeoLocation(ip),
      checkVPNStatus(ip),
      performAdditionalSecurityChecks(ip)
    ]);

    const geo = geoData.status === 'fulfilled' ? geoData.value : null;
    const vpn = vpnData.status === 'fulfilled' ? vpnData.value : null;
    const security = additionalChecks.status === 'fulfilled' ? additionalChecks.value : null;

    // Combine all threat indicators
    const combinedThreats = [
      ...(vpn?.threatTypes || []),
      ...(security?.threatTypes || [])
    ];

    return {
      ip,
      country: geo?.country || 'Unknown',
      region: geo?.region || 'Unknown',
      city: geo?.city || 'Unknown',
      isp: geo?.isp || 'Unknown',
      isVPN: vpn?.isVPN || security?.isVPN || false,
      isTor: vpn?.isTor || security?.isTor || false,
      isProxy: vpn?.isProxy || security?.isProxy || false,
      riskScore: calculateCombinedRiskScore(vpn, security, geo),
      threatTypes: [...new Set(combinedThreats)] // Remove duplicates
    };
  } catch (error) {
    console.error('Error analyzing IP:', error);
    return null;
  }
}

async function getClientIP(): Promise<string | null> {
  const ipServices = [
    'https://api.ipify.org?format=json',
    'https://ipapi.co/json/',
    'https://api.ip.sb/jsonip',
    'https://httpbin.org/ip'
  ];

  for (const service of ipServices) {
    try {
      const response = await fetch(service, { timeout: 5000 } as any);
      const data = await response.json();
      
      // Different services return IP in different formats
      const ip = data.ip || data.query || data.origin;
      if (ip && isValidIP(ip)) {
        return ip;
      }
    } catch (error) {
      continue; // Try next service
    }
  }
  
  return null;
}

function isValidIP(ip: string): boolean {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

async function getGeoLocation(ip: string) {
  const geoServices = [
    {
      url: `http://ip-api.com/json/${ip}?fields=status,country,regionName,city,isp,org,as,query,proxy,hosting`,
      parser: (data: any) => ({
        country: data.country,
        region: data.regionName,
        city: data.city,
        isp: data.isp,
        org: data.org,
        as: data.as,
        isHosting: data.hosting,
        isProxy: data.proxy
      })
    },
    {
      url: `https://ipapi.co/${ip}/json/`,
      parser: (data: any) => ({
        country: data.country_name,
        region: data.region,
        city: data.city,
        isp: data.org,
        org: data.org,
        as: data.asn
      })
    }
  ];

  for (const service of geoServices) {
    try {
      const response = await fetch(service.url);
      const data = await response.json();
      
      if (data.status !== 'fail' && !data.error) {
        return service.parser(data);
      }
    } catch (error) {
      continue;
    }
  }
  
  throw new Error('All geo services failed');
}

async function checkVPNStatus(ip: string) {
  const vpnServices = [
    {
      name: 'proxycheck',
      check: () => checkProxyCheckIO(ip)
    },
    {
      name: 'vpnapi',
      check: () => checkVPNAPI(ip)
    },
    {
      name: 'iphub',
      check: () => checkIPHub(ip)
    }
  ];

  const results = await Promise.allSettled(
    vpnServices.map(service => service.check())
  );

  // Combine results from multiple services
  const validResults = results
    .filter((result): result is PromiseFulfilledResult<any> => result.status === 'fulfilled')
    .map(result => result.value);

  if (validResults.length === 0) {
    return checkVPNHeuristics(ip);
  }

  // Aggregate results
  const isVPN = validResults.some(r => r.isVPN);
  const isTor = validResults.some(r => r.isTor);
  const isProxy = validResults.some(r => r.isProxy);
  const avgRisk = validResults.reduce((sum, r) => sum + (r.riskScore || 0), 0) / validResults.length;
  
  const allThreats = validResults.flatMap(r => r.threatTypes || []);
  const threatTypes = [...new Set(allThreats)];

  return {
    isVPN,
    isTor,
    isProxy,
    riskScore: Math.round(avgRisk),
    threatTypes,
    sources: validResults.length
  };
}

async function checkProxyCheckIO(ip: string) {
  try {
    const response = await fetch(
      `https://proxycheck.io/v2/${ip}?vpn=1&asn=1&risk=1&port=1&seen=1&days=7&tag=saas-protection`,
      { timeout: 8000 } as any
    );
    const data = await response.json();
    
    const ipData = data[ip];
    if (ipData && ipData.status === 'ok') {
      const threatTypes = [];
      if (ipData.proxy === 'yes') threatTypes.push('proxy');
      if (ipData.type === 'VPN') threatTypes.push('vpn');
      if (ipData.type === 'TOR') threatTypes.push('tor');
      if (ipData.risk > 75) threatTypes.push('high-risk');
      
      return {
        isVPN: ipData.type === 'VPN',
        isTor: ipData.type === 'TOR',
        isProxy: ipData.proxy === 'yes',
        riskScore: ipData.risk || 0,
        threatTypes,
        provider: ipData.provider,
        asn: ipData.asn,
        lastSeen: ipData.seen
      };
    }
    
    return { isVPN: false, isTor: false, isProxy: false, riskScore: 0, threatTypes: [] };
  } catch (error) {
    throw new Error('ProxyCheck.io failed');
  }
}

async function checkVPNAPI(ip: string) {
  try {
    // Using vpnapi.io (free tier available)
    const response = await fetch(`https://vpnapi.io/api/${ip}?key=free`, { timeout: 6000 } as any);
    const data = await response.json();
    
    if (data.security) {
      const threatTypes = [];
      if (data.security.vpn) threatTypes.push('vpn');
      if (data.security.tor) threatTypes.push('tor');
      if (data.security.proxy) threatTypes.push('proxy');
      if (data.security.anonymous) threatTypes.push('anonymous');
      if (data.security.threat) threatTypes.push('threat');
      
      return {
        isVPN: data.security.vpn,
        isTor: data.security.tor,
        isProxy: data.security.proxy,
        riskScore: data.security.threat ? 80 : (data.security.vpn ? 60 : 0),
        threatTypes
      };
    }
    
    return { isVPN: false, isTor: false, isProxy: false, riskScore: 0, threatTypes: [] };
  } catch (error) {
    throw new Error('VPNAPI failed');
  }
}

async function checkIPHub(ip: string) {
  try {
    // IPHub.info - requires API key but has free tier
    const response = await fetch(`http://v2.api.iphub.info/ip/${ip}`, {
      headers: { 'X-Key': 'free' }, // Use 'free' for limited free tier
      timeout: 6000
    } as any);
    const data = await response.json();
    
    const threatTypes = [];
    const block = data.block;
    
    if (block === 1) threatTypes.push('vpn', 'proxy');
    if (block === 2) threatTypes.push('tor');
    if (data.hostname && data.hostname.includes('vpn')) threatTypes.push('vpn');
    
    return {
      isVPN: block === 1,
      isTor: block === 2,
      isProxy: block === 1,
      riskScore: block > 0 ? 70 : 0,
      threatTypes,
      countryCode: data.countryCode,
      isp: data.isp
    };
  } catch (error) {
    throw new Error('IPHub failed');
  }
}

async function performAdditionalSecurityChecks(ip: string) {
  const checks = await Promise.allSettled([
    checkDNSBlacklists(ip),
    checkKnownVPNRanges(ip),
    checkHostingProviders(ip),
    checkReputationDatabases(ip)
  ]);

  const results = checks
    .filter((check): check is PromiseFulfilledResult<any> => check.status === 'fulfilled')
    .map(check => check.value);

  const threatTypes = results.flatMap(r => r.threatTypes || []);
  const isVPN = results.some(r => r.isVPN);
  const isTor = results.some(r => r.isTor);
  const isProxy = results.some(r => r.isProxy);
  const maxRisk = Math.max(...results.map(r => r.riskScore || 0));

  return {
    isVPN,
    isTor,
    isProxy,
    riskScore: maxRisk,
    threatTypes: [...new Set(threatTypes)]
  };
}

async function checkDNSBlacklists(ip: string) {
  // Check against known DNS blacklists
  const blacklists = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'dnsbl.sorbs.net'
  ];

  const threatTypes = [];
  let riskScore = 0;

  // This is a simplified check - in production you'd use proper DNS queries
  // For demo purposes, we'll use pattern matching
  if (isKnownBadIP(ip)) {
    threatTypes.push('blacklisted');
    riskScore = 90;
  }

  return {
    isVPN: false,
    isTor: false,
    isProxy: false,
    riskScore,
    threatTypes
  };
}

async function checkKnownVPNRanges(ip: string) {
  // Check against known VPN IP ranges
  const knownVPNPatterns = [
    /^185\.159\./, // NordVPN
    /^103\.231\./, // ExpressVPN
    /^146\.70\./, // Surfshark
    /^89\.187\./, // CyberGhost
    /^195\.181\./, // ProtonVPN
  ];

  const isKnownVPN = knownVPNPatterns.some(pattern => pattern.test(ip));
  
  return {
    isVPN: isKnownVPN,
    isTor: false,
    isProxy: false,
    riskScore: isKnownVPN ? 75 : 0,
    threatTypes: isKnownVPN ? ['known-vpn'] : []
  };
}

async function checkHostingProviders(ip: string) {
  // Check if IP belongs to hosting/cloud providers (often used for abuse)
  const hostingPatterns = [
    /^54\./, // AWS
    /^34\./, // Google Cloud
    /^40\./, // Azure
    /^167\.172\./, // DigitalOcean
    /^159\.89\./, // DigitalOcean
    /^138\.197\./, // DigitalOcean
  ];

  const isHosting = hostingPatterns.some(pattern => pattern.test(ip));
  
  return {
    isVPN: false,
    isTor: false,
    isProxy: false,
    riskScore: isHosting ? 30 : 0,
    threatTypes: isHosting ? ['hosting-provider'] : []
  };
}

async function checkReputationDatabases(ip: string) {
  // Simplified reputation check
  const suspiciousPatterns = [
    /^10\./, // Private ranges (shouldn't appear as public)
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, 
    /^192\.168\./,
    /^169\.254\./, // Link-local
    /^127\./, // Loopback
  ];

  const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(ip));
  
  return {
    isVPN: false,
    isTor: false,
    isProxy: isSuspicious,
    riskScore: isSuspicious ? 50 : 0,
    threatTypes: isSuspicious ? ['private-ip', 'suspicious'] : []
  };
}

function checkVPNHeuristics(ip: string) {
  // Enhanced heuristics for VPN detection
  const vpnIndicators = [];
  let riskScore = 0;

  // Check for common VPN IP patterns
  if (/^(10|172|192\.168)\./.test(ip)) {
    vpnIndicators.push('private-ip');
    riskScore += 40;
  }

  // Check for sequential IP patterns (common in VPN pools)
  const octets = ip.split('.').map(Number);
  if (octets.length === 4 && octets[3] % 10 === 0) {
    vpnIndicators.push('sequential-pattern');
    riskScore += 20;
  }

  return {
    isVPN: riskScore > 30,
    isTor: false,
    isProxy: riskScore > 20,
    riskScore,
    threatTypes: vpnIndicators
  };
}

function calculateCombinedRiskScore(vpnData: any, securityData: any, geoData: any): number {
  let score = 0;
  
  // VPN/Proxy detection
  if (vpnData?.isVPN) score += 50;
  if (vpnData?.isTor) score += 80;
  if (vpnData?.isProxy) score += 40;
  
  // Security checks
  if (securityData?.isVPN) score += 30;
  if (securityData?.isTor) score += 60;
  if (securityData?.isProxy) score += 25;
  
  // Base risk scores
  score += (vpnData?.riskScore || 0) * 0.6;
  score += (securityData?.riskScore || 0) * 0.4;
  
  // Geographic risk factors
  if (geoData?.isHosting) score += 20;
  
  // High-risk countries (simplified list)
  const highRiskCountries = ['Unknown', 'Anonymous'];
  if (highRiskCountries.includes(geoData?.country)) {
    score += 30;
  }
  
  return Math.min(Math.round(score), 100);
}

function isKnownBadIP(ip: string): boolean {
  // Simplified bad IP detection
  const badPatterns = [
    /^0\./, // Invalid
    /^255\./, // Broadcast
    /^224\./, // Multicast
  ];
  
  return badPatterns.some(pattern => pattern.test(ip));
}