import type { IPAnalysis } from '~/types/fingerprint';

export async function analyzeIP(): Promise<IPAnalysis | null> {
  try {
    // Get user's IP address
    const ipResponse = await fetch('https://api.ipify.org?format=json');
    const { ip } = await ipResponse.json();

    // Analyze IP using multiple free services
    const [geoData, vpnData] = await Promise.allSettled([
      getGeoLocation(ip),
      checkVPNStatus(ip)
    ]);

    const geo = geoData.status === 'fulfilled' ? geoData.value : null;
    const vpn = vpnData.status === 'fulfilled' ? vpnData.value : null;

    return {
      ip,
      country: geo?.country || 'Unknown',
      region: geo?.region || 'Unknown',
      city: geo?.city || 'Unknown',
      isp: geo?.isp || 'Unknown',
      isVPN: vpn?.isVPN || false,
      isTor: vpn?.isTor || false,
      isProxy: vpn?.isProxy || false,
      riskScore: calculateRiskScore(vpn),
      threatTypes: vpn?.threatTypes || []
    };
  } catch (error) {
    console.error('Error analyzing IP:', error);
    return null;
  }
}

async function getGeoLocation(ip: string) {
  try {
    // Using ip-api.com (free tier: 1000 requests/month)
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city,isp,org,as,query`);
    const data = await response.json();
    
    if (data.status === 'success') {
      return {
        country: data.country,
        region: data.regionName,
        city: data.city,
        isp: data.isp,
        org: data.org,
        as: data.as
      };
    }
    throw new Error('Geo location failed');
  } catch (error) {
    // Fallback to ipapi.co
    try {
      const response = await fetch(`https://ipapi.co/${ip}/json/`);
      const data = await response.json();
      return {
        country: data.country_name,
        region: data.region,
        city: data.city,
        isp: data.org,
        org: data.org,
        as: data.asn
      };
    } catch (fallbackError) {
      throw new Error('All geo services failed');
    }
  }
}

async function checkVPNStatus(ip: string) {
  try {
    // Using proxycheck.io (free tier: 1000 requests/day)
    const response = await fetch(`https://proxycheck.io/v2/${ip}?vpn=1&asn=1&risk=1&port=1&seen=1&days=7&tag=demo`);
    const data = await response.json();
    
    const ipData = data[ip];
    if (ipData) {
      const threatTypes = [];
      if (ipData.proxy === 'yes') threatTypes.push('proxy');
      if (ipData.type === 'VPN') threatTypes.push('vpn');
      if (ipData.type === 'TOR') threatTypes.push('tor');
      
      return {
        isVPN: ipData.type === 'VPN',
        isTor: ipData.type === 'TOR',
        isProxy: ipData.proxy === 'yes',
        riskScore: ipData.risk || 0,
        threatTypes,
        provider: ipData.provider,
        asn: ipData.asn
      };
    }
    
    return {
      isVPN: false,
      isTor: false,
      isProxy: false,
      riskScore: 0,
      threatTypes: []
    };
  } catch (error) {
    // Fallback: simple heuristics
    return checkVPNHeuristics(ip);
  }
}

function checkVPNHeuristics(ip: string) {
  // Simple heuristics for common VPN/proxy patterns
  const vpnPatterns = [
    /^10\./, // Private IP ranges
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, 
    /^192\.168\./,
    /^169\.254\./ // Link-local
  ];
  
  const isPrivateIP = vpnPatterns.some(pattern => pattern.test(ip));
  
  return {
    isVPN: false,
    isTor: false,
    isProxy: isPrivateIP,
    riskScore: isPrivateIP ? 30 : 0,
    threatTypes: isPrivateIP ? ['private-ip'] : []
  };
}

function calculateRiskScore(vpnData: any): number {
  if (!vpnData) return 0;
  
  let score = vpnData.riskScore || 0;
  
  if (vpnData.isVPN) score += 40;
  if (vpnData.isTor) score += 80;
  if (vpnData.isProxy) score += 30;
  
  return Math.min(score, 100);
}