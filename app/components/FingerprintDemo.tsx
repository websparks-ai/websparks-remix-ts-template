import { useState, useEffect, useRef } from 'react';
import type { FingerprintSession } from '~/types/fingerprint';
import { generateDeviceFingerprint, getDeviceInfo } from '~/utils/fingerprint.client';
import { detectIncognito } from '~/utils/incognito.client';
import { analyzeIP } from '~/utils/ip-analysis.client';
import { BehaviorTracker } from '~/utils/behavior.client';
import { saveFingerprint, getStoredFingerprints, clearStoredFingerprints } from '~/utils/storage.client';
import { calculateRiskScore } from '~/utils/risk-calculator';

export default function FingerprintDemo() {
  const [currentSession, setCurrentSession] = useState<FingerprintSession | null>(null);
  const [sessions, setSessions] = useState<FingerprintSession[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'current' | 'history' | 'analysis'>('current');
  const behaviorTracker = useRef<BehaviorTracker | null>(null);

  useEffect(() => {
    // Initialize behavior tracker
    behaviorTracker.current = new BehaviorTracker();
    
    // Load stored sessions
    const stored = getStoredFingerprints();
    setSessions(stored.sessions);
    
    // Generate initial fingerprint
    generateFingerprint();
    
    return () => {
      // Cleanup is handled by the tracker itself
    };
  }, []);

  const generateFingerprint = async () => {
    setIsLoading(true);
    
    try {
      // Generate all fingerprint components
      const [deviceFingerprint, incognitoDetection, ipAnalysis] = await Promise.allSettled([
        generateDeviceFingerprint(),
        detectIncognito(),
        analyzeIP()
      ]);
      
      const deviceInfo = getDeviceInfo();
      const behaviorAnalysis = behaviorTracker.current?.getAnalysis() || {
        mouseMovements: 0,
        keystrokes: 0,
        scrollEvents: 0,
        timeOnPage: 0,
        interactionSpeed: 0,
        suspiciousPatterns: []
      };
      
      // Create session object
      const sessionData = {
        id: Math.random().toString(36).substr(2, 9),
        deviceFingerprint: deviceFingerprint.status === 'fulfilled' ? deviceFingerprint.value : {
          visitorId: 'error-' + Date.now(),
          confidence: 0,
          components: {},
          timestamp: Date.now()
        },
        incognitoDetection: incognitoDetection.status === 'fulfilled' ? incognitoDetection.value : {
          isIncognito: false,
          confidence: 0,
          method: 'error',
          details: {}
        },
        ipAnalysis: ipAnalysis.status === 'fulfilled' ? ipAnalysis.value : null,
        behaviorAnalysis,
        timestamp: Date.now(),
        userAgent: deviceInfo.userAgent,
        screenResolution: deviceInfo.screenResolution,
        timezone: deviceInfo.timezone,
        language: deviceInfo.language
      };
      
      // Calculate risk score
      const { riskScore, riskLevel } = calculateRiskScore(sessionData);
      
      const session: FingerprintSession = {
        ...sessionData,
        riskScore,
        riskLevel
      };
      
      setCurrentSession(session);
      
      // Save to storage
      saveFingerprint(session);
      
      // Update sessions list
      const updated = getStoredFingerprints();
      setSessions(updated.sessions);
      
    } catch (error) {
      console.error('Error generating fingerprint:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const clearHistory = () => {
    clearStoredFingerprints();
    setSessions([]);
  };

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'LOW': return 'text-green-600 bg-green-100';
      case 'MEDIUM': return 'text-yellow-600 bg-yellow-100';
      case 'HIGH': return 'text-orange-600 bg-orange-100';
      case 'CRITICAL': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const formatTimestamp = (timestamp: number) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Advanced Device Fingerprinting Demo
          </h1>
          <p className="text-lg text-gray-600 max-w-3xl mx-auto">
            This demo combines device fingerprinting, incognito detection, IP analysis, and behavior tracking 
            to create a comprehensive fraud detection system with ~85-90% accuracy.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex justify-center gap-4 mb-8">
          <button
            onClick={generateFingerprint}
            disabled={isLoading}
            className="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white px-6 py-3 rounded-lg font-medium transition-colors"
          >
            {isLoading ? 'Generating...' : 'Generate New Fingerprint'}
          </button>
          <button
            onClick={clearHistory}
            className="bg-red-600 hover:bg-red-700 text-white px-6 py-3 rounded-lg font-medium transition-colors"
          >
            Clear History
          </button>
        </div>

        {/* Tabs */}
        <div className="flex justify-center mb-8">
          <div className="bg-white rounded-lg p-1 shadow-sm">
            {(['current', 'history', 'analysis'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-6 py-2 rounded-md font-medium transition-colors ${
                  activeTab === tab
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                {tab === 'current' && 'Current Session'}
                {tab === 'history' && 'Session History'}
                {tab === 'analysis' && 'Analysis'}
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        {activeTab === 'current' && currentSession && (
          <div className="bg-white rounded-lg shadow-lg p-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Risk Assessment */}
              <div className="bg-gray-50 rounded-lg p-4">
                <h3 className="text-lg font-semibold mb-4">Risk Assessment</h3>
                <div className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span>Risk Score:</span>
                    <span className="font-bold text-xl">{currentSession.riskScore}/100</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span>Risk Level:</span>
                    <span className={`px-3 py-1 rounded-full text-sm font-medium ${getRiskColor(currentSession.riskLevel)}`}>
                      {currentSession.riskLevel}
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full ${
                        currentSession.riskLevel === 'LOW' ? 'bg-green-500' :
                        currentSession.riskLevel === 'MEDIUM' ? 'bg-yellow-500' :
                        currentSession.riskLevel === 'HIGH' ? 'bg-orange-500' : 'bg-red-500'
                      }`}
                      style={{ width: `${currentSession.riskScore}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Device Fingerprint */}
              <div className="bg-gray-50 rounded-lg p-4">
                <h3 className="text-lg font-semibold mb-4">Device Fingerprint</h3>
                <div className="space-y-2 text-sm">
                  <div><strong>Visitor ID:</strong> {currentSession.deviceFingerprint.visitorId}</div>
                  <div><strong>Confidence:</strong> {(currentSession.deviceFingerprint.confidence * 100).toFixed(1)}%</div>
                  <div><strong>Components:</strong> {Object.keys(currentSession.deviceFingerprint.components).length}</div>
                </div>
              </div>

              {/* Incognito Detection */}
              <div className="bg-gray-50 rounded-lg p-4">
                <h3 className="text-lg font-semibold mb-4">Incognito Detection</h3>
                <div className="space-y-2 text-sm">
                  <div><strong>Is Incognito:</strong> 
                    <span className={`ml-2 px-2 py-1 rounded text-xs ${
                      currentSession.incognitoDetection.isIncognito ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                    }`}>
                      {currentSession.incognitoDetection.isIncognito ? 'YES' : 'NO'}
                    </span>
                  </div>
                  <div><strong>Confidence:</strong> {(currentSession.incognitoDetection.confidence * 100).toFixed(1)}%</div>
                  <div><strong>Tests Run:</strong> {currentSession.incognitoDetection.details.totalTests || 0}</div>
                </div>
              </div>

              {/* IP Analysis */}
              <div className="bg-gray-50 rounded-lg p-4">
                <h3 className="text-lg font-semibold mb-4">IP Analysis</h3>
                {currentSession.ipAnalysis ? (
                  <div className="space-y-2 text-sm">
                    <div><strong>IP:</strong> {currentSession.ipAnalysis.ip}</div>
                    <div><strong>Location:</strong> {currentSession.ipAnalysis.city}, {currentSession.ipAnalysis.country}</div>
                    <div><strong>ISP:</strong> {currentSession.ipAnalysis.isp}</div>
                    <div className="flex gap-2">
                      {currentSession.ipAnalysis.isVPN && <span className="bg-red-100 text-red-800 px-2 py-1 rounded text-xs">VPN</span>}
                      {currentSession.ipAnalysis.isTor && <span className="bg-red-100 text-red-800 px-2 py-1 rounded text-xs">TOR</span>}
                      {currentSession.ipAnalysis.isProxy && <span className="bg-orange-100 text-orange-800 px-2 py-1 rounded text-xs">PROXY</span>}
                    </div>
                  </div>
                ) : (
                  <div className="text-gray-500">IP analysis failed</div>
                )}
              </div>

              {/* Behavior Analysis */}
              <div className="bg-gray-50 rounded-lg p-4 lg:col-span-2">
                <h3 className="text-lg font-semibold mb-4">Behavior Analysis</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <div className="font-medium">Mouse Movements</div>
                    <div className="text-2xl font-bold text-blue-600">{currentSession.behaviorAnalysis.mouseMovements}</div>
                  </div>
                  <div>
                    <div className="font-medium">Keystrokes</div>
                    <div className="text-2xl font-bold text-green-600">{currentSession.behaviorAnalysis.keystrokes}</div>
                  </div>
                  <div>
                    <div className="font-medium">Scroll Events</div>
                    <div className="text-2xl font-bold text-purple-600">{currentSession.behaviorAnalysis.scrollEvents}</div>
                  </div>
                  <div>
                    <div className="font-medium">Time on Page</div>
                    <div className="text-2xl font-bold text-orange-600">{Math.round(currentSession.behaviorAnalysis.timeOnPage / 1000)}s</div>
                  </div>
                </div>
                {currentSession.behaviorAnalysis.suspiciousPatterns.length > 0 && (
                  <div className="mt-4">
                    <div className="font-medium text-red-600 mb-2">Suspicious Patterns Detected:</div>
                    <div className="flex flex-wrap gap-2">
                      {currentSession.behaviorAnalysis.suspiciousPatterns.map((pattern, index) => (
                        <span key={index} className="bg-red-100 text-red-800 px-2 py-1 rounded text-xs">
                          {pattern.replace(/-/g, ' ').toUpperCase()}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'history' && (
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h3 className="text-lg font-semibold mb-4">Session History ({sessions.length})</h3>
            {sessions.length === 0 ? (
              <div className="text-center text-gray-500 py-8">
                No sessions recorded yet. Generate a fingerprint to get started.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Timestamp</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Device ID</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Level</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Incognito</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">VPN/Proxy</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Suspicious Patterns</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {sessions.map((session) => (
                      <tr key={session.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {formatTimestamp(session.timestamp)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-600">
                          {session.deviceFingerprint.visitorId.substring(0, 12)}...
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRiskColor(session.riskLevel)}`}>
                            {session.riskLevel}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          {session.incognitoDetection.isIncognito ? '✓' : '✗'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          {session.ipAnalysis && (session.ipAnalysis.isVPN || session.ipAnalysis.isProxy || session.ipAnalysis.isTor) ? '✓' : '✗'}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          {session.behaviorAnalysis.suspiciousPatterns.length}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === 'analysis' && (
          <div className="bg-white rounded-lg shadow-lg p-6">
            <h3 className="text-lg font-semibold mb-6">System Analysis</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {/* Accuracy Breakdown */}
              <div className="bg-gray-50 rounded-lg p-4">
                <h4 className="font-semibold mb-3">Estimated Accuracy</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span>Device Fingerprint:</span>
                    <span className="font-medium">60-80%</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Incognito Detection:</span>
                    <span className="font-medium">70-85%</span>
                  </div>
                  <div className="flex justify-between">
                    <span>VPN/Proxy Detection:</span>
                    <span className="font-medium">90-95%</span>
                  </div>
                  <div className="flex justify-between border-t pt-2 font-semibold">
                    <span>Combined System:</span>
                    <span className="text-blue-600">85-90%</span>
                  </div>
                </div>
              </div>

              {/* Detection Methods */}
              <div className="bg-gray-50 rounded-lg p-4">
                <h4 className="font-semibold mb-3">Detection Methods</h4>
                <div className="space-y-2 text-sm">
                  <div>• Canvas & WebGL fingerprinting</div>
                  <div>• Audio context analysis</div>
                  <div>• Screen & hardware detection</div>
                  <div>• Storage quota analysis</div>
                  <div>• IP reputation checking</div>
                  <div>• Behavioral pattern analysis</div>
                  <div>• Mouse movement tracking</div>
                  <div>• Keystroke timing analysis</div>
                </div>
              </div>

              {/* Statistics */}
              <div className="bg-gray-50 rounded-lg p-4">
                <h4 className="font-semibold mb-3">Session Statistics</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span>Total Sessions:</span>
                    <span className="font-medium">{sessions.length}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>High Risk:</span>
                    <span className="font-medium text-red-600">
                      {sessions.filter(s => s.riskLevel === 'HIGH' || s.riskLevel === 'CRITICAL').length}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Incognito Detected:</span>
                    <span className="font-medium">
                      {sessions.filter(s => s.incognitoDetection.isIncognito).length}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>VPN/Proxy Detected:</span>
                    <span className="font-medium">
                      {sessions.filter(s => s.ipAnalysis && (s.ipAnalysis.isVPN || s.ipAnalysis.isProxy)).length}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Improvement Suggestions */}
            <div className="mt-6 bg-blue-50 rounded-lg p-4">
              <h4 className="font-semibold mb-3 text-blue-900">Suggestions for Production</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-blue-800">
                <div>
                  <div className="font-medium mb-2">Server-Side Enhancements:</div>
                  <ul className="space-y-1 list-disc list-inside">
                    <li>TLS fingerprinting</li>
                    <li>HTTP header analysis</li>
                    <li>Request timing patterns</li>
                    <li>Geolocation consistency checks</li>
                  </ul>
                </div>
                <div>
                  <div className="font-medium mb-2">Advanced Features:</div>
                  <ul className="space-y-1 list-disc list-inside">
                    <li>Machine learning risk scoring</li>
                    <li>Device reputation database</li>
                    <li>Real-time threat intelligence</li>
                    <li>Behavioral biometrics</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}