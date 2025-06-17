import type { BehaviorAnalysis } from '~/types/fingerprint';

export class BehaviorTracker {
  private mouseMovements = 0;
  private keystrokes = 0;
  private scrollEvents = 0;
  private startTime = Date.now();
  private lastInteraction = Date.now();
  private suspiciousPatterns: string[] = [];
  private mousePath: Array<{ x: number; y: number; timestamp: number }> = [];
  private keystrokeTimings: number[] = [];

  constructor() {
    this.setupEventListeners();
  }

  private setupEventListeners() {
    // Mouse movement tracking
    document.addEventListener('mousemove', (e) => {
      this.mouseMovements++;
      this.lastInteraction = Date.now();
      this.mousePath.push({
        x: e.clientX,
        y: e.clientY,
        timestamp: Date.now()
      });
      
      // Keep only last 100 mouse positions
      if (this.mousePath.length > 100) {
        this.mousePath.shift();
      }
      
      this.analyzeMousePattern();
    });

    // Keystroke tracking
    document.addEventListener('keydown', (e) => {
      this.keystrokes++;
      this.lastInteraction = Date.now();
      this.keystrokeTimings.push(Date.now());
      
      // Keep only last 50 keystrokes
      if (this.keystrokeTimings.length > 50) {
        this.keystrokeTimings.shift();
      }
      
      this.analyzeKeystrokePattern();
    });

    // Scroll tracking
    document.addEventListener('scroll', () => {
      this.scrollEvents++;
      this.lastInteraction = Date.now();
    });

    // Click tracking
    document.addEventListener('click', () => {
      this.lastInteraction = Date.now();
    });
  }

  private analyzeMousePattern() {
    if (this.mousePath.length < 10) return;

    // Check for perfectly straight lines (bot behavior)
    const recentMoves = this.mousePath.slice(-10);
    const straightLines = this.detectStraightLines(recentMoves);
    if (straightLines > 5) {
      this.addSuspiciousPattern('straight-mouse-lines');
    }

    // Check for inhuman speed
    const speeds = this.calculateMouseSpeeds(recentMoves);
    const avgSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;
    if (avgSpeed > 2000) { // pixels per second
      this.addSuspiciousPattern('inhuman-mouse-speed');
    }

    // Check for repetitive patterns
    if (this.detectRepetitiveMousePattern()) {
      this.addSuspiciousPattern('repetitive-mouse-pattern');
    }
  }

  private analyzeKeystrokePattern() {
    if (this.keystrokeTimings.length < 10) return;

    // Check for inhuman typing speed
    const recentTimings = this.keystrokeTimings.slice(-10);
    const intervals = [];
    for (let i = 1; i < recentTimings.length; i++) {
      intervals.push(recentTimings[i] - recentTimings[i - 1]);
    }
    
    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    if (avgInterval < 50) { // Less than 50ms between keystrokes
      this.addSuspiciousPattern('inhuman-typing-speed');
    }

    // Check for perfectly consistent timing (bot behavior)
    const variance = this.calculateVariance(intervals);
    if (variance < 10) {
      this.addSuspiciousPattern('consistent-keystroke-timing');
    }
  }

  private detectStraightLines(moves: Array<{ x: number; y: number; timestamp: number }>): number {
    let straightCount = 0;
    for (let i = 2; i < moves.length; i++) {
      const p1 = moves[i - 2];
      const p2 = moves[i - 1];
      const p3 = moves[i];
      
      // Calculate if points are collinear
      const area = Math.abs((p2.x - p1.x) * (p3.y - p1.y) - (p3.x - p1.x) * (p2.y - p1.y));
      if (area < 5) { // Very small area indicates straight line
        straightCount++;
      }
    }
    return straightCount;
  }

  private calculateMouseSpeeds(moves: Array<{ x: number; y: number; timestamp: number }>): number[] {
    const speeds = [];
    for (let i = 1; i < moves.length; i++) {
      const prev = moves[i - 1];
      const curr = moves[i];
      const distance = Math.sqrt(Math.pow(curr.x - prev.x, 2) + Math.pow(curr.y - prev.y, 2));
      const time = (curr.timestamp - prev.timestamp) / 1000; // Convert to seconds
      if (time > 0) {
        speeds.push(distance / time);
      }
    }
    return speeds;
  }

  private detectRepetitiveMousePattern(): boolean {
    if (this.mousePath.length < 20) return false;
    
    // Simple pattern detection: check if mouse follows same path repeatedly
    const recent = this.mousePath.slice(-20);
    const first10 = recent.slice(0, 10);
    const second10 = recent.slice(10, 20);
    
    let similarMoves = 0;
    for (let i = 0; i < 10; i++) {
      const distance = Math.sqrt(
        Math.pow(first10[i].x - second10[i].x, 2) + 
        Math.pow(first10[i].y - second10[i].y, 2)
      );
      if (distance < 50) { // Within 50 pixels
        similarMoves++;
      }
    }
    
    return similarMoves > 7; // 70% similarity
  }

  private calculateVariance(numbers: number[]): number {
    const mean = numbers.reduce((a, b) => a + b, 0) / numbers.length;
    const squaredDiffs = numbers.map(n => Math.pow(n - mean, 2));
    return squaredDiffs.reduce((a, b) => a + b, 0) / numbers.length;
  }

  private addSuspiciousPattern(pattern: string) {
    if (!this.suspiciousPatterns.includes(pattern)) {
      this.suspiciousPatterns.push(pattern);
    }
  }

  getAnalysis(): BehaviorAnalysis {
    const timeOnPage = Date.now() - this.startTime;
    const timeSinceLastInteraction = Date.now() - this.lastInteraction;
    
    // Calculate interaction speed (interactions per minute)
    const totalInteractions = this.mouseMovements + this.keystrokes + this.scrollEvents;
    const interactionSpeed = (totalInteractions / (timeOnPage / 60000)) || 0;

    return {
      mouseMovements: this.mouseMovements,
      keystrokes: this.keystrokes,
      scrollEvents: this.scrollEvents,
      timeOnPage,
      interactionSpeed,
      suspiciousPatterns: [...this.suspiciousPatterns]
    };
  }

  reset() {
    this.mouseMovements = 0;
    this.keystrokes = 0;
    this.scrollEvents = 0;
    this.startTime = Date.now();
    this.lastInteraction = Date.now();
    this.suspiciousPatterns = [];
    this.mousePath = [];
    this.keystrokeTimings = [];
  }
}