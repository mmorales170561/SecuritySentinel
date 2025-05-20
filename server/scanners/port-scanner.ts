import * as net from 'net';

interface PortScanResult {
  port: number;
  state: 'open' | 'closed';
  service?: string;
}

interface ScanOptions {
  timeout?: number;
  concurrency?: number;
  detectServices?: boolean;
}

/**
 * Common services that run on specific ports
 */
const commonServices: Record<number, string> = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  143: 'IMAP',
  443: 'HTTPS',
  465: 'SMTPS',
  587: 'SMTP (Submission)',
  993: 'IMAPS',
  995: 'POP3S',
  3306: 'MySQL',
  5432: 'PostgreSQL',
  6379: 'Redis',
  8080: 'HTTP-Alternate',
  8443: 'HTTPS-Alternate',
  27017: 'MongoDB',
};

/**
 * Simple port scanner implementation
 */
export class PortScanner {
  /**
   * Scan a single port on a host
   */
  static async scanPort(host: string, port: number, timeout = 2000): Promise<PortScanResult> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let status: 'open' | 'closed' = 'closed';
      
      // Set timeout
      socket.setTimeout(timeout);
      
      // Attempt to connect
      socket.connect(port, host, () => {
        status = 'open';
        socket.destroy();
      });
      
      // Handle errors
      socket.on('error', () => {
        status = 'closed';
      });
      
      // Handle timeouts
      socket.on('timeout', () => {
        socket.destroy();
      });
      
      // When socket closes, resolve the promise
      socket.on('close', () => {
        const service = status === 'open' && commonServices[port] ? commonServices[port] : undefined;
        resolve({ port, state: status, service });
      });
    });
  }
  
  /**
   * Scan a range of ports on a host
   */
  static async scanPorts(
    host: string, 
    portRange: [number, number] = [1, 1024],
    options: ScanOptions = {}
  ): Promise<PortScanResult[]> {
    const { 
      timeout = 2000,
      concurrency = 10,
      detectServices = true
    } = options;
    
    const results: PortScanResult[] = [];
    const [startPort, endPort] = portRange;
    
    // Generate array of port numbers to scan
    const ports = Array.from(
      { length: endPort - startPort + 1 },
      (_, i) => startPort + i
    );
    
    // Scan ports with concurrency limit
    for (let i = 0; i < ports.length; i += concurrency) {
      const batch = ports.slice(i, i + concurrency);
      const scanPromises = batch.map(port => this.scanPort(host, port, timeout));
      const batchResults = await Promise.all(scanPromises);
      
      // Add results to our array
      results.push(...batchResults);
    }
    
    // Filter to only show open ports if requested
    return results.filter(result => result.state === 'open');
  }
  
  /**
   * Parse port range string like "80,443,8000-8100"
   */
  static parsePortRange(portRangeStr: string): number[] {
    const ports: number[] = [];
    
    if (!portRangeStr) {
      return [80, 443]; // Default to common HTTP/HTTPS ports
    }
    
    const rangeParts = portRangeStr.split(',');
    
    for (const part of rangeParts) {
      if (part.includes('-')) {
        // Handle port range (e.g., "1000-2000")
        const [start, end] = part.split('-').map(p => parseInt(p.trim()));
        for (let port = start; port <= end; port++) {
          ports.push(port);
        }
      } else {
        // Handle single port (e.g., "80")
        const port = parseInt(part.trim());
        if (!isNaN(port)) {
          ports.push(port);
        }
      }
    }
    
    return ports;
  }
  
  /**
   * Scan a target with a port range string
   */
  static async scanTarget(target: string, portRangeStr: string, options: ScanOptions = {}): Promise<PortScanResult[]> {
    // Parse the port range string
    const ports = this.parsePortRange(portRangeStr);
    
    // Find the min and max port
    const minPort = Math.min(...ports);
    const maxPort = Math.max(...ports);
    
    // Only scan the specific ports requested
    const results: PortScanResult[] = [];
    
    for (let i = 0; i < ports.length; i += options.concurrency || 10) {
      const batch = ports.slice(i, i + (options.concurrency || 10));
      const scanPromises = batch.map(port => this.scanPort(target, port, options.timeout));
      const batchResults = await Promise.all(scanPromises);
      
      // Add results to our array
      results.push(...batchResults.filter(result => result.state === 'open'));
    }
    
    return results;
  }
}