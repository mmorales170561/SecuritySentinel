import { Request, Response, Router } from 'express';
import { PortScanner } from '../scanners/port-scanner';
import { WebScanner } from '../scanners/web-scanner';
import { CodeAnalyzer } from '../scanners/code-analyzer';
import { storage } from '../storage';
import { v4 as uuidv4 } from 'uuid';

const router = Router();

// Port Scanner API endpoint
router.post('/port-scan', async (req: Request, res: Response) => {
  try {
    const { target, ports, options } = req.body;
    
    if (!target) {
      return res.status(400).json({ error: 'Target is required' });
    }
    
    // Create new scan record
    const scan = await storage.createScan({
      target,
      scanType: 'port-scan',
      startedAt: new Date(),
      status: 'in_progress',
      options: { ports, ...options },
    });
    
    // Return scan ID immediately so client can track progress
    res.status(201).json({ 
      message: 'Port scan started',
      scanId: scan.id,
      target
    });
    
    // Run port scan in background
    PortScanner.scanTarget(target, ports || '1-1024', options)
      .then(async (results) => {
        // Convert port scan results to findings format
        const findings = results.map(result => ({
          id: uuidv4(),
          severity: result.port < 1024 ? 'medium' : 'low',
          title: `Open Port: ${result.port} (${result.service || 'Unknown'})`,
          description: `Port ${result.port} is open and accepting connections.`,
          location: `${target}:${result.port}`,
          evidence: `Service: ${result.service || 'Unknown'}`,
          impact: 'Open ports may expose services that can be targeted for attacks.',
          remediation: 'Verify that this port needs to be open and properly secure the service.',
          falsePositive: false,
          verified: true,
        }));
        
        const severityCounts = countSeverities(findings);
        
        // Update scan with results
        await storage.updateScanStatus(scan.id, 'completed', {
          findings,
          stats: severityCounts
        });
      })
      .catch(async (error) => {
        console.error('Port scan error:', error);
        await storage.updateScanStatus(scan.id, 'failed');
      });
      
  } catch (error) {
    console.error('Error processing port scan request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Web Scanner API endpoint
router.post('/web-scan', async (req: Request, res: Response) => {
  try {
    const { url, scanType, options } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }
    
    // Create new scan record
    const scan = await storage.createScan({
      target: url,
      scanType: scanType || 'web-security',
      startedAt: new Date(),
      status: 'in_progress',
      options,
    });
    
    // Return scan ID immediately so client can track progress
    res.status(201).json({ 
      message: 'Web scan started',
      scanId: scan.id,
      target: url
    });
    
    // Run web scan in background
    const webScanner = new WebScanner(options);
    
    webScanner.scan(url)
      .then(async (findings) => {
        // Convert to our standard findings format
        const standardizedFindings = findings.map(finding => ({
          ...finding,
          falsePositive: false,
          verified: false,
        }));
        
        const severityCounts = countSeverities(standardizedFindings);
        
        // Update scan with results
        await storage.updateScanStatus(scan.id, 'completed', {
          findings: standardizedFindings,
          stats: severityCounts
        });
      })
      .catch(async (error) => {
        console.error('Web scan error:', error);
        await storage.updateScanStatus(scan.id, 'failed');
      });
      
  } catch (error) {
    console.error('Error processing web scan request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Code Analysis API endpoint
router.post('/code-analyze', async (req: Request, res: Response) => {
  try {
    const { code, language, options } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }
    
    // Create new scan record
    const scan = await storage.createScan({
      target: `Code snippet (${language || 'auto'})`,
      scanType: 'code-analysis',
      startedAt: new Date(),
      status: 'in_progress',
      options: { language, ...options },
    });
    
    // Return scan ID immediately so client can track progress
    res.status(201).json({ 
      message: 'Code analysis started',
      scanId: scan.id
    });
    
    // Run code analysis in background
    const codeAnalyzer = new CodeAnalyzer(options);
    
    try {
      const vulnerabilities = codeAnalyzer.analyze(code, language);
      
      // Convert to our standard findings format
      const findings = vulnerabilities.map(vuln => ({
        id: vuln.id,
        severity: vuln.severity,
        title: vuln.title,
        description: vuln.description,
        location: `Line ${vuln.location.line}${vuln.location.column ? `, Column ${vuln.location.column}` : ''}`,
        evidence: vuln.location.snippet,
        impact: `CWE-${vuln.cwe || 'Unknown'}: Potential security vulnerability in the code.`,
        remediation: vuln.remediation || 'Review and fix the vulnerable code pattern.',
        falsePositive: false,
        verified: false,
      }));
      
      const severityCounts = countSeverities(findings);
      
      // Update scan with results
      await storage.updateScanStatus(scan.id, 'completed', {
        findings,
        stats: severityCounts
      });
      
    } catch (error) {
      console.error('Code analysis error:', error);
      await storage.updateScanStatus(scan.id, 'failed');
    }
    
  } catch (error) {
    console.error('Error processing code analysis request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Helper function to count findings by severity
function countSeverities(findings: any[]) {
  return findings.reduce((counts, finding) => {
    const severity = finding.severity || 'info';
    counts[severity] = (counts[severity] || 0) + 1;
    return counts;
  }, {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  });
}

export default router;