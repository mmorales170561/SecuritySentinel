import { Router, Request, Response } from 'express';
import { storage } from '../storage';
import { PortScanner } from '../scanners/port-scanner';
import { WebScanner } from '../scanners/web-scanner';
import { CodeAnalyzer } from '../scanners/code-analyzer';
import { z } from 'zod';
import { fromZodError } from 'zod-validation-error';
import { randomUUID } from 'crypto';

const router = Router();

// Port scanner endpoint
router.post('/port-scan', async (req: Request, res: Response) => {
  try {
    const portScanSchema = z.object({
      target: z.string().min(1),
      ports: z.string().optional(),
      options: z.object({
        timeout: z.number().optional(),
        concurrency: z.number().optional(),
        detectServices: z.boolean().optional(),
      }).optional(),
    });

    const result = portScanSchema.safeParse(req.body);
    
    if (!result.success) {
      const errorMessage = fromZodError(result.error).message;
      return res.status(400).json({ 
        error: errorMessage
      });
    }

    const { target, ports = '1-1024', options } = result.data;

    // Create a scan record
    const scan = await storage.createScan({
      target,
      scanType: 'port-scan',
      status: 'running',
      startedAt: new Date(),
      findings: [],
      options: options || {},
    });

    // Start the scan in the background
    setTimeout(async () => {
      try {
        const scanResults = await PortScanner.scanTarget(target, ports, options);
        
        // Process results and create findings
        const findings = scanResults.map(result => {
          const severity = result.state === 'open' ? 'medium' : 'info';
          return {
            id: randomUUID(),
            scanId: scan.id,
            title: `Port ${result.port} ${result.state}`,
            severity,
            description: result.service 
              ? `Port ${result.port} is ${result.state} running ${result.service}`
              : `Port ${result.port} is ${result.state}`,
            location: `${target}:${result.port}`,
            falsePositive: false,
            verified: false,
            details: result,
          };
        });

        // Update scan status with findings
        await storage.updateScanStatus(scan.id, 'completed', findings);
      } catch (error) {
        console.error('Port scan error:', error);
        await storage.updateScanStatus(scan.id, 'failed', []);
      }
    }, 100);

    // Return the scan id immediately
    return res.status(200).json({ 
      scanId: scan.id,
      message: 'Port scan started' 
    });
  } catch (error) {
    console.error('Error in port scan endpoint:', error);
    return res.status(500).json({ 
      error: 'Internal server error' 
    });
  }
});

// Web security scanner endpoint
router.post('/web-scan', async (req: Request, res: Response) => {
  try {
    const webScanSchema = z.object({
      url: z.string().url(),
      scanType: z.enum(['basic', 'full', 'passive']),
      options: z.object({
        followRedirects: z.boolean().optional(),
        checkXSS: z.boolean().optional(),
        checkSQLi: z.boolean().optional(),
        checkHeaders: z.boolean().optional(),
        maxPages: z.number().optional(),
        timeout: z.number().optional(),
      }).optional(),
    });

    const result = webScanSchema.safeParse(req.body);
    
    if (!result.success) {
      const errorMessage = fromZodError(result.error).message;
      return res.status(400).json({ 
        error: errorMessage
      });
    }

    const { url, scanType, options } = result.data;

    // Create a scan record
    const scan = await storage.createScan({
      target: url,
      scanType: 'web-scan',
      status: 'running',
      startedAt: new Date(),
      findings: [],
      options: { scanType, ...(options || {}) },
    });

    // Start the scan in the background
    setTimeout(async () => {
      try {
        const scanner = new WebScanner({
          followRedirects: options?.followRedirects,
          checkXSS: options?.checkXSS,
          checkSQLi: options?.checkSQLi,
          checkHeaders: options?.checkHeaders,
          maxPages: scanType === 'basic' ? 5 : scanType === 'full' ? 20 : 1,
          timeout: options?.timeout,
        });
        
        const scanResults = await scanner.scan(url);
        
        // Process results and create findings
        const findings = scanResults.map(result => {
          return {
            id: result.id,
            scanId: scan.id,
            title: result.title,
            severity: result.severity,
            description: result.description,
            location: result.location,
            evidence: result.evidence,
            impact: result.impact,
            remediation: result.remediation,
            falsePositive: false,
            verified: false,
            details: result,
          };
        });

        // Update scan status with findings
        await storage.updateScanStatus(scan.id, 'completed', findings);
      } catch (error) {
        console.error('Web scan error:', error);
        await storage.updateScanStatus(scan.id, 'failed', []);
      }
    }, 100);

    // Return the scan id immediately
    return res.status(200).json({ 
      scanId: scan.id,
      message: 'Web security scan started' 
    });
  } catch (error) {
    console.error('Error in web scan endpoint:', error);
    return res.status(500).json({ 
      error: 'Internal server error' 
    });
  }
});

// Code analyzer endpoint
router.post('/code-analyze', async (req: Request, res: Response) => {
  try {
    const codeAnalysisSchema = z.object({
      code: z.string().min(1),
      language: z.string(),
      options: z.object({
        checkAuthentication: z.boolean().optional(),
        checkCryptography: z.boolean().optional(),
        checkInjection: z.boolean().optional(),
        checkSensitiveData: z.boolean().optional(),
      }).optional(),
    });

    const result = codeAnalysisSchema.safeParse(req.body);
    
    if (!result.success) {
      const errorMessage = fromZodError(result.error).message;
      return res.status(400).json({ 
        error: errorMessage
      });
    }

    const { code, language, options } = result.data;

    // Create a scan record
    const scan = await storage.createScan({
      target: `Code Analysis (${language})`,
      scanType: 'code-analysis',
      status: 'running',
      startedAt: new Date(),
      findings: [],
      options: { language, ...(options || {}) },
    });

    // Start the code analysis in the background
    setTimeout(async () => {
      try {
        const analyzer = new CodeAnalyzer(options);
        const analysisResults = analyzer.analyze(code, language);
        
        // Process results and create findings
        const findings = analysisResults.map(result => {
          return {
            id: result.id,
            scanId: scan.id,
            title: result.title,
            severity: result.severity,
            description: result.description,
            location: `Line ${result.location.line}: ${result.location.snippet}`,
            evidence: result.location.snippet,
            remediation: result.remediation,
            falsePositive: false,
            verified: false,
            details: {
              ...result,
              cwe: result.cwe,
              language: result.language,
            },
          };
        });

        // Update scan status with findings
        await storage.updateScanStatus(scan.id, 'completed', findings);
      } catch (error) {
        console.error('Code analysis error:', error);
        await storage.updateScanStatus(scan.id, 'failed', []);
      }
    }, 100);

    // Return the scan id immediately
    return res.status(200).json({ 
      scanId: scan.id,
      message: 'Code analysis started' 
    });
  } catch (error) {
    console.error('Error in code analysis endpoint:', error);
    return res.status(500).json({ 
      error: 'Internal server error' 
    });
  }
});

function countSeverities(findings: any[]) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  
  findings.forEach(finding => {
    if (finding.severity in counts) {
      counts[finding.severity as keyof typeof counts]++;
    }
  });
  
  return counts;
}

export default router;