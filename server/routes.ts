import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { WebSocket, WebSocketServer } from "ws";
import { 
  webScanRequestSchema, 
  codeAnalysisRequestSchema, 
  ScanResult, 
  WebScanRequest, 
  CodeAnalysisRequest 
} from "@shared/schema";
import { ZodError } from "zod";
import { fromZodError } from "zod-validation-error";

export async function registerRoutes(app: Express): Promise<Server> {
  const httpServer = createServer(app);
  
  // WebSocket server for real-time updates
  const wss = new WebSocketServer({ 
    server: httpServer,
    path: "/ws"
  });
  
  wss.on('connection', (ws) => {
    console.log('WebSocket client connected');
    
    // Send initial connection confirmation
    ws.send(JSON.stringify({ type: "connected", message: "Connection established" }));
    
    ws.on('message', (message) => {
      console.log('Received message: %s', message);
    });
    
    ws.on('close', () => {
      console.log('WebSocket client disconnected');
    });
    
    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
    });
  });
  
  // Helper function to broadcast to all connected clients
  function broadcast(data: any) {
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(data));
      }
    });
  }
  
  // Simulate a security scan with progress updates via WebSocket
  app.post('/api/scan/web', async (req: Request, res: Response) => {
    try {
      const scanRequest = webScanRequestSchema.parse(req.body);
      
      // Create a scan record
      const scan = await storage.createScan({
        target: scanRequest.url,
        scanType: scanRequest.scanType,
        status: 'in-progress',
        options: scanRequest.options,
        startedAt: new Date(),
      });
      
      // Send initial response
      res.status(201).json({ 
        message: 'Scan started', 
        scanId: scan.id,
        target: scan.target,
        scanType: scan.scanType,
      });
      
      // Run the simulated scan asynchronously
      simulateScanWithProgress(scanRequest, scan.id, broadcast);
      
    } catch (error) {
      if (error instanceof ZodError) {
        const validationError = fromZodError(error);
        res.status(400).json({ error: validationError.message });
      } else {
        console.error(error);
        res.status(500).json({ error: 'An error occurred while starting the scan' });
      }
    }
  });
  
  // Analyze code for security vulnerabilities
  app.post('/api/scan/code', async (req: Request, res: Response) => {
    try {
      const codeRequest = codeAnalysisRequestSchema.parse(req.body);
      
      // Create a scan record
      const scan = await storage.createScan({
        target: `Code snippet (${codeRequest.language})`,
        scanType: 'code-analysis',
        status: 'in-progress',
        options: {},
        startedAt: new Date(),
      });
      
      // Send initial response
      res.status(201).json({ 
        message: 'Code analysis started', 
        scanId: scan.id 
      });
      
      // Run the simulated code analysis asynchronously
      simulateCodeAnalysisWithProgress(codeRequest, scan.id, broadcast);
      
    } catch (error) {
      if (error instanceof ZodError) {
        const validationError = fromZodError(error);
        res.status(400).json({ error: validationError.message });
      } else {
        console.error(error);
        res.status(500).json({ error: 'An error occurred while analyzing the code' });
      }
    }
  });
  
  // Get scan result by ID
  app.get('/api/scan/:id', async (req: Request, res: Response) => {
    try {
      const scanId = parseInt(req.params.id);
      if (isNaN(scanId)) {
        return res.status(400).json({ error: 'Invalid scan ID' });
      }
      
      const scan = await storage.getScan(scanId);
      if (!scan) {
        return res.status(404).json({ error: 'Scan not found' });
      }
      
      res.json(scan);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred while retrieving the scan' });
    }
  });
  
  // Get all scans (history)
  app.get('/api/scans', async (_req: Request, res: Response) => {
    try {
      const scans = await storage.getAllScans();
      res.json(scans);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred while retrieving scans' });
    }
  });
  
  // Mark finding as false positive
  app.post('/api/finding/:id/false-positive', async (req: Request, res: Response) => {
    try {
      const findingId = parseInt(req.params.id);
      if (isNaN(findingId)) {
        return res.status(400).json({ error: 'Invalid finding ID' });
      }
      
      const isFalse = req.body.isFalse === true;
      const finding = await storage.markFindingAsFalsePositive(findingId, isFalse);
      
      if (!finding) {
        return res.status(404).json({ error: 'Finding not found' });
      }
      
      res.json(finding);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred while updating the finding' });
    }
  });
  
  // Mark finding as verified (fix verified)
  app.post('/api/finding/:id/verify', async (req: Request, res: Response) => {
    try {
      const findingId = parseInt(req.params.id);
      if (isNaN(findingId)) {
        return res.status(400).json({ error: 'Invalid finding ID' });
      }
      
      const isVerified = req.body.isVerified === true;
      const finding = await storage.markFindingAsVerified(findingId, isVerified);
      
      if (!finding) {
        return res.status(404).json({ error: 'Finding not found' });
      }
      
      res.json(finding);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred while updating the finding' });
    }
  });

  return httpServer;
}

// Helper functions for simulating scans with progress updates

async function simulateScanWithProgress(
  scanRequest: WebScanRequest, 
  scanId: number, 
  broadcast: (data: any) => void
) {
  try {
    const progressSteps = [
      { progress: 10, message: `Initializing scan for ${scanRequest.url}` },
      { progress: 20, message: 'Performing DNS resolution' },
      { progress: 30, message: 'Starting port scan' },
      { progress: 40, message: 'Found open ports: 80, 443' },
      { progress: 50, message: 'Checking for SSL/TLS configuration' },
      { progress: 60, message: 'Crawling website structure' },
      { progress: 70, message: 'Analyzing HTTP headers' },
      { progress: 80, message: 'Testing for XSS vulnerabilities' },
      { progress: 90, message: 'Testing for SQL injection vulnerabilities' },
      { progress: 95, message: 'Finalizing results' },
    ];
    
    // Send progress updates
    for (const step of progressSteps) {
      await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000));
      
      broadcast({
        type: 'scan_progress',
        scanId,
        progress: step.progress,
        message: step.message
      });
    }
    
    // Complete the scan
    const result = await storage.simulateWebScan(scanRequest);
    
    // Update the scan in storage
    await storage.updateScanStatus(scanId, 'completed', result.findings);
    
    // Send final update
    broadcast({
      type: 'scan_complete',
      scanId,
      result
    });
    
  } catch (error) {
    console.error('Error in scan simulation:', error);
    
    // Update scan status to failed
    await storage.updateScanStatus(scanId, 'failed');
    
    // Send failure notification
    broadcast({
      type: 'scan_failed',
      scanId,
      error: 'An error occurred during the scan'
    });
  }
}

async function simulateCodeAnalysisWithProgress(
  codeRequest: CodeAnalysisRequest, 
  scanId: number, 
  broadcast: (data: any) => void
) {
  try {
    const progressSteps = [
      { progress: 10, message: `Initializing code analysis for ${codeRequest.language}` },
      { progress: 30, message: 'Parsing code' },
      { progress: 50, message: 'Analyzing for security vulnerabilities' },
      { progress: 70, message: 'Checking for code quality issues' },
      { progress: 90, message: 'Finalizing results' },
    ];
    
    // Send progress updates
    for (const step of progressSteps) {
      await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000));
      
      broadcast({
        type: 'code_analysis_progress',
        scanId,
        progress: step.progress,
        message: step.message
      });
    }
    
    // Complete the analysis
    const result = await storage.simulateCodeAnalysis(codeRequest);
    
    // Update the scan in storage
    await storage.updateScanStatus(scanId, 'completed', result.findings);
    
    // Send final update
    broadcast({
      type: 'code_analysis_complete',
      scanId,
      result
    });
    
  } catch (error) {
    console.error('Error in code analysis:', error);
    
    // Update scan status to failed
    await storage.updateScanStatus(scanId, 'failed');
    
    // Send failure notification
    broadcast({
      type: 'code_analysis_failed',
      scanId,
      error: 'An error occurred during code analysis'
    });
  }
}
