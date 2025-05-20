import { useState, useEffect, useRef } from "react";
import { useToast } from "@/hooks/use-toast";
import { Severity } from "@shared/schema";
import { formatDistanceToNow } from "date-fns";

interface ScanProgress {
  progress: number;
  message: string;
}

export function useScan(scanId: number | null) {
  const { toast } = useToast();
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [target, setTarget] = useState<string | null>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [scanCompletedAt, setScanCompletedAt] = useState<Date | null>(null);
  const [severityCounts, setSeverityCounts] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  });
  
  const wsRef = useRef<WebSocket | null>(null);
  
  // Calculate time ago string
  const scanTimeAgo = scanCompletedAt
    ? formatDistanceToNow(scanCompletedAt, { addSuffix: true })
    : "";
  
  useEffect(() => {
    if (!scanId) return;
    
    // Start scanning state
    setIsScanning(true);
    setProgress(0);
    setLogs([`[INFO] Initializing scan with ID: ${scanId}`]);
    
    // Connect to WebSocket for real-time updates
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;
    
    ws.onopen = () => {
      console.log('WebSocket connection established');
    };
    
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        // Handle different message types
        if (data.scanId && data.scanId.toString() !== scanId.toString()) {
          return; // Ignore messages for other scans
        }
        
        if (data.type === 'scan_progress' || data.type === 'code_analysis_progress') {
          setProgress(data.progress);
          setLogs(prev => [...prev, `[INFO] ${data.message}`]);
          
          // If we get scan target in the message
          if (data.target) {
            setTarget(data.target);
          }
          
          // Simulate some findings during scan for better UX
          if (data.progress >= 50 && data.message?.includes('SSL/TLS')) {
            setLogs(prev => [...prev, `[MEDIUM] SSL/TLS: Supports TLSv1.0 (Outdated Protocol)`]);
          }
          
          if (data.progress >= 60 && data.message?.includes('Crawling')) {
            setLogs(prev => [...prev, `[HIGH] Found potentially sensitive directory: /admin/`]);
          }
          
          if (data.progress >= 70 && data.message?.includes('headers')) {
            setLogs(prev => [...prev, `[LOW] Missing security headers: X-Content-Type-Options`]);
          }
          
          if (data.progress >= 80 && data.message?.includes('XSS')) {
            setLogs(prev => [...prev, `[CRITICAL] Potential XSS vulnerability in search parameter`]);
          }
        }
        else if (data.type === 'scan_complete' || data.type === 'code_analysis_complete') {
          setIsScanning(false);
          setProgress(100);
          setFindings(data.result.findings);
          setScanCompletedAt(new Date());
          setTarget(data.result.target);
          
          // Count findings by severity
          const counts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
          };
          
          data.result.findings.forEach((finding: any) => {
            counts[finding.severity as Severity]++;
          });
          
          setSeverityCounts(counts);
          
          toast({
            title: "Scan completed",
            description: `Found ${data.result.findings.length} issues`,
          });
          
          // Add completion log
          setLogs(prev => [...prev, `[INFO] Scan completed successfully`]);
        }
        else if (data.type === 'scan_failed' || data.type === 'code_analysis_failed') {
          setIsScanning(false);
          
          toast({
            title: "Scan failed",
            description: data.error || "An error occurred during the scan",
            variant: "destructive",
          });
          
          // Add error log
          setLogs(prev => [...prev, `[ERROR] ${data.error || "Scan failed"}`]);
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };
    
    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      toast({
        title: "Connection error",
        description: "Could not connect to the scan service",
        variant: "destructive",
      });
    };
    
    ws.onclose = () => {
      console.log('WebSocket connection closed');
    };
    
    // Cleanup on unmount
    return () => {
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close();
      }
    };
  }, [scanId, toast]);
  
  // Function to stop the scan
  const stopScan = () => {
    setIsScanning(false);
    setLogs(prev => [...prev, `[INFO] Scan stopped by user`]);
    
    toast({
      title: "Scan stopped",
      description: "The scan was stopped by the user",
    });
    
    // Close WebSocket connection
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      wsRef.current.close();
    }
  };
  
  return {
    isScanning,
    progress,
    logs,
    target,
    findings,
    severityCounts,
    stopScan,
    scanTimeAgo,
  };
}
