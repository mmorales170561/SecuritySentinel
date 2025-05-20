import React, { useState } from "react";
import { CodeAnalysisForm } from "@/components/code-analysis-form";
import { ScanningProgress } from "@/components/scanning-progress";
import { ScanResults } from "@/components/scan-results";
import { useScan } from "@/hooks/use-scan";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";

export default function CodeAnalysis() {
  const [scanId, setScanId] = useState<number | null>(null);
  const { scan, log, progress } = useScan(scanId);
  
  const handleAnalysisStart = (id: number) => {
    setScanId(id);
  };
  
  const handleStopScan = () => {
    // In a real application, this would call an API to stop the scan
    console.log("Stopping scan", scanId);
  };
  
  return (
    <div className="container py-10 max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Code Analysis</h1>
        <p className="text-muted-foreground mt-2">
          Analyze code for security vulnerabilities and best practice violations
        </p>
      </div>
      
      <Tabs defaultValue="scan" className="space-y-4">
        <TabsList>
          <TabsTrigger value="scan">Code Analysis</TabsTrigger>
          {scan?.status === "completed" && (
            <TabsTrigger value="results">Results</TabsTrigger>
          )}
        </TabsList>
        
        <TabsContent value="scan" className="space-y-4">
          {!scanId || scan?.status === "completed" ? (
            <CodeAnalysisForm onAnalysisStart={handleAnalysisStart} />
          ) : (
            <ScanningProgress
              target={scan?.target || "Code snippet"}
              progress={progress}
              log={log}
              onStopScan={handleStopScan}
            />
          )}
        </TabsContent>
        
        {scan?.status === "completed" && (
          <TabsContent value="results">
            <ScanResults
              findings={scan.findings || []}
              scanTime={scan.completedAt ? new Date(scan.completedAt).toLocaleString() : undefined}
              severityCounts={scan.stats || {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0
              }}
            />
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}