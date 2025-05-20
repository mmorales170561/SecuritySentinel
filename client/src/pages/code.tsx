import React, { useState } from "react";
import { CodeAnalysisForm } from "@/components/code-analysis-form";
import { ScanningProgress } from "@/components/scanning-progress";
import { ScanResults } from "@/components/scan-results";
import { PageNav } from "@/components/layout/page-nav";
import { useScan } from "@/hooks/use-scan";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function CodeAnalysis() {
  const [scanId, setScanId] = useState<number | null>(null);
  const { isScanning, progress, logs, target, findings, severityCounts, stopScan, scanTimeAgo } = useScan(scanId);
  
  const handleAnalysisStart = (id: number) => {
    setScanId(id);
  };
  
  return (
    <div className="container py-10 max-w-7xl mx-auto">
      <PageNav 
        title="Code Analysis" 
        description="Analyze code for security vulnerabilities and best practice violations" 
      />
      
      <Tabs defaultValue="scan" className="space-y-4">
        <TabsList>
          <TabsTrigger value="scan">Code Analysis</TabsTrigger>
          {!isScanning && findings.length > 0 && (
            <TabsTrigger value="results">Results</TabsTrigger>
          )}
        </TabsList>
        
        <TabsContent value="scan" className="space-y-4">
          {!scanId || (!isScanning && findings.length > 0) ? (
            <CodeAnalysisForm onAnalysisStart={handleAnalysisStart} />
          ) : (
            <ScanningProgress
              target={target || "Code snippet"}
              progress={progress}
              log={logs}
              onStopScan={stopScan}
            />
          )}
        </TabsContent>
        
        {!isScanning && findings.length > 0 && (
          <TabsContent value="results">
            <ScanResults
              findings={findings}
              scanTime={scanTimeAgo}
              severityCounts={severityCounts}
            />
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}