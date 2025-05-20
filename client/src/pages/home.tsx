import { useState, useEffect } from "react";
import { Header } from "@/components/layout/header";
import { Sidebar } from "@/components/layout/sidebar";
import { ScanForm } from "@/components/scan-form";
import { CodeAnalysisForm } from "@/components/code-analysis-form";
import { ScanningProgress } from "@/components/scanning-progress";
import { ScanResults } from "@/components/scan-results";
import { useScan } from "@/hooks/use-scan";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Severity } from "@shared/schema";

export default function Home() {
  const [activeTab, setActiveTab] = useState("web");
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [scanId, setScanId] = useState<number | null>(null);
  
  const {
    isScanning,
    progress,
    logs,
    target,
    findings,
    severityCounts,
    stopScan,
    scanTimeAgo,
  } = useScan(scanId);

  const handleScanStart = (newScanId: number) => {
    setScanId(newScanId);
  };

  const handleCodeAnalysisStart = (newScanId: number) => {
    setScanId(newScanId);
    setActiveTab("web"); // Switch to web tab to show results
  };

  const toggleMobileMenu = () => {
    setMobileSidebarOpen(!mobileSidebarOpen);
  };

  return (
    <div className="min-h-screen flex flex-col">
      <Header toggleMobileMenu={toggleMobileMenu} />

      <div className="flex flex-1">
        <Sidebar 
          isMobileOpen={mobileSidebarOpen} 
          closeMobileMenu={() => setMobileSidebarOpen(false)} 
        />
        
        <main className="flex-1 overflow-auto">
          <div className="container mx-auto p-4 md:p-6">
            <Tabs defaultValue="web" value={activeTab} onValueChange={setActiveTab}>
              <TabsList className="bg-dark-surface mb-6 w-full flex space-x-0">
                <TabsTrigger value="web" className="flex-1">Web Security Scan</TabsTrigger>
                <TabsTrigger value="code" className="flex-1">Code Analysis</TabsTrigger>
              </TabsList>
              
              <TabsContent value="web" className="mt-4">
                <ScanForm onScanStart={handleScanStart} />
              </TabsContent>
              
              <TabsContent value="code" className="mt-4">
                <CodeAnalysisForm onAnalysisStart={handleCodeAnalysisStart} />
              </TabsContent>
            </Tabs>
            
            {isScanning && (
              <ScanningProgress
                target={target || ""}
                progress={progress}
                log={logs}
                onStopScan={stopScan}
              />
            )}
            
            {findings.length > 0 && (
              <ScanResults
                findings={findings}
                scanTime={scanTimeAgo}
                severityCounts={severityCounts}
              />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
