import { useState, useEffect } from "react";
import { Header } from "@/components/layout/header";
import { Sidebar } from "@/components/layout/sidebar";
import { ScanForm } from "@/components/scan-form";
import { CodeAnalysisForm } from "@/components/code-analysis-form";
import { ScanningProgress } from "@/components/scanning-progress";
import { ScanResults } from "@/components/scan-results";
import { CircularNav } from "@/components/ui/circular-nav";
import { PageHeader } from "@/components/layout/page-header";
import { useScan } from "@/hooks/use-scan";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Severity } from "@shared/schema";
import { Card, CardContent } from "@/components/ui/card";

export default function Home() {
  const [activeTab, setActiveTab] = useState("web");
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [scanId, setScanId] = useState<number | null>(null);
  const [showScanInterface, setShowScanInterface] = useState(false);
  
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
  
  // Navigation items for the circular navigation
  const navItems = [
    {
      name: "Web Scan",
      path: "/",
      icon: "language",
      description: "Scan websites for security vulnerabilities"
    },
    {
      name: "Code Analysis",
      path: "/code",
      icon: "code",
      description: "Analyze source code for security issues"
    },
    {
      name: "Network Scan",
      path: "/network",
      icon: "network_check",
      description: "Scan networks for open ports and services"
    },
    {
      name: "API Testing",
      path: "/api",
      icon: "api",
      description: "Test APIs for security vulnerabilities"
    },
    {
      name: "Repository",
      path: "/repository",
      icon: "source",
      description: "Scan code repositories for security issues"
    },
    {
      name: "Custom Tools",
      path: "/custom-tools",
      icon: "security",
      description: "Access our custom security scanners"
    },
    {
      name: "Dashboard",
      path: "/dashboard",
      icon: "dashboard",
      description: "View your security risk overview"
    },
    {
      name: "History",
      path: "/history",
      icon: "history",
      description: "View past scan results"
    }
  ];

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
            <PageHeader 
              title="Security Scanner Hub" 
              description="Your comprehensive security scanning platform"
              showBackButton={false}
            />
            
            {isScanning ? (
              <ScanningProgress
                target={target || ""}
                progress={progress}
                log={logs}
                onStopScan={stopScan}
              />
            ) : findings && findings.length > 0 ? (
              <ScanResults
                findings={findings}
                scanTime={scanTimeAgo}
                severityCounts={severityCounts}
              />
            ) : showScanInterface ? (
              <div className="animate-fadeIn">
                <Tabs defaultValue="web" value={activeTab} onValueChange={setActiveTab}>
                  <TabsList className="bg-dark-surface mb-6">
                    <TabsTrigger value="web">Web Security Scan</TabsTrigger>
                    <TabsTrigger value="code">Code Analysis</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="web">
                    <ScanForm onScanStart={handleScanStart} />
                  </TabsContent>
                  
                  <TabsContent value="code">
                    <CodeAnalysisForm onAnalysisStart={handleCodeAnalysisStart} />
                  </TabsContent>
                </Tabs>
              </div>
            ) : (
              <div className="space-y-10 animate-fadeIn">
                <Card className="bg-gradient-to-br from-gray-900 to-gray-800 border-gray-700">
                  <CardContent className="p-0">
                    <div className="py-8">
                      <CircularNav items={navItems} />
                    </div>
                    
                    <div className="py-5 text-center bg-gray-800 bg-opacity-50">
                      <button 
                        className="bg-primary hover:bg-primary-dark text-white px-6 py-3 rounded-full font-semibold transition-all transform hover:scale-105 shadow-lg"
                        onClick={() => setShowScanInterface(true)}
                      >
                        Start Quick Scan
                      </button>
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
