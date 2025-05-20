import React, { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { PageNav } from "@/components/layout/page-nav";
import { useToast } from "@/hooks/use-toast";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { CodeEditor } from "@/components/ui/code-editor";
import { AlertCircle, Download, ExternalLink, Play, Settings } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { apiRequest } from "@/lib/queryClient";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { useScan } from "@/hooks/use-scan";
import { ScanningProgress } from "@/components/scanning-progress";
import { ScanResults } from "@/components/scan-results";

export default function CustomTools() {
  const { toast } = useToast();
  const [scanId, setScanId] = useState<number | null>(null);
  const { isScanning, progress, logs, target, findings, severityCounts, stopScan, scanTimeAgo } = useScan(scanId);
  
  // Port Scanner state
  const [portScanTarget, setPortScanTarget] = useState("");
  const [portRange, setPortRange] = useState("1-1024");
  const [portScanTimeout, setPortScanTimeout] = useState("2000");
  const [portScanConcurrency, setPortScanConcurrency] = useState("10");
  
  // Web Scanner state
  const [webScanTarget, setWebScanTarget] = useState("");
  const [webScanType, setWebScanType] = useState("basic");
  const [followRedirects, setFollowRedirects] = useState(true);
  const [checkXSS, setCheckXSS] = useState(true);
  const [checkSQLi, setCheckSQLi] = useState(true);
  const [checkHeaders, setCheckHeaders] = useState(true);
  
  // Code Analyzer state
  const [codeToAnalyze, setCodeToAnalyze] = useState(`// Example JavaScript code to analyze
function login(username, password) {
  // Connect to database
  const db = connectToDatabase();
  
  // WARNING: SQL Injection vulnerability!
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  
  // Execute query
  const result = db.query(query);
  
  return result.length > 0;
}`);
  const [codeLanguage, setCodeLanguage] = useState("javascript");
  const [checkAuthCode, setCheckAuthCode] = useState(true);
  const [checkCryptoCode, setCheckCryptoCode] = useState(true);
  const [checkInjectionCode, setCheckInjectionCode] = useState(true);
  const [checkSensitiveData, setCheckSensitiveData] = useState(true);
  
  // Run port scan
  const runPortScan = async () => {
    if (!portScanTarget) {
      toast({
        title: "Target required",
        description: "Please enter a target hostname or IP address",
        variant: "destructive",
      });
      return;
    }
    
    try {
      const scanRequest = {
        target: portScanTarget,
        ports: portRange,
        options: {
          timeout: parseInt(portScanTimeout),
          concurrency: parseInt(portScanConcurrency),
        }
      };
      
      // Send the request to the custom scanner API
      const response = await apiRequest("POST", "/api/scanners/port-scan", scanRequest);
      
      // Parse the response
      const responseData = await response.json();
      
      // Set the scan ID to trigger the scan progress UI
      if (responseData && responseData.scanId) {
        setScanId(responseData.scanId);
        
        toast({
          title: "Port scan started",
          description: `Scanning ${portScanTarget} for open ports`,
        });
      }
      
    } catch (error) {
      console.error("Error starting port scan:", error);
      toast({
        title: "Scan failed",
        description: "There was an error starting the port scan",
        variant: "destructive",
      });
    }
  };
  
  // Run web scan
  const runWebScan = async () => {
    if (!webScanTarget) {
      toast({
        title: "Target required",
        description: "Please enter a target URL",
        variant: "destructive",
      });
      return;
    }
    
    try {
      const scanRequest = {
        url: webScanTarget,
        scanType: webScanType,
        options: {
          followRedirects,
          checkXSS,
          checkSQLi,
          checkHeaders,
        }
      };
      
      // Send the request to the custom scanner API
      const response = await apiRequest("POST", "/api/scanners/web-scan", scanRequest);
      
      // Parse the response
      const responseData = await response.json();
      
      // Set the scan ID to trigger the scan progress UI
      if (responseData && responseData.scanId) {
        setScanId(responseData.scanId);
        
        toast({
          title: "Web security scan started",
          description: `Scanning ${webScanTarget} for vulnerabilities`,
        });
      }
      
    } catch (error) {
      console.error("Error starting web scan:", error);
      toast({
        title: "Scan failed",
        description: "There was an error starting the web security scan",
        variant: "destructive",
      });
    }
  };
  
  // Run code analysis
  const runCodeAnalysis = async () => {
    if (!codeToAnalyze) {
      toast({
        title: "Code required",
        description: "Please enter some code to analyze",
        variant: "destructive",
      });
      return;
    }
    
    try {
      const analysisRequest = {
        code: codeToAnalyze,
        language: codeLanguage,
        options: {
          checkAuthentication: checkAuthCode,
          checkCryptography: checkCryptoCode,
          checkInjection: checkInjectionCode,
          checkSensitiveData: checkSensitiveData,
        }
      };
      
      // Send the request to the custom scanner API
      const response = await apiRequest("POST", "/api/scanners/code-analyze", analysisRequest);
      
      // Parse the response
      const responseData = await response.json();
      
      // Set the scan ID to trigger the scan progress UI
      if (responseData && responseData.scanId) {
        setScanId(responseData.scanId);
        
        toast({
          title: "Code analysis started",
          description: `Analyzing ${codeLanguage} code for vulnerabilities`,
        });
      }
      
    } catch (error) {
      console.error("Error starting code analysis:", error);
      toast({
        title: "Analysis failed",
        description: "There was an error analyzing the code",
        variant: "destructive",
      });
    }
  };
  
  // Reset scan to show input form again
  const resetScan = () => {
    setScanId(null);
  };
  
  // Download scan results
  const downloadResults = () => {
    if (!findings || findings.length === 0) return;
    
    const element = document.createElement("a");
    const file = new Blob([JSON.stringify(findings, null, 2)], { type: "application/json" });
    element.href = URL.createObjectURL(file);
    element.download = `security-scan-results-${new Date().toISOString().split("T")[0]}.json`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };
  
  return (
    <div className="container py-10 max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Custom Security Tools</h1>
        <p className="text-muted-foreground mt-2">
          Powerful security scanning tools built directly into our platform
        </p>
      </div>
      
      {/* Main content - either show scan tools or results */}
      {isScanning ? (
        <ScanningProgress
          target={target || "Target"}
          progress={progress}
          log={logs}
          onStopScan={stopScan}
        />
      ) : findings && findings.length > 0 ? (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-2xl font-semibold">Scan Results</h2>
            <div className="space-x-2">
              <Button onClick={downloadResults}>
                <Download className="h-4 w-4 mr-2" />
                Download Results
              </Button>
              <Button variant="outline" onClick={resetScan}>
                New Scan
              </Button>
            </div>
          </div>
          
          <ScanResults
            findings={findings}
            scanTime={scanTimeAgo}
            severityCounts={severityCounts}
          />
        </div>
      ) : (
        <Tabs defaultValue="port-scanner" className="space-y-4">
          <TabsList className="grid grid-cols-3 w-full">
            <TabsTrigger value="port-scanner">Port Scanner</TabsTrigger>
            <TabsTrigger value="web-scanner">Web Security Scanner</TabsTrigger>
            <TabsTrigger value="code-analyzer">Code Analyzer</TabsTrigger>
          </TabsList>
          
          {/* Port Scanner Tab */}
          <TabsContent value="port-scanner">
            <Card>
              <CardHeader>
                <CardTitle>Port Scanner</CardTitle>
                <CardDescription>
                  Scan hosts for open ports and detect running services
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <Label htmlFor="port-scan-target">Target Hostname/IP</Label>
                    <Input
                      id="port-scan-target"
                      placeholder="example.com or 192.168.1.1"
                      value={portScanTarget}
                      onChange={(e) => setPortScanTarget(e.target.value)}
                    />
                    <p className="text-sm text-muted-foreground">
                      Hostname or IP address to scan
                    </p>
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="port-range">Port Range</Label>
                    <Input
                      id="port-range"
                      placeholder="1-1024,3306,27017"
                      value={portRange}
                      onChange={(e) => setPortRange(e.target.value)}
                    />
                    <p className="text-sm text-muted-foreground">
                      Comma-separated list or range of ports (e.g., 1-1024,3306,8080-8090)
                    </p>
                  </div>
                </div>
                
                <Accordion type="single" collapsible className="w-full">
                  <AccordionItem value="advanced-options">
                    <AccordionTrigger>Advanced Options</AccordionTrigger>
                    <AccordionContent>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div className="space-y-2">
                          <Label htmlFor="port-scan-timeout">Timeout (ms)</Label>
                          <Input
                            id="port-scan-timeout"
                            type="number"
                            min="500"
                            max="10000"
                            value={portScanTimeout}
                            onChange={(e) => setPortScanTimeout(e.target.value)}
                          />
                          <p className="text-sm text-muted-foreground">
                            Connection timeout in milliseconds
                          </p>
                        </div>
                        
                        <div className="space-y-2">
                          <Label htmlFor="port-scan-concurrency">Concurrency</Label>
                          <Input
                            id="port-scan-concurrency"
                            type="number"
                            min="1"
                            max="100"
                            value={portScanConcurrency}
                            onChange={(e) => setPortScanConcurrency(e.target.value)}
                          />
                          <p className="text-sm text-muted-foreground">
                            Number of ports to scan concurrently
                          </p>
                        </div>
                      </div>
                    </AccordionContent>
                  </AccordionItem>
                </Accordion>
              </CardContent>
              <CardFooter className="flex justify-end">
                <Button onClick={runPortScan}>
                  <Play className="h-4 w-4 mr-2" />
                  Start Port Scan
                </Button>
              </CardFooter>
            </Card>
          </TabsContent>
          
          {/* Web Scanner Tab */}
          <TabsContent value="web-scanner">
            <Card>
              <CardHeader>
                <CardTitle>Web Security Scanner</CardTitle>
                <CardDescription>
                  Scan websites for security vulnerabilities and misconfigurations
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="md:col-span-2 space-y-2">
                    <Label htmlFor="web-scan-target">Target URL</Label>
                    <Input
                      id="web-scan-target"
                      placeholder="https://example.com"
                      value={webScanTarget}
                      onChange={(e) => setWebScanTarget(e.target.value)}
                    />
                    <p className="text-sm text-muted-foreground">
                      Complete URL to the website you want to scan
                    </p>
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="web-scan-type">Scan Type</Label>
                    <Select
                      value={webScanType}
                      onValueChange={setWebScanType}
                    >
                      <SelectTrigger id="web-scan-type">
                        <SelectValue placeholder="Select scan type" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="basic">Basic Scan</SelectItem>
                        <SelectItem value="full">Full Scan</SelectItem>
                        <SelectItem value="passive">Passive Scan</SelectItem>
                      </SelectContent>
                    </Select>
                    <p className="text-sm text-muted-foreground">
                      Type of security scan to perform
                    </p>
                  </div>
                </div>
                
                <Accordion type="single" collapsible className="w-full">
                  <AccordionItem value="scan-options">
                    <AccordionTrigger>Scan Options</AccordionTrigger>
                    <AccordionContent>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div className="space-y-2 flex items-center justify-between">
                          <div>
                            <Label htmlFor="follow-redirects">Follow Redirects</Label>
                            <p className="text-sm text-muted-foreground">
                              Follow HTTP redirects during scan
                            </p>
                          </div>
                          <input
                            id="follow-redirects"
                            type="checkbox"
                            checked={followRedirects}
                            onChange={(e) => setFollowRedirects(e.target.checked)}
                            className="toggle"
                          />
                        </div>
                        
                        <div className="space-y-2 flex items-center justify-between">
                          <div>
                            <Label htmlFor="check-xss">Check for XSS</Label>
                            <p className="text-sm text-muted-foreground">
                              Scan for cross-site scripting vulnerabilities
                            </p>
                          </div>
                          <input
                            id="check-xss"
                            type="checkbox"
                            checked={checkXSS}
                            onChange={(e) => setCheckXSS(e.target.checked)}
                            className="toggle"
                          />
                        </div>
                        
                        <div className="space-y-2 flex items-center justify-between">
                          <div>
                            <Label htmlFor="check-sqli">Check for SQL Injection</Label>
                            <p className="text-sm text-muted-foreground">
                              Scan for SQL injection vulnerabilities
                            </p>
                          </div>
                          <input
                            id="check-sqli"
                            type="checkbox"
                            checked={checkSQLi}
                            onChange={(e) => setCheckSQLi(e.target.checked)}
                            className="toggle"
                          />
                        </div>
                        
                        <div className="space-y-2 flex items-center justify-between">
                          <div>
                            <Label htmlFor="check-headers">Check Headers</Label>
                            <p className="text-sm text-muted-foreground">
                              Scan for missing or misconfigured security headers
                            </p>
                          </div>
                          <input
                            id="check-headers"
                            type="checkbox"
                            checked={checkHeaders}
                            onChange={(e) => setCheckHeaders(e.target.checked)}
                            className="toggle"
                          />
                        </div>
                      </div>
                    </AccordionContent>
                  </AccordionItem>
                </Accordion>
              </CardContent>
              <CardFooter className="flex justify-end">
                <Button onClick={runWebScan}>
                  <Play className="h-4 w-4 mr-2" />
                  Start Web Scan
                </Button>
              </CardFooter>
            </Card>
          </TabsContent>
          
          {/* Code Analyzer Tab */}
          <TabsContent value="code-analyzer">
            <Card>
              <CardHeader>
                <CardTitle>Code Analyzer</CardTitle>
                <CardDescription>
                  Analyze source code for security vulnerabilities and best practice violations
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                  <div className="md:col-span-1">
                    <Label htmlFor="code-language">Language</Label>
                    <Select
                      value={codeLanguage}
                      onValueChange={setCodeLanguage}
                    >
                      <SelectTrigger id="code-language">
                        <SelectValue placeholder="Select language" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="javascript">JavaScript</SelectItem>
                        <SelectItem value="python">Python</SelectItem>
                        <SelectItem value="java">Java</SelectItem>
                        <SelectItem value="php">PHP</SelectItem>
                        <SelectItem value="csharp">C#</SelectItem>
                        <SelectItem value="go">Go</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  
                  <div className="md:col-span-3 space-y-2 flex items-center">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="flex items-center space-x-2">
                        <input
                          id="check-auth"
                          type="checkbox"
                          checked={checkAuthCode}
                          onChange={(e) => setCheckAuthCode(e.target.checked)}
                          className="checkbox"
                        />
                        <Label htmlFor="check-auth">Check Authentication</Label>
                      </div>
                      
                      <div className="flex items-center space-x-2">
                        <input
                          id="check-crypto"
                          type="checkbox"
                          checked={checkCryptoCode}
                          onChange={(e) => setCheckCryptoCode(e.target.checked)}
                          className="checkbox"
                        />
                        <Label htmlFor="check-crypto">Check Cryptography</Label>
                      </div>
                      
                      <div className="flex items-center space-x-2">
                        <input
                          id="check-injection"
                          type="checkbox"
                          checked={checkInjectionCode}
                          onChange={(e) => setCheckInjectionCode(e.target.checked)}
                          className="checkbox"
                        />
                        <Label htmlFor="check-injection">Check Injection</Label>
                      </div>
                      
                      <div className="flex items-center space-x-2">
                        <input
                          id="check-sensitive"
                          type="checkbox"
                          checked={checkSensitiveData}
                          onChange={(e) => setCheckSensitiveData(e.target.checked)}
                          className="checkbox"
                        />
                        <Label htmlFor="check-sensitive">Check Sensitive Data</Label>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="code-input">Code to Analyze</Label>
                  <CodeEditor
                    value={codeToAnalyze}
                    onChange={setCodeToAnalyze}
                    language={codeLanguage}
                    className="min-h-[300px]"
                  />
                  <p className="text-sm text-muted-foreground">
                    Paste the code you want to analyze for security vulnerabilities
                  </p>
                </div>
              </CardContent>
              <CardFooter className="flex justify-end">
                <Button onClick={runCodeAnalysis}>
                  <Play className="h-4 w-4 mr-2" />
                  Analyze Code
                </Button>
              </CardFooter>
            </Card>
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}