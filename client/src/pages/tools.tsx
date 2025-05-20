import React, { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageNav } from "@/components/layout/page-nav";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { CodeEditor } from "@/components/ui/code-editor";
import { AlertCircle, Download, ExternalLink, Play, Settings } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { apiRequest } from "@/lib/queryClient";

export default function ToolsIntegration() {
  const { toast } = useToast();
  const [burpTarget, setBurpTarget] = useState("");
  const [burpScanType, setBurpScanType] = useState("active");
  const [burpOutput, setBurpOutput] = useState("");
  const [burpLoading, setBurpLoading] = useState(false);
  
  const [zapTarget, setZapTarget] = useState("");
  const [zapScanType, setZapScanType] = useState("spider");
  const [zapOutput, setZapOutput] = useState("");
  const [zapLoading, setZapLoading] = useState(false);
  
  const [nmapTarget, setNmapTarget] = useState("");
  const [nmapFlags, setNmapFlags] = useState("-sV -sC");
  const [nmapOutput, setNmapOutput] = useState("");
  const [nmapLoading, setNmapLoading] = useState(false);
  
  const [semgrepCode, setSemgrepCode] = useState(`// Example JavaScript code to scan
function login(username, password) {
  // Connect to database
  const db = connectToDatabase();
  
  // WARNING: SQL Injection vulnerability!
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  
  // Execute query
  const result = db.query(query);
  
  return result.length > 0;
}`);
  const [semgrepLanguage, setSemgrepLanguage] = useState("javascript");
  const [semgrepRules, setSemgrepRules] = useState("p/security-audit");
  const [semgrepOutput, setSemgrepOutput] = useState("");
  const [semgrepLoading, setSemgrepLoading] = useState(false);
  
  const [sonarqubeProject, setSonarqubeProject] = useState("");
  const [sonarqubeToken, setSonarqubeToken] = useState("");
  const [sonarqubeOutput, setSonarqubeOutput] = useState("");
  const [sonarqubeLoading, setSonarqubeLoading] = useState(false);
  
  // Execute Burp Suite scan
  const runBurpScan = async () => {
    if (!burpTarget) {
      toast({
        title: "Target required",
        description: "Please enter a target URL for the Burp Suite scan",
        variant: "destructive",
      });
      return;
    }
    
    setBurpLoading(true);
    setBurpOutput("Initializing Burp Suite scan...\n");
    
    try {
      // Simulate API request to run a Burp Suite scan
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Simulate scan progress
      setBurpOutput(prev => prev + `Starting ${burpScanType} scan against ${burpTarget}...\n`);
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setBurpOutput(prev => prev + "Scan in progress. Checking for vulnerabilities...\n");
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Generate mock findings based on scan type
      let findings = "";
      if (burpScanType === "active") {
        findings += "[+] VULNERABILITY: Cross-Site Scripting (XSS) found in /search parameter\n";
        findings += "[+] VULNERABILITY: SQL Injection vulnerability detected in /login endpoint\n";
        findings += "[+] INFO: Sensitive information disclosure in HTTP headers\n";
      } else if (burpScanType === "passive") {
        findings += "[+] INFO: Missing security headers detected (X-XSS-Protection)\n";
        findings += "[+] INFO: Cookie missing Secure flag\n";
      } else if (burpScanType === "crawl") {
        findings += "[+] DISCOVERED: Admin panel at /admin\n";
        findings += "[+] DISCOVERED: API endpoints at /api/v1/users\n";
        findings += "[+] DISCOVERED: Login page with potential CSRF vulnerability\n";
      }
      
      setBurpOutput(prev => prev + findings);
      setBurpOutput(prev => prev + "\nScan completed. Results have been saved.\n");
      
      toast({
        title: "Burp Suite scan completed",
        description: "The scan results are available in the output panel",
      });
      
    } catch (error) {
      console.error("Error running Burp Suite scan:", error);
      setBurpOutput(prev => prev + `\nERROR: ${error}\n`);
      
      toast({
        title: "Scan failed",
        description: "There was an error running the Burp Suite scan",
        variant: "destructive",
      });
    } finally {
      setBurpLoading(false);
    }
  };
  
  // Execute ZAP scan
  const runZapScan = async () => {
    if (!zapTarget) {
      toast({
        title: "Target required",
        description: "Please enter a target URL for the ZAP scan",
        variant: "destructive",
      });
      return;
    }
    
    setZapLoading(true);
    setZapOutput("Initializing OWASP ZAP scan...\n");
    
    try {
      // Simulate API request to run a ZAP scan
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Simulate scan progress
      setZapOutput(prev => prev + `Starting ${zapScanType} scan against ${zapTarget}...\n`);
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setZapOutput(prev => prev + "Scan in progress. Analyzing target...\n");
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Generate mock findings based on scan type
      let findings = "";
      if (zapScanType === "spider") {
        findings += "[+] DISCOVERED: 38 unique URLs found\n";
        findings += "[+] DISCOVERED: 5 forms detected\n";
        findings += "[+] DISCOVERED: 3 API endpoints identified\n";
      } else if (zapScanType === "active") {
        findings += "[+] HIGH: Cross-Site Scripting (Reflected) at /product?id=123<script>\n";
        findings += "[+] MEDIUM: X-Frame-Options Header Not Set\n";
        findings += "[+] LOW: Cookie Without Secure Flag\n";
      } else if (zapScanType === "passive") {
        findings += "[+] MEDIUM: Content Security Policy (CSP) Header Not Set\n";
        findings += "[+] LOW: X-Content-Type-Options Header Missing\n";
        findings += "[+] INFO: Retrieved 5 cookie names and values\n";
      }
      
      setZapOutput(prev => prev + findings);
      setZapOutput(prev => prev + "\nScan completed. Results have been saved.\n");
      
      toast({
        title: "OWASP ZAP scan completed",
        description: "The scan results are available in the output panel",
      });
      
    } catch (error) {
      console.error("Error running ZAP scan:", error);
      setZapOutput(prev => prev + `\nERROR: ${error}\n`);
      
      toast({
        title: "Scan failed",
        description: "There was an error running the ZAP scan",
        variant: "destructive",
      });
    } finally {
      setZapLoading(false);
    }
  };
  
  // Execute Nmap scan
  const runNmapScan = async () => {
    if (!nmapTarget) {
      toast({
        title: "Target required",
        description: "Please enter a target IP or hostname for the Nmap scan",
        variant: "destructive",
      });
      return;
    }
    
    setNmapLoading(true);
    setNmapOutput("Initializing Nmap scan...\n");
    
    try {
      // Simulate API request to run a Nmap scan
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Simulate scan progress
      setNmapOutput(prev => prev + `Starting Nmap scan against ${nmapTarget} with flags: ${nmapFlags}...\n`);
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setNmapOutput(prev => prev + "Scan in progress. Discovering open ports and services...\n");
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Generate mock Nmap output
      let output = `
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-18 12:00 UTC
Nmap scan report for ${nmapTarget}
Host is up (0.015s latency).
Not shown: 992 closed ports
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.4p1 (protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:98:b0:ac:c4:39:8b:31:c3 (RSA)
|   256 04:e3:7b:5e:98:9c:9d:4a:6b:67:1c:2b:3c:15:3c:6f (ECDSA)
|_  256 ba:7c:6a:63:35:d7:74:15:ea:ce:21:d1:83:7a:73:52 (ED25519)
80/tcp    open  http        nginx 1.18.0
|_http-title: Welcome to Our Website
|_http-server-header: nginx/1.18.0
443/tcp   open  ssl/https   nginx 1.18.0
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=example.com
| Not valid before: 2023-01-01T00:00:00
|_Not valid after:  2024-01-01T23:59:59
3306/tcp  open  mysql       MySQL 8.0.29
| ssl-cert: Subject: commonName=MySQL_Server_8.0.29_Auto_Generated_Server_Certificate
| Not valid before: 2023-01-01T00:00:00
|_Not valid after:  2024-01-01T23:59:59
8080/tcp  open  http-proxy  Apache/2.4.46 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.46 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.23 seconds
`;
      
      setNmapOutput(prev => prev + output);
      
      toast({
        title: "Nmap scan completed",
        description: "The scan results are available in the output panel",
      });
      
    } catch (error) {
      console.error("Error running Nmap scan:", error);
      setNmapOutput(prev => prev + `\nERROR: ${error}\n`);
      
      toast({
        title: "Scan failed",
        description: "There was an error running the Nmap scan",
        variant: "destructive",
      });
    } finally {
      setNmapLoading(false);
    }
  };
  
  // Execute Semgrep scan
  const runSemgrepScan = async () => {
    if (!semgrepCode) {
      toast({
        title: "Code required",
        description: "Please enter some code to analyze with Semgrep",
        variant: "destructive",
      });
      return;
    }
    
    setSemgrepLoading(true);
    setSemgrepOutput("Initializing Semgrep scan...\n");
    
    try {
      // Simulate API request to run a Semgrep scan
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Simulate scan progress
      setSemgrepOutput(prev => prev + `Starting Semgrep analysis with ${semgrepRules} ruleset...\n`);
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setSemgrepOutput(prev => prev + "Scan in progress. Analyzing code...\n");
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Generate mock Semgrep findings based on code content and language
      let findings = "";
      
      if (semgrepLanguage === "javascript" && semgrepCode.includes("SELECT") && semgrepCode.includes("+")) {
        findings += `
==== SQL Injection detected ====
rule_id: javascript.express.security.audit.sql-injection.string-concat-query
severity: ERROR
pattern: Detected string concatenation in SQL query
location: line 7, column 25
code: 
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";

recommendation: 
  Use parameterized queries with prepared statements:
  const query = "SELECT * FROM users WHERE username = ? AND password = ?";
  const result = db.query(query, [username, password]);
`;
      }
      
      if (semgrepLanguage === "javascript" && semgrepCode.includes("password")) {
        findings += `
==== Hardcoded credentials ====
rule_id: javascript.security.hardcoded-credentials
severity: WARNING
pattern: Potential hardcoded credentials in function parameter
location: line 2, column 16
code: 
  function login(username, password) {

recommendation: 
  Avoid using function parameters named 'password' for clarity. Consider adding validation for empty/null passwords.
`;
      }
      
      if (findings === "") {
        findings = "No issues found in the provided code.\n";
      }
      
      setSemgrepOutput(prev => prev + findings);
      setSemgrepOutput(prev => prev + "\nSemgrep analysis completed.\n");
      
      toast({
        title: "Semgrep analysis completed",
        description: "The scan results are available in the output panel",
      });
      
    } catch (error) {
      console.error("Error running Semgrep scan:", error);
      setSemgrepOutput(prev => prev + `\nERROR: ${error}\n`);
      
      toast({
        title: "Analysis failed",
        description: "There was an error running the Semgrep analysis",
        variant: "destructive",
      });
    } finally {
      setSemgrepLoading(false);
    }
  };
  
  // Execute SonarQube scan
  const runSonarQubeScan = async () => {
    if (!sonarqubeProject) {
      toast({
        title: "Project key required",
        description: "Please enter a project key for the SonarQube scan",
        variant: "destructive",
      });
      return;
    }
    
    setSonarqubeLoading(true);
    setSonarqubeOutput("Initializing SonarQube scan...\n");
    
    try {
      // Simulate API request to run a SonarQube scan
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Simulate scan progress
      setSonarqubeOutput(prev => prev + `Starting SonarQube analysis for project: ${sonarqubeProject}...\n`);
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setSonarqubeOutput(prev => prev + "Scan in progress. Analyzing quality profile...\n");
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Generate mock SonarQube scan results
      const sonarResults = `
==== SonarQube Analysis Results ====
Project: ${sonarqubeProject}
Quality Gate: Passed

Issues Summary:
- Bugs: 12 (2 Critical, 5 Major, 5 Minor)
- Vulnerabilities: 8 (1 Critical, 3 Major, 4 Minor)
- Code Smells: 87 (15 Major, 72 Minor)
- Security Hotspots: 15
- Coverage: 68.5%
- Duplications: 7.2%

Critical Issues:
1. SQL Injection vulnerability in UserController.java:152
2. Hardcoded credentials in DatabaseConfig.java:34
3. Cross-Site Scripting (XSS) in ProfileView.js:78

View complete results on the SonarQube dashboard.
`;
      
      setSonarqubeOutput(prev => prev + sonarResults);
      
      toast({
        title: "SonarQube analysis completed",
        description: "The scan results are available in the output panel",
      });
      
    } catch (error) {
      console.error("Error running SonarQube scan:", error);
      setSonarqubeOutput(prev => prev + `\nERROR: ${error}\n`);
      
      toast({
        title: "Analysis failed",
        description: "There was an error running the SonarQube analysis",
        variant: "destructive",
      });
    } finally {
      setSonarqubeLoading(false);
    }
  };
  
  // Download scan results
  const downloadResults = (content: string, tool: string) => {
    const element = document.createElement("a");
    const file = new Blob([content], { type: "text/plain" });
    element.href = URL.createObjectURL(file);
    element.download = `${tool.toLowerCase().replace(/\s/g, "-")}-scan-results-${new Date().toISOString().split("T")[0]}.txt`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };
  
  return (
    <div className="container py-10 max-w-7xl mx-auto">
      <PageNav
        title="Security Tools Integration"
        description="Access and run popular security tools directly from the web interface"
      />
      
      <Alert className="mb-6">
        <AlertCircle className="h-4 w-4" />
        <AlertTitle>Tool Integration</AlertTitle>
        <AlertDescription>
          The tools below simulate interactions with common security scanning tools. In a production environment, these would connect to actual tool installations or APIs.
        </AlertDescription>
      </Alert>
      
      <Tabs defaultValue="burp" className="space-y-4">
        <TabsList className="grid grid-cols-5 w-full">
          <TabsTrigger value="burp">Burp Suite</TabsTrigger>
          <TabsTrigger value="zap">OWASP ZAP</TabsTrigger>
          <TabsTrigger value="nmap">Nmap</TabsTrigger>
          <TabsTrigger value="semgrep">Semgrep</TabsTrigger>
          <TabsTrigger value="sonarqube">SonarQube</TabsTrigger>
        </TabsList>
        
        {/* Burp Suite Tab */}
        <TabsContent value="burp">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <span className="mr-2">Burp Suite</span>
                <span className="text-xs px-2 py-1 rounded-full bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-300">Professional Edition</span>
              </CardTitle>
              <CardDescription>
                Run Burp Suite Professional scans against web applications
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
                <div className="md:col-span-3">
                  <Label htmlFor="burp-target">Target URL</Label>
                  <Input
                    id="burp-target"
                    placeholder="https://example.com"
                    value={burpTarget}
                    onChange={(e) => setBurpTarget(e.target.value)}
                    className="mt-1"
                  />
                </div>
                
                <div>
                  <Label htmlFor="burp-scan-type">Scan Type</Label>
                  <Select
                    value={burpScanType}
                    onValueChange={setBurpScanType}
                  >
                    <SelectTrigger className="mt-1">
                      <SelectValue placeholder="Select scan type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="active">Active Scan</SelectItem>
                      <SelectItem value="passive">Passive Scan</SelectItem>
                      <SelectItem value="crawl">Crawl</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              
              <div className="mb-4">
                <div className="flex justify-between items-center mb-2">
                  <Label>Output</Label>
                  <Button 
                    variant="outline" 
                    size="sm" 
                    onClick={() => downloadResults(burpOutput, "Burp Suite")}
                    disabled={!burpOutput}
                  >
                    <Download className="h-4 w-4 mr-2" />
                    Save
                  </Button>
                </div>
                <Textarea
                  value={burpOutput}
                  readOnly
                  className="font-mono h-80 bg-muted"
                />
              </div>
            </CardContent>
            <CardFooter className="flex justify-between">
              <div className="flex gap-2">
                <Button variant="outline">
                  <Settings className="h-4 w-4 mr-2" />
                  Configure
                </Button>
                <Button variant="outline">
                  <ExternalLink className="h-4 w-4 mr-2" />
                  Open in Burp
                </Button>
              </div>
              <Button onClick={runBurpScan} disabled={burpLoading}>
                {burpLoading ? "Running Scan..." : "Run Scan"}
              </Button>
            </CardFooter>
          </Card>
        </TabsContent>
        
        {/* OWASP ZAP Tab */}
        <TabsContent value="zap">
          <Card>
            <CardHeader>
              <CardTitle>OWASP ZAP</CardTitle>
              <CardDescription>
                Run OWASP Zed Attack Proxy (ZAP) scans against web applications
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
                <div className="md:col-span-3">
                  <Label htmlFor="zap-target">Target URL</Label>
                  <Input
                    id="zap-target"
                    placeholder="https://example.com"
                    value={zapTarget}
                    onChange={(e) => setZapTarget(e.target.value)}
                    className="mt-1"
                  />
                </div>
                
                <div>
                  <Label htmlFor="zap-scan-type">Scan Type</Label>
                  <Select
                    value={zapScanType}
                    onValueChange={setZapScanType}
                  >
                    <SelectTrigger className="mt-1">
                      <SelectValue placeholder="Select scan type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="spider">Spider</SelectItem>
                      <SelectItem value="active">Active Scan</SelectItem>
                      <SelectItem value="passive">Passive Scan</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              
              <div className="mb-4">
                <div className="flex justify-between items-center mb-2">
                  <Label>Output</Label>
                  <Button 
                    variant="outline" 
                    size="sm" 
                    onClick={() => downloadResults(zapOutput, "OWASP ZAP")}
                    disabled={!zapOutput}
                  >
                    <Download className="h-4 w-4 mr-2" />
                    Save
                  </Button>
                </div>
                <Textarea
                  value={zapOutput}
                  readOnly
                  className="font-mono h-80 bg-muted"
                />
              </div>
            </CardContent>
            <CardFooter className="flex justify-between">
              <div className="flex gap-2">
                <Button variant="outline">
                  <Settings className="h-4 w-4 mr-2" />
                  Configure
                </Button>
                <Button variant="outline">
                  <ExternalLink className="h-4 w-4 mr-2" />
                  Open in ZAP
                </Button>
              </div>
              <Button onClick={runZapScan} disabled={zapLoading}>
                {zapLoading ? "Running Scan..." : "Run Scan"}
              </Button>
            </CardFooter>
          </Card>
        </TabsContent>
        
        {/* Nmap Tab */}
        <TabsContent value="nmap">
          <Card>
            <CardHeader>
              <CardTitle>Nmap</CardTitle>
              <CardDescription>
                Run Nmap network scans against hosts and networks
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
                <div className="md:col-span-3">
                  <Label htmlFor="nmap-target">Target IP/Hostname</Label>
                  <Input
                    id="nmap-target"
                    placeholder="192.168.1.1 or example.com"
                    value={nmapTarget}
                    onChange={(e) => setNmapTarget(e.target.value)}
                    className="mt-1"
                  />
                </div>
                
                <div>
                  <Label htmlFor="nmap-flags">Nmap Flags</Label>
                  <Input
                    id="nmap-flags"
                    placeholder="-sV -sC"
                    value={nmapFlags}
                    onChange={(e) => setNmapFlags(e.target.value)}
                    className="mt-1"
                  />
                </div>
              </div>
              
              <div className="mb-4">
                <div className="flex justify-between items-center mb-2">
                  <Label>Output</Label>
                  <Button 
                    variant="outline" 
                    size="sm" 
                    onClick={() => downloadResults(nmapOutput, "Nmap")}
                    disabled={!nmapOutput}
                  >
                    <Download className="h-4 w-4 mr-2" />
                    Save
                  </Button>
                </div>
                <Textarea
                  value={nmapOutput}
                  readOnly
                  className="font-mono h-80 bg-muted"
                />
              </div>
            </CardContent>
            <CardFooter className="flex justify-between">
              <div className="flex gap-2">
                <Button variant="outline">
                  <Settings className="h-4 w-4 mr-2" />
                  Configure
                </Button>
              </div>
              <Button onClick={runNmapScan} disabled={nmapLoading}>
                {nmapLoading ? "Running Scan..." : "Run Scan"}
              </Button>
            </CardFooter>
          </Card>
        </TabsContent>
        
        {/* Semgrep Tab */}
        <TabsContent value="semgrep">
          <Card>
            <CardHeader>
              <CardTitle>Semgrep</CardTitle>
              <CardDescription>
                Analyze code for security vulnerabilities using Semgrep
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div>
                  <Label htmlFor="semgrep-language">Language</Label>
                  <Select
                    value={semgrepLanguage}
                    onValueChange={setSemgrepLanguage}
                  >
                    <SelectTrigger className="mt-1">
                      <SelectValue placeholder="Select language" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="javascript">JavaScript</SelectItem>
                      <SelectItem value="python">Python</SelectItem>
                      <SelectItem value="java">Java</SelectItem>
                      <SelectItem value="go">Go</SelectItem>
                      <SelectItem value="ruby">Ruby</SelectItem>
                      <SelectItem value="php">PHP</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <div>
                  <Label htmlFor="semgrep-ruleset">Ruleset</Label>
                  <Select
                    value={semgrepRules}
                    onValueChange={setSemgrepRules}
                  >
                    <SelectTrigger className="mt-1">
                      <SelectValue placeholder="Select ruleset" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="p/security-audit">Security Audit</SelectItem>
                      <SelectItem value="p/owasp-top-ten">OWASP Top 10</SelectItem>
                      <SelectItem value="p/ci">CI Rules</SelectItem>
                      <SelectItem value="p/javascript">JavaScript Rules</SelectItem>
                      <SelectItem value="p/python">Python Rules</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              
              <div className="mb-6">
                <Label htmlFor="semgrep-code">Code to Analyze</Label>
                <div className="mt-1">
                  <CodeEditor
                    value={semgrepCode}
                    onChange={setSemgrepCode}
                    language={semgrepLanguage}
                    className="h-60"
                  />
                </div>
              </div>
              
              <div className="mb-4">
                <div className="flex justify-between items-center mb-2">
                  <Label>Analysis Results</Label>
                  <Button 
                    variant="outline" 
                    size="sm" 
                    onClick={() => downloadResults(semgrepOutput, "Semgrep")}
                    disabled={!semgrepOutput}
                  >
                    <Download className="h-4 w-4 mr-2" />
                    Save
                  </Button>
                </div>
                <Textarea
                  value={semgrepOutput}
                  readOnly
                  className="font-mono h-40 bg-muted"
                />
              </div>
            </CardContent>
            <CardFooter className="flex justify-between">
              <div className="flex gap-2">
                <Button variant="outline">
                  <Settings className="h-4 w-4 mr-2" />
                  Configure
                </Button>
              </div>
              <Button onClick={runSemgrepScan} disabled={semgrepLoading}>
                {semgrepLoading ? "Analyzing..." : "Analyze Code"}
              </Button>
            </CardFooter>
          </Card>
        </TabsContent>
        
        {/* SonarQube Tab */}
        <TabsContent value="sonarqube">
          <Card>
            <CardHeader>
              <CardTitle>SonarQube</CardTitle>
              <CardDescription>
                Run SonarQube analysis on projects for code quality and security issues
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div>
                  <Label htmlFor="sonarqube-project">Project Key</Label>
                  <Input
                    id="sonarqube-project"
                    placeholder="my-project"
                    value={sonarqubeProject}
                    onChange={(e) => setSonarqubeProject(e.target.value)}
                    className="mt-1"
                  />
                </div>
                
                <div>
                  <Label htmlFor="sonarqube-token">Authentication Token (optional)</Label>
                  <Input
                    id="sonarqube-token"
                    type="password"
                    placeholder="SonarQube token"
                    value={sonarqubeToken}
                    onChange={(e) => setSonarqubeToken(e.target.value)}
                    className="mt-1"
                  />
                </div>
              </div>
              
              <div className="mb-4">
                <div className="flex justify-between items-center mb-2">
                  <Label>Analysis Results</Label>
                  <Button 
                    variant="outline" 
                    size="sm" 
                    onClick={() => downloadResults(sonarqubeOutput, "SonarQube")}
                    disabled={!sonarqubeOutput}
                  >
                    <Download className="h-4 w-4 mr-2" />
                    Save
                  </Button>
                </div>
                <Textarea
                  value={sonarqubeOutput}
                  readOnly
                  className="font-mono h-80 bg-muted"
                />
              </div>
            </CardContent>
            <CardFooter className="flex justify-between">
              <div className="flex gap-2">
                <Button variant="outline">
                  <Settings className="h-4 w-4 mr-2" />
                  Configure
                </Button>
                <Button variant="outline">
                  <ExternalLink className="h-4 w-4 mr-2" />
                  Open in SonarQube
                </Button>
              </div>
              <Button onClick={runSonarQubeScan} disabled={sonarqubeLoading}>
                {sonarqubeLoading ? "Analyzing..." : "Run Analysis"}
              </Button>
            </CardFooter>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}