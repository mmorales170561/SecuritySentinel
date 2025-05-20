import React, { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { ScanningProgress } from "@/components/scanning-progress";
import { ScanResults } from "@/components/scan-results";
import { useScan } from "@/hooks/use-scan";
import { useToast } from "@/hooks/use-toast";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import * as z from "zod";
import { apiRequest } from "@/lib/queryClient";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";

// Define schema for repository scan form validation
const repoScanFormSchema = z.object({
  repositoryUrl: z.string().min(1, "Repository URL is required")
    .refine(
      (val) => val.startsWith("https://github.com/") || 
               val.startsWith("https://gitlab.com/") ||
               val.startsWith("https://bitbucket.org/"),
      { message: "Must be a GitHub, GitLab, or Bitbucket repository URL" }
    ),
  branch: z.string().optional(),
  scanType: z.enum(["code", "secrets", "dependencies", "compliance", "full"]),
  options: z.object({
    includePrivateData: z.boolean().default(false),
    analyzeCommitHistory: z.boolean().default(false),
    enableDeepScan: z.boolean().default(false),
    includeDependencies: z.boolean().default(true),
    maxDepth: z.number().min(1).max(10).default(3),
    searchTerms: z.string().optional(),
  }),
  authentication: z.object({
    useAuth: z.boolean().default(false),
    token: z.string().optional(),
  }),
});

export default function RepositoryScan() {
  const [scanId, setScanId] = useState<number | null>(null);
  const { isScanning, progress, logs, target, findings, severityCounts, stopScan, scanTimeAgo } = useScan(scanId);
  const { toast } = useToast();
  
  // Initialize form
  const form = useForm<z.infer<typeof repoScanFormSchema>>({
    resolver: zodResolver(repoScanFormSchema),
    defaultValues: {
      repositoryUrl: "",
      branch: "main",
      scanType: "code",
      options: {
        includePrivateData: false,
        analyzeCommitHistory: false,
        enableDeepScan: false,
        includeDependencies: true,
        maxDepth: 3,
        searchTerms: "",
      },
      authentication: {
        useAuth: false,
        token: "",
      },
    },
  });
  
  // Form submission handler
  const onSubmit = async (values: z.infer<typeof repoScanFormSchema>) => {
    try {
      // Create scan request formatted for the API
      const scanRequest = {
        url: values.repositoryUrl,
        scanType: "repository",
        options: {
          ...values.options,
          branch: values.branch,
          repoScanType: values.scanType,
          token: values.authentication.useAuth ? values.authentication.token : undefined,
        },
      };
      
      // Send the request to the scan API
      const response = await apiRequest("POST", "/api/scan/web", scanRequest);
      
      // Parse the response
      const responseData = await response.json();
      
      // Set the scan ID to trigger WebSocket connection
      if (responseData && responseData.scanId) {
        setScanId(responseData.scanId);
      }
      
      toast({
        title: "Repository scan started",
        description: `Scanning ${values.repositoryUrl}`,
      });
      
    } catch (error) {
      console.error("Error starting repository scan:", error);
      toast({
        title: "Failed to start scan",
        description: "There was an error connecting to the scan service",
        variant: "destructive",
      });
    }
  };
  
  // Track if auth is enabled
  const useAuth = form.watch("authentication.useAuth");
  
  return (
    <div className="container py-10 max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Repository Security Scan</h1>
        <p className="text-muted-foreground mt-2">
          Analyze repositories for security vulnerabilities, credentials leakage, and outdated dependencies
        </p>
      </div>
      
      <Tabs defaultValue="scan" className="space-y-4">
        <TabsList>
          <TabsTrigger value="scan">Repository Scanner</TabsTrigger>
          {!isScanning && findings.length > 0 && (
            <TabsTrigger value="results">Results</TabsTrigger>
          )}
        </TabsList>
        
        <TabsContent value="scan" className="space-y-4">
          {!scanId || (!isScanning && findings.length > 0) ? (
            <Card>
              <CardHeader>
                <CardTitle>Repository Scan Configuration</CardTitle>
                <CardDescription>
                  Configure a security scan for your GitHub, GitLab, or Bitbucket repository
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Form {...form}>
                  <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                    <FormField
                      control={form.control}
                      name="repositoryUrl"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Repository URL</FormLabel>
                          <FormControl>
                            <Input placeholder="https://github.com/username/repository" {...field} />
                          </FormControl>
                          <FormDescription>
                            Enter the full URL to the repository you want to scan
                          </FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    
                    <div className="grid grid-cols-2 gap-4">
                      <FormField
                        control={form.control}
                        name="branch"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Branch</FormLabel>
                            <FormControl>
                              <Input placeholder="main" {...field} />
                            </FormControl>
                            <FormDescription>
                              Leave empty to scan the default branch
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <FormField
                        control={form.control}
                        name="scanType"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Scan Type</FormLabel>
                            <Select 
                              onValueChange={field.onChange} 
                              defaultValue={field.value}
                            >
                              <FormControl>
                                <SelectTrigger>
                                  <SelectValue placeholder="Select a scan type" />
                                </SelectTrigger>
                              </FormControl>
                              <SelectContent>
                                <SelectItem value="code">Code Security Analysis</SelectItem>
                                <SelectItem value="secrets">Secret Detection</SelectItem>
                                <SelectItem value="dependencies">Dependency Scanning</SelectItem>
                                <SelectItem value="compliance">Compliance Check</SelectItem>
                                <SelectItem value="full">Full Security Scan</SelectItem>
                              </SelectContent>
                            </Select>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>
                    
                    <Accordion type="single" collapsible className="w-full">
                      <AccordionItem value="auth">
                        <AccordionTrigger>Authentication</AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-4">
                            <FormField
                              control={form.control}
                              name="authentication.useAuth"
                              render={({ field }) => (
                                <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                                  <div className="space-y-0.5">
                                    <FormLabel>Use Authentication</FormLabel>
                                    <FormDescription>
                                      Required for private repositories
                                    </FormDescription>
                                  </div>
                                  <FormControl>
                                    <Switch
                                      checked={field.value}
                                      onCheckedChange={field.onChange}
                                    />
                                  </FormControl>
                                </FormItem>
                              )}
                            />
                            
                            {useAuth && (
                              <FormField
                                control={form.control}
                                name="authentication.token"
                                render={({ field }) => (
                                  <FormItem>
                                    <FormLabel>Access Token</FormLabel>
                                    <FormControl>
                                      <Input type="password" {...field} />
                                    </FormControl>
                                    <FormDescription>
                                      Personal access token with read permissions
                                    </FormDescription>
                                    <FormMessage />
                                  </FormItem>
                                )}
                              />
                            )}
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                      
                      <AccordionItem value="options">
                        <AccordionTrigger>Scan Options</AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-4">
                            <FormField
                              control={form.control}
                              name="options.maxDepth"
                              render={({ field }) => (
                                <FormItem>
                                  <FormLabel>Maximum Scan Depth</FormLabel>
                                  <FormControl>
                                    <Input
                                      type="number"
                                      min={1}
                                      max={10}
                                      {...field}
                                      onChange={(e) => field.onChange(parseInt(e.target.value) || 3)}
                                    />
                                  </FormControl>
                                  <FormDescription>
                                    Maximum directory depth to scan (1-10)
                                  </FormDescription>
                                  <FormMessage />
                                </FormItem>
                              )}
                            />
                            
                            <FormField
                              control={form.control}
                              name="options.searchTerms"
                              render={({ field }) => (
                                <FormItem>
                                  <FormLabel>Custom Search Terms</FormLabel>
                                  <FormControl>
                                    <Input placeholder="password,api_key,secret,token" {...field} />
                                  </FormControl>
                                  <FormDescription>
                                    Custom terms to search for (comma separated)
                                  </FormDescription>
                                  <FormMessage />
                                </FormItem>
                              )}
                            />
                            
                            <FormField
                              control={form.control}
                              name="options.includeDependencies"
                              render={({ field }) => (
                                <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                                  <div className="space-y-0.5">
                                    <FormLabel>Analyze Dependencies</FormLabel>
                                    <FormDescription>
                                      Check for vulnerable dependencies
                                    </FormDescription>
                                  </div>
                                  <FormControl>
                                    <Switch
                                      checked={field.value}
                                      onCheckedChange={field.onChange}
                                    />
                                  </FormControl>
                                </FormItem>
                              )}
                            />
                            
                            <FormField
                              control={form.control}
                              name="options.analyzeCommitHistory"
                              render={({ field }) => (
                                <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                                  <div className="space-y-0.5">
                                    <FormLabel>Analyze Commit History</FormLabel>
                                    <FormDescription>
                                      Look for secrets in commit history (slower)
                                    </FormDescription>
                                  </div>
                                  <FormControl>
                                    <Switch
                                      checked={field.value}
                                      onCheckedChange={field.onChange}
                                    />
                                  </FormControl>
                                </FormItem>
                              )}
                            />
                            
                            <FormField
                              control={form.control}
                              name="options.enableDeepScan"
                              render={({ field }) => (
                                <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                                  <div className="space-y-0.5">
                                    <FormLabel>Deep Scan</FormLabel>
                                    <FormDescription>
                                      More thorough analysis (significantly slower)
                                    </FormDescription>
                                  </div>
                                  <FormControl>
                                    <Switch
                                      checked={field.value}
                                      onCheckedChange={field.onChange}
                                    />
                                  </FormControl>
                                </FormItem>
                              )}
                            />
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                    </Accordion>
                    
                    <div className="flex justify-end">
                      <Button type="submit">
                        Start Repository Scan
                      </Button>
                    </div>
                  </form>
                </Form>
              </CardContent>
            </Card>
          ) : (
            <ScanningProgress
              target={target || "Repository"}
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