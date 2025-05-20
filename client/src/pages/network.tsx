import React, { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ScanningProgress } from "@/components/scanning-progress";
import { ScanResults } from "@/components/scan-results";
import { PageNav } from "@/components/layout/page-nav";
import { useScan } from "@/hooks/use-scan";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import * as z from "zod";
import { isValidUrl } from "@/lib/utils";

// Define schema for form validation
const formSchema = z.object({
  target: z.string().min(1, "Target is required").refine(
    (val) => isValidUrl(val) || /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)$/.test(val),
    { message: "Invalid IP address, CIDR range, or URL" }
  ),
  scanType: z.enum(["basic", "full", "port", "vulnerability"], {
    required_error: "Please select a scan type",
  }),
  options: z.object({
    portRange: z.string().optional(),
    scanSpeed: z.enum(["slow", "normal", "aggressive"]).optional(),
    detectOS: z.boolean().optional(),
    serviceDetection: z.boolean().optional(),
  }).optional(),
});

export default function NetworkScan() {
  const [scanId, setScanId] = useState<number | null>(null);
  const { isScanning, progress, logs, target, findings, severityCounts, stopScan, scanTimeAgo } = useScan(scanId);
  const { toast } = useToast();
  
  // Initialize form
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      target: "",
      scanType: "basic",
      options: {
        portRange: "1-1024",
        scanSpeed: "normal",
        detectOS: true,
        serviceDetection: true,
      },
    },
  });
  
  // Submit handler
  const onSubmit = async (values: z.infer<typeof formSchema>) => {
    try {
      // Create a scan request formatted for the API
      const scanRequest = {
        url: values.target,
        scanType: values.scanType,
        options: values.options,
      };
      
      // Send the request to the scan API
      const response = await apiRequest("POST", "/api/scan/web", scanRequest);
      
      // Parse the response to get the scan ID
      const responseData = await response.json();
      
      // Set the scan ID to trigger WebSocket connection
      if (responseData && responseData.scanId) {
        setScanId(responseData.scanId);
      }
      
      toast({
        title: "Network scan started",
        description: `Target: ${values.target}`,
      });
      
    } catch (error) {
      console.error("Error starting scan:", error);
      toast({
        title: "Failed to start scan",
        description: "There was an error connecting to the scan service",
        variant: "destructive",
      });
    }
  };
  
  // Form error handler
  const onError = (errors: any) => {
    console.error("Form errors:", errors);
  };
  
  return (
    <div className="container py-10 max-w-7xl mx-auto">
      <PageNav 
        title="Network Scan" 
        description="Discover open ports, services, and vulnerabilities in your network" 
      />
      
      <Tabs defaultValue="scan" className="space-y-4">
        <TabsList>
          <TabsTrigger value="scan">Network Scanner</TabsTrigger>
          {!isScanning && findings.length > 0 && (
            <TabsTrigger value="results">Results</TabsTrigger>
          )}
        </TabsList>
        
        <TabsContent value="scan" className="space-y-4">
          {!scanId || (!isScanning && findings.length > 0) ? (
            <Card>
              <CardHeader>
                <CardTitle>Network Scan Configuration</CardTitle>
                <CardDescription>
                  Configure and run a network scan against a target IP, CIDR range, or hostname
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Form {...form}>
                  <form onSubmit={form.handleSubmit(onSubmit, onError)} className="space-y-6">
                    <FormField
                      control={form.control}
                      name="target"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Target IP/CIDR/Hostname</FormLabel>
                          <FormControl>
                            <Input placeholder="192.168.1.1 or example.com" {...field} />
                          </FormControl>
                          <FormDescription>
                            Enter an IP address, CIDR range (e.g., 192.168.1.0/24), or hostname
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
                              <SelectItem value="basic">Basic Port Scan</SelectItem>
                              <SelectItem value="full">Full Network Scan</SelectItem>
                              <SelectItem value="port">Advanced Port Scan</SelectItem>
                              <SelectItem value="vulnerability">Vulnerability Assessment</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormDescription>
                            Choose the type of network scan to perform
                          </FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    
                    <FormField
                      control={form.control}
                      name="options.portRange"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Port Range</FormLabel>
                          <FormControl>
                            <Input placeholder="1-1024" {...field} />
                          </FormControl>
                          <FormDescription>
                            Specify port ranges (e.g., 80,443,8080 or 1-1024)
                          </FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    
                    <FormField
                      control={form.control}
                      name="options.scanSpeed"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Scan Speed</FormLabel>
                          <Select 
                            onValueChange={field.onChange} 
                            defaultValue={field.value}
                          >
                            <FormControl>
                              <SelectTrigger>
                                <SelectValue placeholder="Select scan speed" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="slow">Slow (Stealthy)</SelectItem>
                              <SelectItem value="normal">Normal</SelectItem>
                              <SelectItem value="aggressive">Aggressive (Fast)</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormDescription>
                            Faster scans may be detected by security systems
                          </FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    
                    <div className="flex justify-end">
                      <Button type="submit">
                        Start Network Scan
                      </Button>
                    </div>
                  </form>
                </Form>
              </CardContent>
            </Card>
          ) : (
            <ScanningProgress
              target={target || "Network target"}
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