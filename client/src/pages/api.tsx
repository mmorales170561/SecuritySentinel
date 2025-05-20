import React, { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { ScanningProgress } from "@/components/scanning-progress";
import { ScanResults } from "@/components/scan-results";
import { PageNav } from "@/components/layout/page-nav";
import { useScan } from "@/hooks/use-scan";
import { useToast } from "@/hooks/use-toast";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { CodeEditor } from "@/components/ui/code-editor";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import * as z from "zod";
import { apiRequest } from "@/lib/queryClient";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { isValidUrl } from "@/lib/utils";

// Define schema for API test form validation
const apiTestFormSchema = z.object({
  url: z.string().min(1, "API endpoint URL is required").refine(
    (val) => isValidUrl(val),
    { message: "Invalid URL format" }
  ),
  method: z.enum(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]),
  headers: z.string().optional(),
  body: z.string().optional(),
  authType: z.enum(["none", "basic", "bearer", "apiKey"]).default("none"),
  username: z.string().optional(),
  password: z.string().optional(),
  token: z.string().optional(),
  apiKeyName: z.string().optional(),
  apiKeyValue: z.string().optional(),
  apiKeyLocation: z.enum(["header", "query"]).optional(),
});

export default function ApiTesting() {
  const [scanId, setScanId] = useState<number | null>(null);
  const { isScanning, progress, logs, target, findings, severityCounts, stopScan, scanTimeAgo } = useScan(scanId);
  const { toast } = useToast();
  
  // Initialize form
  const form = useForm<z.infer<typeof apiTestFormSchema>>({
    resolver: zodResolver(apiTestFormSchema),
    defaultValues: {
      url: "",
      method: "GET",
      headers: '{\n  "Content-Type": "application/json"\n}',
      body: '{\n  \n}',
      authType: "none",
      username: "",
      password: "",
      token: "",
      apiKeyName: "",
      apiKeyValue: "",
      apiKeyLocation: "header",
    },
  });
  
  // Form submission handler
  const onSubmit = async (values: z.infer<typeof apiTestFormSchema>) => {
    try {
      // Format headers from JSON string
      let headers = {};
      try {
        if (values.headers) {
          headers = JSON.parse(values.headers);
        }
      } catch (error) {
        toast({
          title: "Invalid Headers JSON",
          description: "Please ensure your headers are in valid JSON format",
          variant: "destructive",
        });
        return;
      }
      
      // Add authentication headers/parameters
      if (values.authType === "basic" && values.username && values.password) {
        const base64Credentials = btoa(`${values.username}:${values.password}`);
        headers = {
          ...headers,
          Authorization: `Basic ${base64Credentials}`,
        };
      } else if (values.authType === "bearer" && values.token) {
        headers = {
          ...headers,
          Authorization: `Bearer ${values.token}`,
        };
      } else if (values.authType === "apiKey" && values.apiKeyName && values.apiKeyValue) {
        if (values.apiKeyLocation === "header") {
          headers = {
            ...headers,
            [values.apiKeyName]: values.apiKeyValue,
          };
        } else if (values.apiKeyLocation === "query") {
          const url = new URL(values.url);
          url.searchParams.append(values.apiKeyName, values.apiKeyValue);
          values.url = url.toString();
        }
      }
      
      // Format request data for API
      const scanRequest = {
        url: values.url,
        method: values.method,
        headers,
        body: values.body && values.method !== "GET" ? values.body : undefined,
        scanType: "api",
      };
      
      // Send the request to start the API scan
      const response = await apiRequest("POST", "/api/scan/web", scanRequest);
      
      // Parse the response
      const responseData = await response.json();
      
      // Set the scan ID to trigger WebSocket connection
      if (responseData && responseData.scanId) {
        setScanId(responseData.scanId);
      }
      
      toast({
        title: "API test started",
        description: `Testing ${values.method} request to ${values.url}`,
      });
      
    } catch (error) {
      console.error("Error starting API test:", error);
      toast({
        title: "Failed to start API test",
        description: "There was an error connecting to the scan service",
        variant: "destructive",
      });
    }
  };
  
  // Watch auth type to show/hide relevant fields
  const authType = form.watch("authType");
  
  return (
    <div className="container py-10 max-w-7xl mx-auto">
      <PageNav
        title="API Security Testing"
        description="Test REST APIs for security vulnerabilities and data leakage"
      />
      
      <Tabs defaultValue="test" className="space-y-4">
        <TabsList>
          <TabsTrigger value="test">API Testing</TabsTrigger>
          {!isScanning && findings.length > 0 && (
            <TabsTrigger value="results">Results</TabsTrigger>
          )}
        </TabsList>
        
        <TabsContent value="test" className="space-y-4">
          {!scanId || (!isScanning && findings.length > 0) ? (
            <Card>
              <CardHeader>
                <CardTitle>API Request Configuration</CardTitle>
                <CardDescription>
                  Configure and send API requests to test for security vulnerabilities
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Form {...form}>
                  <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                    <div className="grid gap-6">
                      <div className="grid grid-cols-4 gap-4">
                        <FormField
                          control={form.control}
                          name="url"
                          render={({ field }) => (
                            <FormItem className="col-span-3">
                              <FormLabel>API Endpoint URL</FormLabel>
                              <FormControl>
                                <Input placeholder="https://api.example.com/endpoint" {...field} />
                              </FormControl>
                              <FormDescription>
                                The complete URL to the API endpoint you want to test
                              </FormDescription>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                        
                        <FormField
                          control={form.control}
                          name="method"
                          render={({ field }) => (
                            <FormItem className="col-span-1">
                              <FormLabel>Method</FormLabel>
                              <Select 
                                onValueChange={field.onChange} 
                                defaultValue={field.value}
                              >
                                <FormControl>
                                  <SelectTrigger>
                                    <SelectValue placeholder="Select HTTP method" />
                                  </SelectTrigger>
                                </FormControl>
                                <SelectContent>
                                  <SelectItem value="GET">GET</SelectItem>
                                  <SelectItem value="POST">POST</SelectItem>
                                  <SelectItem value="PUT">PUT</SelectItem>
                                  <SelectItem value="DELETE">DELETE</SelectItem>
                                  <SelectItem value="PATCH">PATCH</SelectItem>
                                  <SelectItem value="OPTIONS">OPTIONS</SelectItem>
                                </SelectContent>
                              </Select>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      </div>
                      
                      <FormField
                        control={form.control}
                        name="authType"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Authentication</FormLabel>
                            <Select 
                              onValueChange={field.onChange} 
                              defaultValue={field.value}
                            >
                              <FormControl>
                                <SelectTrigger>
                                  <SelectValue placeholder="Select authentication type" />
                                </SelectTrigger>
                              </FormControl>
                              <SelectContent>
                                <SelectItem value="none">No Auth</SelectItem>
                                <SelectItem value="basic">Basic Auth</SelectItem>
                                <SelectItem value="bearer">Bearer Token</SelectItem>
                                <SelectItem value="apiKey">API Key</SelectItem>
                              </SelectContent>
                            </Select>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      {authType === "basic" && (
                        <div className="grid grid-cols-2 gap-4">
                          <FormField
                            control={form.control}
                            name="username"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Username</FormLabel>
                                <FormControl>
                                  <Input {...field} />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                          
                          <FormField
                            control={form.control}
                            name="password"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Password</FormLabel>
                                <FormControl>
                                  <Input type="password" {...field} />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                        </div>
                      )}
                      
                      {authType === "bearer" && (
                        <FormField
                          control={form.control}
                          name="token"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Bearer Token</FormLabel>
                              <FormControl>
                                <Input {...field} />
                              </FormControl>
                              <FormDescription>
                                Token value without "Bearer" prefix
                              </FormDescription>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      )}
                      
                      {authType === "apiKey" && (
                        <div className="grid grid-cols-3 gap-4">
                          <FormField
                            control={form.control}
                            name="apiKeyName"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>API Key Name</FormLabel>
                                <FormControl>
                                  <Input placeholder="X-API-Key" {...field} />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                          
                          <FormField
                            control={form.control}
                            name="apiKeyValue"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>API Key Value</FormLabel>
                                <FormControl>
                                  <Input {...field} />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                          
                          <FormField
                            control={form.control}
                            name="apiKeyLocation"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Location</FormLabel>
                                <Select 
                                  onValueChange={field.onChange} 
                                  defaultValue={field.value}
                                >
                                  <FormControl>
                                    <SelectTrigger>
                                      <SelectValue placeholder="Select location" />
                                    </SelectTrigger>
                                  </FormControl>
                                  <SelectContent>
                                    <SelectItem value="header">Header</SelectItem>
                                    <SelectItem value="query">Query Parameter</SelectItem>
                                  </SelectContent>
                                </Select>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                        </div>
                      )}
                      
                      <Accordion type="single" collapsible className="w-full">
                        <AccordionItem value="headers">
                          <AccordionTrigger>Headers</AccordionTrigger>
                          <AccordionContent>
                            <FormField
                              control={form.control}
                              name="headers"
                              render={({ field }) => (
                                <FormItem>
                                  <FormDescription className="mb-2">
                                    Enter headers as JSON key-value pairs
                                  </FormDescription>
                                  <FormControl>
                                    <Textarea
                                      className="font-mono min-h-[100px]"
                                      {...field}
                                    />
                                  </FormControl>
                                  <FormMessage />
                                </FormItem>
                              )}
                            />
                          </AccordionContent>
                        </AccordionItem>
                        
                        <AccordionItem value="body">
                          <AccordionTrigger>Request Body</AccordionTrigger>
                          <AccordionContent>
                            <FormField
                              control={form.control}
                              name="body"
                              render={({ field }) => (
                                <FormItem>
                                  <FormDescription className="mb-2">
                                    Enter request body as JSON (not used for GET requests)
                                  </FormDescription>
                                  <FormControl>
                                    <Textarea
                                      className="font-mono min-h-[150px]"
                                      {...field}
                                    />
                                  </FormControl>
                                  <FormMessage />
                                </FormItem>
                              )}
                            />
                          </AccordionContent>
                        </AccordionItem>
                      </Accordion>
                    </div>
                    
                    <div className="flex justify-end">
                      <Button type="submit">
                        Run API Test
                      </Button>
                    </div>
                  </form>
                </Form>
              </CardContent>
            </Card>
          ) : (
            <ScanningProgress
              target={target || "API endpoint"}
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