import React, { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import * as z from "zod";
import { Separator } from "@/components/ui/separator";
import { apiRequest } from "@/lib/queryClient";

// Define schema for API credentials form validation
const apiCredentialsSchema = z.object({
  shodan: z.object({
    enabled: z.boolean().default(false),
    apiKey: z.string().min(1, "API key is required").optional(),
  }),
  virustotal: z.object({
    enabled: z.boolean().default(false),
    apiKey: z.string().min(1, "API key is required").optional(),
  }),
  securitytrails: z.object({
    enabled: z.boolean().default(false),
    apiKey: z.string().min(1, "API key is required").optional(),
  }),
  censys: z.object({
    enabled: z.boolean().default(false),
    apiKey: z.string().min(1, "API key is required").optional(),
    apiSecret: z.string().min(1, "API secret is required").optional(),
  }),
});

// Define schema for general settings form validation
const generalSettingsSchema = z.object({
  scanDefaults: z.object({
    defaultScanDepth: z.number().min(1).max(5).default(3),
    defaultScanTimeout: z.number().min(30).max(900).default(300),
    maxConcurrentScans: z.number().min(1).max(10).default(3),
  }),
  userInterface: z.object({
    theme: z.enum(["light", "dark", "system"]).default("system"),
    enableAnimations: z.boolean().default(true),
    showDetailedFindings: z.boolean().default(true),
  }),
  notifications: z.object({
    emailNotifications: z.boolean().default(false),
    emailAddress: z.string().email().optional(),
    notifyOnScanComplete: z.boolean().default(true),
    notifyOnHighSeverity: z.boolean().default(true),
  }),
});

// Define schema for advanced settings form validation
const advancedSettingsSchema = z.object({
  scanEngine: z.object({
    userAgentString: z.string().optional(),
    requestsPerSecond: z.number().min(1).max(100).default(10),
    followRedirects: z.boolean().default(true),
    maxRedirects: z.number().min(1).max(10).default(5),
  }),
  proxy: z.object({
    useProxy: z.boolean().default(false),
    proxyUrl: z.string().optional(),
    proxyUsername: z.string().optional(),
    proxyPassword: z.string().optional(),
  }),
  database: z.object({
    retentionPeriod: z.number().min(7).max(365).default(90),
    automaticPruning: z.boolean().default(true),
  }),
});

export default function Settings() {
  const { toast } = useToast();
  const [savingCredentials, setSavingCredentials] = useState(false);
  const [savingGeneral, setSavingGeneral] = useState(false);
  const [savingAdvanced, setSavingAdvanced] = useState(false);
  
  // Initialize forms
  const apiCredentialsForm = useForm<z.infer<typeof apiCredentialsSchema>>({
    resolver: zodResolver(apiCredentialsSchema),
    defaultValues: {
      shodan: {
        enabled: false,
        apiKey: "",
      },
      virustotal: {
        enabled: false,
        apiKey: "",
      },
      securitytrails: {
        enabled: false,
        apiKey: "",
      },
      censys: {
        enabled: false,
        apiKey: "",
        apiSecret: "",
      },
    },
  });
  
  const generalSettingsForm = useForm<z.infer<typeof generalSettingsSchema>>({
    resolver: zodResolver(generalSettingsSchema),
    defaultValues: {
      scanDefaults: {
        defaultScanDepth: 3,
        defaultScanTimeout: 300,
        maxConcurrentScans: 3,
      },
      userInterface: {
        theme: "system",
        enableAnimations: true,
        showDetailedFindings: true,
      },
      notifications: {
        emailNotifications: false,
        emailAddress: "",
        notifyOnScanComplete: true,
        notifyOnHighSeverity: true,
      },
    },
  });
  
  const advancedSettingsForm = useForm<z.infer<typeof advancedSettingsSchema>>({
    resolver: zodResolver(advancedSettingsSchema),
    defaultValues: {
      scanEngine: {
        userAgentString: "Mozilla/5.0 (compatible; SecurityScannerBot/1.0)",
        requestsPerSecond: 10,
        followRedirects: true,
        maxRedirects: 5,
      },
      proxy: {
        useProxy: false,
        proxyUrl: "",
        proxyUsername: "",
        proxyPassword: "",
      },
      database: {
        retentionPeriod: 90,
        automaticPruning: true,
      },
    },
  });
  
  // Form submission handlers
  const onSaveApiCredentials = async (values: z.infer<typeof apiCredentialsSchema>) => {
    try {
      setSavingCredentials(true);
      
      // Simulate API call to save credentials
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      toast({
        title: "API credentials saved",
        description: "Your external service credentials have been updated",
      });
      
    } catch (error) {
      console.error("Error saving API credentials:", error);
      toast({
        title: "Failed to save credentials",
        description: "There was an error saving your credentials",
        variant: "destructive",
      });
    } finally {
      setSavingCredentials(false);
    }
  };
  
  const onSaveGeneralSettings = async (values: z.infer<typeof generalSettingsSchema>) => {
    try {
      setSavingGeneral(true);
      
      // Simulate API call to save general settings
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      toast({
        title: "Settings saved",
        description: "Your general settings have been updated",
      });
      
      // Apply theme setting immediately if changed
      const theme = values.userInterface.theme;
      if (theme === "dark") {
        document.documentElement.classList.add("dark");
      } else if (theme === "light") {
        document.documentElement.classList.remove("dark");
      } else {
        // Handle system preference
        const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
        if (prefersDark) {
          document.documentElement.classList.add("dark");
        } else {
          document.documentElement.classList.remove("dark");
        }
      }
      
    } catch (error) {
      console.error("Error saving general settings:", error);
      toast({
        title: "Failed to save settings",
        description: "There was an error saving your settings",
        variant: "destructive",
      });
    } finally {
      setSavingGeneral(false);
    }
  };
  
  const onSaveAdvancedSettings = async (values: z.infer<typeof advancedSettingsSchema>) => {
    try {
      setSavingAdvanced(true);
      
      // Simulate API call to save advanced settings
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      toast({
        title: "Advanced settings saved",
        description: "Your advanced settings have been updated",
      });
      
    } catch (error) {
      console.error("Error saving advanced settings:", error);
      toast({
        title: "Failed to save settings",
        description: "There was an error saving your settings",
        variant: "destructive",
      });
    } finally {
      setSavingAdvanced(false);
    }
  };
  
  // Watch form values for conditional rendering
  const shodanEnabled = apiCredentialsForm.watch("shodan.enabled");
  const virustotalEnabled = apiCredentialsForm.watch("virustotal.enabled");
  const securitytrailsEnabled = apiCredentialsForm.watch("securitytrails.enabled");
  const censysEnabled = apiCredentialsForm.watch("censys.enabled");
  
  const emailNotifications = generalSettingsForm.watch("notifications.emailNotifications");
  const useProxy = advancedSettingsForm.watch("proxy.useProxy");
  
  return (
    <div className="container py-10 max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
        <p className="text-muted-foreground mt-2">
          Configure your scanning environment, API integrations, and user preferences
        </p>
      </div>
      
      <Tabs defaultValue="general" className="space-y-4">
        <TabsList>
          <TabsTrigger value="general">General</TabsTrigger>
          <TabsTrigger value="api-credentials">API Credentials</TabsTrigger>
          <TabsTrigger value="advanced">Advanced</TabsTrigger>
        </TabsList>
        
        {/* General Settings Tab */}
        <TabsContent value="general">
          <Card>
            <CardHeader>
              <CardTitle>General Settings</CardTitle>
              <CardDescription>
                Configure scan defaults and user interface preferences
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Form {...generalSettingsForm}>
                <form onSubmit={generalSettingsForm.handleSubmit(onSaveGeneralSettings)} className="space-y-8">
                  <div>
                    <h3 className="text-lg font-medium">Scan Defaults</h3>
                    <Separator className="my-4" />
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <FormField
                        control={generalSettingsForm.control}
                        name="scanDefaults.defaultScanDepth"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Default Scan Depth</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                min={1}
                                max={5}
                                {...field}
                                onChange={(e) => field.onChange(parseInt(e.target.value) || 3)}
                              />
                            </FormControl>
                            <FormDescription>
                              How deep scans should traverse by default (1-5)
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <FormField
                        control={generalSettingsForm.control}
                        name="scanDefaults.defaultScanTimeout"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Default Scan Timeout (seconds)</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                min={30}
                                max={900}
                                {...field}
                                onChange={(e) => field.onChange(parseInt(e.target.value) || 300)}
                              />
                            </FormControl>
                            <FormDescription>
                              Maximum time in seconds for a scan to complete
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <FormField
                        control={generalSettingsForm.control}
                        name="scanDefaults.maxConcurrentScans"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Maximum Concurrent Scans</FormLabel>
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
                              Maximum number of scans that can run simultaneously
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>
                  </div>
                  
                  <div>
                    <h3 className="text-lg font-medium">User Interface</h3>
                    <Separator className="my-4" />
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <FormField
                        control={generalSettingsForm.control}
                        name="userInterface.theme"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Theme</FormLabel>
                            <Select 
                              onValueChange={field.onChange} 
                              defaultValue={field.value}
                            >
                              <FormControl>
                                <SelectTrigger>
                                  <SelectValue placeholder="Select theme" />
                                </SelectTrigger>
                              </FormControl>
                              <SelectContent>
                                <SelectItem value="light">Light</SelectItem>
                                <SelectItem value="dark">Dark</SelectItem>
                                <SelectItem value="system">System Default</SelectItem>
                              </SelectContent>
                            </Select>
                            <FormDescription>
                              Select your preferred color theme
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <FormField
                        control={generalSettingsForm.control}
                        name="userInterface.enableAnimations"
                        render={({ field }) => (
                          <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                            <div className="space-y-0.5">
                              <FormLabel>Enable Animations</FormLabel>
                              <FormDescription>
                                Show animations and transitions in the UI
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
                        control={generalSettingsForm.control}
                        name="userInterface.showDetailedFindings"
                        render={({ field }) => (
                          <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                            <div className="space-y-0.5">
                              <FormLabel>Show Detailed Findings</FormLabel>
                              <FormDescription>
                                Display detailed information for each vulnerability
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
                  </div>
                  
                  <div>
                    <h3 className="text-lg font-medium">Notifications</h3>
                    <Separator className="my-4" />
                    <div className="grid grid-cols-1 gap-6">
                      <FormField
                        control={generalSettingsForm.control}
                        name="notifications.emailNotifications"
                        render={({ field }) => (
                          <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                            <div className="space-y-0.5">
                              <FormLabel>Email Notifications</FormLabel>
                              <FormDescription>
                                Receive scan results and alerts via email
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
                      
                      {emailNotifications && (
                        <FormField
                          control={generalSettingsForm.control}
                          name="notifications.emailAddress"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Email Address</FormLabel>
                              <FormControl>
                                <Input type="email" placeholder="your.email@example.com" {...field} />
                              </FormControl>
                              <FormDescription>
                                Where to send notification emails
                              </FormDescription>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      )}
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <FormField
                          control={generalSettingsForm.control}
                          name="notifications.notifyOnScanComplete"
                          render={({ field }) => (
                            <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                              <div className="space-y-0.5">
                                <FormLabel>Notify on Scan Completion</FormLabel>
                                <FormDescription>
                                  Get notified when scans complete
                                </FormDescription>
                              </div>
                              <FormControl>
                                <Switch
                                  checked={field.value}
                                  onCheckedChange={field.onChange}
                                  disabled={!emailNotifications}
                                />
                              </FormControl>
                            </FormItem>
                          )}
                        />
                        
                        <FormField
                          control={generalSettingsForm.control}
                          name="notifications.notifyOnHighSeverity"
                          render={({ field }) => (
                            <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                              <div className="space-y-0.5">
                                <FormLabel>Critical Finding Alerts</FormLabel>
                                <FormDescription>
                                  Get alerted for high/critical findings
                                </FormDescription>
                              </div>
                              <FormControl>
                                <Switch
                                  checked={field.value}
                                  onCheckedChange={field.onChange}
                                  disabled={!emailNotifications}
                                />
                              </FormControl>
                            </FormItem>
                          )}
                        />
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex justify-end">
                    <Button type="submit" disabled={savingGeneral}>
                      {savingGeneral ? "Saving..." : "Save Settings"}
                    </Button>
                  </div>
                </form>
              </Form>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* API Credentials Tab */}
        <TabsContent value="api-credentials">
          <Card>
            <CardHeader>
              <CardTitle>External API Credentials</CardTitle>
              <CardDescription>
                Configure credentials for third-party services to enhance scan capabilities
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Form {...apiCredentialsForm}>
                <form onSubmit={apiCredentialsForm.handleSubmit(onSaveApiCredentials)} className="space-y-8">
                  <div>
                    <h3 className="text-lg font-medium">Shodan</h3>
                    <p className="text-sm text-muted-foreground mb-4">
                      Use Shodan to discover exposed devices and services
                    </p>
                    
                    <FormField
                      control={apiCredentialsForm.control}
                      name="shodan.enabled"
                      render={({ field }) => (
                        <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm mb-4">
                          <div className="space-y-0.5">
                            <FormLabel>Enable Shodan Integration</FormLabel>
                            <FormDescription>
                              Integrate with Shodan for enhanced reconnaissance
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
                    
                    {shodanEnabled && (
                      <FormField
                        control={apiCredentialsForm.control}
                        name="shodan.apiKey"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Shodan API Key</FormLabel>
                            <FormControl>
                              <Input type="password" placeholder="Enter your Shodan API key" {...field} />
                            </FormControl>
                            <FormDescription>
                              Your Shodan API key (get one at <a href="https://account.shodan.io/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">account.shodan.io</a>)
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    )}
                  </div>
                  
                  <Separator />
                  
                  <div>
                    <h3 className="text-lg font-medium">VirusTotal</h3>
                    <p className="text-sm text-muted-foreground mb-4">
                      Use VirusTotal to check for known malicious content
                    </p>
                    
                    <FormField
                      control={apiCredentialsForm.control}
                      name="virustotal.enabled"
                      render={({ field }) => (
                        <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm mb-4">
                          <div className="space-y-0.5">
                            <FormLabel>Enable VirusTotal Integration</FormLabel>
                            <FormDescription>
                              Check files and URLs against VirusTotal database
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
                    
                    {virustotalEnabled && (
                      <FormField
                        control={apiCredentialsForm.control}
                        name="virustotal.apiKey"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>VirusTotal API Key</FormLabel>
                            <FormControl>
                              <Input type="password" placeholder="Enter your VirusTotal API key" {...field} />
                            </FormControl>
                            <FormDescription>
                              Your VirusTotal API key
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    )}
                  </div>
                  
                  <Separator />
                  
                  <div>
                    <h3 className="text-lg font-medium">SecurityTrails</h3>
                    <p className="text-sm text-muted-foreground mb-4">
                      Use SecurityTrails for historical DNS and domain information
                    </p>
                    
                    <FormField
                      control={apiCredentialsForm.control}
                      name="securitytrails.enabled"
                      render={({ field }) => (
                        <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm mb-4">
                          <div className="space-y-0.5">
                            <FormLabel>Enable SecurityTrails Integration</FormLabel>
                            <FormDescription>
                              Access historical DNS records and domain information
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
                    
                    {securitytrailsEnabled && (
                      <FormField
                        control={apiCredentialsForm.control}
                        name="securitytrails.apiKey"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>SecurityTrails API Key</FormLabel>
                            <FormControl>
                              <Input type="password" placeholder="Enter your SecurityTrails API key" {...field} />
                            </FormControl>
                            <FormDescription>
                              Your SecurityTrails API key
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    )}
                  </div>
                  
                  <Separator />
                  
                  <div>
                    <h3 className="text-lg font-medium">Censys</h3>
                    <p className="text-sm text-muted-foreground mb-4">
                      Use Censys for internet-wide asset discovery
                    </p>
                    
                    <FormField
                      control={apiCredentialsForm.control}
                      name="censys.enabled"
                      render={({ field }) => (
                        <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm mb-4">
                          <div className="space-y-0.5">
                            <FormLabel>Enable Censys Integration</FormLabel>
                            <FormDescription>
                              Discover internet-facing assets and services
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
                    
                    {censysEnabled && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <FormField
                          control={apiCredentialsForm.control}
                          name="censys.apiKey"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Censys API ID</FormLabel>
                              <FormControl>
                                <Input type="password" placeholder="Enter your Censys API ID" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                        
                        <FormField
                          control={apiCredentialsForm.control}
                          name="censys.apiSecret"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Censys API Secret</FormLabel>
                              <FormControl>
                                <Input type="password" placeholder="Enter your Censys API Secret" {...field} />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      </div>
                    )}
                  </div>
                  
                  <div className="flex justify-end">
                    <Button type="submit" disabled={savingCredentials}>
                      {savingCredentials ? "Saving..." : "Save Credentials"}
                    </Button>
                  </div>
                </form>
              </Form>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Advanced Settings Tab */}
        <TabsContent value="advanced">
          <Card>
            <CardHeader>
              <CardTitle>Advanced Settings</CardTitle>
              <CardDescription>
                Configure scanning engine parameters and system behavior
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Form {...advancedSettingsForm}>
                <form onSubmit={advancedSettingsForm.handleSubmit(onSaveAdvancedSettings)} className="space-y-8">
                  <div>
                    <h3 className="text-lg font-medium">Scan Engine</h3>
                    <Separator className="my-4" />
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <FormField
                        control={advancedSettingsForm.control}
                        name="scanEngine.userAgentString"
                        render={({ field }) => (
                          <FormItem className="col-span-2">
                            <FormLabel>User Agent String</FormLabel>
                            <FormControl>
                              <Input placeholder="Mozilla/5.0 (compatible; Scanner/1.0)" {...field} />
                            </FormControl>
                            <FormDescription>
                              Custom user agent string for scan requests
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <FormField
                        control={advancedSettingsForm.control}
                        name="scanEngine.requestsPerSecond"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Requests Per Second</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                min={1}
                                max={100}
                                {...field}
                                onChange={(e) => field.onChange(parseInt(e.target.value) || 10)}
                              />
                            </FormControl>
                            <FormDescription>
                              Maximum number of requests per second (1-100)
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <div className="grid grid-cols-2 gap-4">
                        <FormField
                          control={advancedSettingsForm.control}
                          name="scanEngine.followRedirects"
                          render={({ field }) => (
                            <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                              <div className="space-y-0.5">
                                <FormLabel>Follow Redirects</FormLabel>
                                <FormDescription>
                                  Follow HTTP redirects during scans
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
                          control={advancedSettingsForm.control}
                          name="scanEngine.maxRedirects"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Max Redirects</FormLabel>
                              <FormControl>
                                <Input
                                  type="number"
                                  min={1}
                                  max={10}
                                  {...field}
                                  onChange={(e) => field.onChange(parseInt(e.target.value) || 5)}
                                  disabled={!advancedSettingsForm.watch("scanEngine.followRedirects")}
                                />
                              </FormControl>
                              <FormDescription>
                                Maximum redirect depth
                              </FormDescription>
                              <FormMessage />
                            </FormItem>
                          )}
                        />
                      </div>
                    </div>
                  </div>
                  
                  <div>
                    <h3 className="text-lg font-medium">Proxy Settings</h3>
                    <Separator className="my-4" />
                    <div className="space-y-6">
                      <FormField
                        control={advancedSettingsForm.control}
                        name="proxy.useProxy"
                        render={({ field }) => (
                          <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                            <div className="space-y-0.5">
                              <FormLabel>Use Proxy for Scans</FormLabel>
                              <FormDescription>
                                Route scan traffic through a proxy server
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
                      
                      {useProxy && (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                          <FormField
                            control={advancedSettingsForm.control}
                            name="proxy.proxyUrl"
                            render={({ field }) => (
                              <FormItem className="col-span-2">
                                <FormLabel>Proxy URL</FormLabel>
                                <FormControl>
                                  <Input placeholder="http://proxy.example.com:8080" {...field} />
                                </FormControl>
                                <FormDescription>
                                  Proxy server URL with port (e.g., http://proxy.example.com:8080)
                                </FormDescription>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                          
                          <FormField
                            control={advancedSettingsForm.control}
                            name="proxy.proxyUsername"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Proxy Username</FormLabel>
                                <FormControl>
                                  <Input placeholder="Optional username" {...field} />
                                </FormControl>
                                <FormDescription>
                                  Optional username for proxy authentication
                                </FormDescription>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                          
                          <FormField
                            control={advancedSettingsForm.control}
                            name="proxy.proxyPassword"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Proxy Password</FormLabel>
                                <FormControl>
                                  <Input type="password" placeholder="Optional password" {...field} />
                                </FormControl>
                                <FormDescription>
                                  Optional password for proxy authentication
                                </FormDescription>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                        </div>
                      )}
                    </div>
                  </div>
                  
                  <div>
                    <h3 className="text-lg font-medium">Database Settings</h3>
                    <Separator className="my-4" />
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <FormField
                        control={advancedSettingsForm.control}
                        name="database.retentionPeriod"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Data Retention Period (days)</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                min={7}
                                max={365}
                                {...field}
                                onChange={(e) => field.onChange(parseInt(e.target.value) || 90)}
                              />
                            </FormControl>
                            <FormDescription>
                              How long to keep scan data (7-365 days)
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      
                      <FormField
                        control={advancedSettingsForm.control}
                        name="database.automaticPruning"
                        render={({ field }) => (
                          <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3 shadow-sm">
                            <div className="space-y-0.5">
                              <FormLabel>Automatic Data Pruning</FormLabel>
                              <FormDescription>
                                Automatically remove data older than retention period
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
                  </div>
                  
                  <div className="flex justify-end">
                    <Button type="submit" disabled={savingAdvanced}>
                      {savingAdvanced ? "Saving..." : "Save Advanced Settings"}
                    </Button>
                  </div>
                </form>
              </Form>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}