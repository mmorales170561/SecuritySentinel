import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { WebScanRequest } from "@shared/schema";

interface ScanFormProps {
  onScanStart: (scanId: number) => void;
}

export function ScanForm({ onScanStart }: ScanFormProps) {
  const { toast } = useToast();
  const [url, setUrl] = useState("example.com");
  const [scanType, setScanType] = useState("quick");
  const [useProxy, setUseProxy] = useState(false);
  const [useAuth, setUseAuth] = useState(false);
  const [passiveOnly, setPassiveOnly] = useState(false);

  const startScanMutation = useMutation({
    mutationFn: async (scanRequest: WebScanRequest) => {
      const response = await apiRequest("POST", "/api/scan/web", scanRequest);
      return await response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Scan started",
        description: `Starting scan of ${url}`,
      });
      onScanStart(data.scanId);
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: `Failed to start scan: ${error.message}`,
        variant: "destructive",
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    const scanRequest: WebScanRequest = {
      url,
      scanType,
      options: {
        useProxy,
        useAuth,
        passiveOnly,
      },
    };
    
    startScanMutation.mutate(scanRequest);
  };

  return (
    <div className="bg-dark-surface rounded-lg p-4 md:p-6 mb-6">
      <h2 className="text-xl font-bold mb-4">Web Security Scan</h2>
      
      <form className="space-y-4" onSubmit={handleSubmit}>
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1">
            <Label htmlFor="url-input" className="block text-sm font-medium mb-1">
              Target URL or Repository
            </Label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none text-gray-400">
                <span className="material-icons text-sm">link</span>
              </span>
              <Input
                id="url-input"
                className="bg-dark-bg border border-dark-border text-white rounded-lg block w-full pl-10 p-2.5 focus:ring-2 focus:ring-primary focus:border-primary outline-none"
                placeholder="https://example.com or github.com/user/repo"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </div>
          </div>
          <div>
            <Label htmlFor="scan-type" className="block text-sm font-medium mb-1">
              Scan Type
            </Label>
            <Select value={scanType} onValueChange={setScanType}>
              <SelectTrigger id="scan-type" className="bg-dark-bg border border-dark-border text-white rounded-lg">
                <SelectValue placeholder="Select scan type" />
              </SelectTrigger>
              <SelectContent className="bg-dark-bg border border-dark-border text-white">
                <SelectItem value="full">Full Scan</SelectItem>
                <SelectItem value="quick">Quick Scan</SelectItem>
                <SelectItem value="authentication">Authentication</SelectItem>
                <SelectItem value="injection">Injection Vulnerabilities</SelectItem>
                <SelectItem value="xss">XSS Vulnerabilities</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        
        <div className="flex flex-wrap gap-4">
          <div className="flex items-center">
            <Checkbox 
              id="use-proxy" 
              checked={useProxy} 
              onCheckedChange={(checked) => setUseProxy(!!checked)}
              className="w-4 h-4 bg-dark-bg border-dark-border rounded focus:ring-primary focus:ring-2"
            />
            <Label htmlFor="use-proxy" className="ml-2 text-sm font-medium text-gray-300">
              Use Proxy
            </Label>
          </div>
          <div className="flex items-center">
            <Checkbox 
              id="use-auth" 
              checked={useAuth} 
              onCheckedChange={(checked) => setUseAuth(!!checked)}
              className="w-4 h-4 bg-dark-bg border-dark-border rounded focus:ring-primary focus:ring-2"
            />
            <Label htmlFor="use-auth" className="ml-2 text-sm font-medium text-gray-300">
              Authentication Required
            </Label>
          </div>
          <div className="flex items-center">
            <Checkbox 
              id="passive-only" 
              checked={passiveOnly} 
              onCheckedChange={(checked) => setPassiveOnly(!!checked)}
              className="w-4 h-4 bg-dark-bg border-dark-border rounded focus:ring-primary focus:ring-2"
            />
            <Label htmlFor="passive-only" className="ml-2 text-sm font-medium text-gray-300">
              Passive Scan Only
            </Label>
          </div>
        </div>
        
        <div className="flex justify-end">
          <Button type="button" variant="secondary" className="mr-2">
            Advanced Options
          </Button>
          <Button 
            type="submit" 
            className="bg-primary hover:bg-blue-700 text-white flex items-center"
            disabled={startScanMutation.isPending}
          >
            <span className="material-icons text-sm mr-1">search</span>
            <span>Start Scan</span>
          </Button>
        </div>
      </form>
    </div>
  );
}
