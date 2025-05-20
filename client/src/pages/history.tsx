import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { format } from "date-fns";
import { Download, Eye, Filter } from "lucide-react";
import { ScanResults } from "@/components/scan-results";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

export default function History() {
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [scanTypeFilter, setScanTypeFilter] = useState('all');
  
  // Fetch all scans
  const { data: scans = [], isLoading } = useQuery({
    queryKey: ['/api/scans'],
    refetchInterval: 0,
    refetchOnWindowFocus: false
  });
  
  // Fetch findings for selected scan
  const { data: findings = [] } = useQuery({
    queryKey: ['/api/scan', selectedScanId, 'findings'],
    enabled: !!selectedScanId,
    refetchInterval: 0,
    refetchOnWindowFocus: false
  });
  
  // Filter and sort scans
  const filteredScans = React.useMemo(() => {
    if (!scans) return [];
    
    return scans
      .filter((scan: any) => {
        // Filter by search term
        const matchesSearch = 
          searchTerm === '' || 
          scan.target.toLowerCase().includes(searchTerm.toLowerCase());
        
        // Filter by scan type
        const matchesType = 
          scanTypeFilter === 'all' || 
          scan.scanType === scanTypeFilter;
        
        return matchesSearch && matchesType;
      })
      .sort((a: any, b: any) => {
        // Sort by date (newest first)
        return new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime();
      });
  }, [scans, searchTerm, scanTypeFilter]);
  
  // Get scan details
  const selectedScan = React.useMemo(() => {
    if (!scans || !selectedScanId) return null;
    return scans.find((scan: any) => scan.id === selectedScanId);
  }, [scans, selectedScanId]);
  
  // Handle viewing scan details
  const viewScanDetails = (scanId: number) => {
    setSelectedScanId(scanId);
  };
  
  // Handle downloading scan results
  const downloadResults = (scanId: number) => {
    if (!findings) return;
    
    const scanResults = findings.filter((finding: any) => finding.scanId === scanId);
    if (!scanResults.length) return;
    
    const element = document.createElement("a");
    const file = new Blob(
      [JSON.stringify(scanResults, null, 2)], 
      { type: "application/json" }
    );
    element.href = URL.createObjectURL(file);
    element.download = `security-scan-results-${scanId}.json`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };
  
  // Get severity counts for a scan
  const getSeverityCounts = (scanId: number) => {
    if (!findings) return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    
    const scanFindings = findings.filter((finding: any) => finding.scanId === scanId);
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    
    scanFindings.forEach((finding: any) => {
      if (finding.severity in counts) {
        counts[finding.severity as keyof typeof counts]++;
      }
    });
    
    return counts;
  };
  
  // Render a badge for scan status
  const renderStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return <Badge className="bg-green-600 text-white">Completed</Badge>;
      case 'running':
        return <Badge variant="secondary">Running</Badge>;
      case 'failed':
        return <Badge variant="destructive">Failed</Badge>;
      default:
        return <Badge>{status}</Badge>;
    }
  };
  
  // Render a badge for scan type
  const renderTypeBadge = (type: string) => {
    switch (type) {
      case 'port-scan':
        return <Badge variant="outline">Port Scan</Badge>;
      case 'web-scan':
        return <Badge variant="outline">Web Scan</Badge>;
      case 'code-analysis':
        return <Badge variant="outline">Code Analysis</Badge>;
      default:
        return <Badge variant="outline">{type}</Badge>;
    }
  };
  
  // Format date for display
  const formatDate = (dateString: string) => {
    try {
      return format(new Date(dateString), 'MMM d, yyyy HH:mm:ss');
    } catch (error) {
      return 'Invalid date';
    }
  };
  
  // Get scan findings
  const getScanFindings = (scanId: number) => {
    if (!findings) return [];
    return findings.filter((finding: any) => finding.scanId === scanId);
  };
  
  return (
    <div className="container py-10 max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight">Scan History</h1>
        <p className="text-muted-foreground mt-2">
          View and analyze past security scans
        </p>
      </div>
      
      {/* Main content - either show scan history or results */}
      {selectedScanId ? (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-2xl font-semibold">
              Scan Results: {selectedScan?.target}
            </h2>
            <div className="space-x-2">
              <Button onClick={() => downloadResults(selectedScanId)}>
                <Download className="h-4 w-4 mr-2" />
                Download Results
              </Button>
              <Button variant="outline" onClick={() => setSelectedScanId(null)}>
                Back to History
              </Button>
            </div>
          </div>
          
          <Card className="mb-6">
            <CardContent className="pt-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div>
                  <h3 className="text-sm font-medium text-muted-foreground mb-1">Target</h3>
                  <p className="font-medium">{selectedScan?.target}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-muted-foreground mb-1">Scan Type</h3>
                  <p className="font-medium">{renderTypeBadge(selectedScan?.scanType)}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-muted-foreground mb-1">Scan Date</h3>
                  <p className="font-medium">{formatDate(selectedScan?.startedAt)}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-muted-foreground mb-1">Status</h3>
                  <p className="font-medium">{renderStatusBadge(selectedScan?.status)}</p>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-muted-foreground mb-1">Duration</h3>
                  <p className="font-medium">
                    {selectedScan?.completedAt ? 
                      `${Math.round((new Date(selectedScan.completedAt).getTime() - new Date(selectedScan.startedAt).getTime()) / 1000)} seconds` : 
                      'N/A'}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <ScanResults
            findings={getScanFindings(selectedScanId)}
            scanTime={formatDate(selectedScan?.startedAt)}
            severityCounts={getSeverityCounts(selectedScanId)}
          />
        </div>
      ) : (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Filter Scans</CardTitle>
              <CardDescription>
                Find specific scans in your history
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col sm:flex-row gap-4">
                <div className="flex-1">
                  <Input
                    placeholder="Search by target..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </div>
                <div className="w-full sm:w-48">
                  <Select
                    value={scanTypeFilter}
                    onValueChange={setScanTypeFilter}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Filter by type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Types</SelectItem>
                      <SelectItem value="port-scan">Port Scan</SelectItem>
                      <SelectItem value="web-scan">Web Scan</SelectItem>
                      <SelectItem value="code-analysis">Code Analysis</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardContent>
          </Card>
          
          <Tabs defaultValue="table" className="w-full">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="table">Table View</TabsTrigger>
              <TabsTrigger value="cards">Card View</TabsTrigger>
            </TabsList>
            
            <TabsContent value="table" className="mt-6">
              <Card>
                <CardContent className="p-0">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Date</TableHead>
                        <TableHead>Target</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Findings</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {isLoading ? (
                        <TableRow>
                          <TableCell colSpan={6} className="text-center py-6">
                            Loading scan history...
                          </TableCell>
                        </TableRow>
                      ) : filteredScans.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={6} className="text-center py-6">
                            No scan history found
                          </TableCell>
                        </TableRow>
                      ) : (
                        filteredScans.map((scan: any) => (
                          <TableRow key={scan.id}>
                            <TableCell className="font-medium">
                              {formatDate(scan.startedAt)}
                            </TableCell>
                            <TableCell className="max-w-[200px] truncate">
                              {scan.target}
                            </TableCell>
                            <TableCell>
                              {renderTypeBadge(scan.scanType)}
                            </TableCell>
                            <TableCell>
                              {renderStatusBadge(scan.status)}
                            </TableCell>
                            <TableCell>
                              {scan.status === 'completed' && (
                                <div className="flex space-x-1">
                                  {getSeverityCounts(scan.id).critical > 0 && (
                                    <Badge variant="destructive" className="rounded-sm">
                                      {getSeverityCounts(scan.id).critical} Critical
                                    </Badge>
                                  )}
                                  {getSeverityCounts(scan.id).high > 0 && (
                                    <Badge variant="destructive" className="bg-orange-500 rounded-sm">
                                      {getSeverityCounts(scan.id).high} High
                                    </Badge>
                                  )}
                                </div>
                              )}
                            </TableCell>
                            <TableCell className="text-right">
                              <Button
                                variant="ghost"
                                size="icon"
                                onClick={() => viewScanDetails(scan.id)}
                              >
                                <Eye className="h-4 w-4" />
                              </Button>
                              {scan.status === 'completed' && (
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  onClick={() => downloadResults(scan.id)}
                                >
                                  <Download className="h-4 w-4" />
                                </Button>
                              )}
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </TabsContent>
            
            <TabsContent value="cards" className="mt-6">
              {isLoading ? (
                <div className="text-center py-8">
                  Loading scan history...
                </div>
              ) : filteredScans.length === 0 ? (
                <div className="text-center py-8">
                  No scan history found
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {filteredScans.map((scan: any) => (
                    <Card key={scan.id}>
                      <CardHeader className="pb-2">
                        <div className="flex justify-between items-start">
                          <CardTitle className="text-lg truncate">
                            {scan.target}
                          </CardTitle>
                          {renderStatusBadge(scan.status)}
                        </div>
                        <CardDescription>
                          {formatDate(scan.startedAt)}
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          <div className="flex justify-between">
                            <span className="text-sm">Type:</span>
                            <span>{renderTypeBadge(scan.scanType)}</span>
                          </div>
                          {scan.status === 'completed' && (
                            <div className="flex justify-between">
                              <span className="text-sm">Findings:</span>
                              <div className="space-x-1">
                                {getSeverityCounts(scan.id).critical > 0 && (
                                  <Badge variant="destructive" className="rounded-sm">
                                    {getSeverityCounts(scan.id).critical} Critical
                                  </Badge>
                                )}
                                {getSeverityCounts(scan.id).high > 0 && (
                                  <Badge variant="destructive" className="bg-orange-500 rounded-sm">
                                    {getSeverityCounts(scan.id).high} High
                                  </Badge>
                                )}
                                {getSeverityCounts(scan.id).medium > 0 && (
                                  <Badge variant="outline" className="rounded-sm">
                                    {getSeverityCounts(scan.id).medium} Medium
                                  </Badge>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      </CardContent>
                      <div className="px-6 pb-6 pt-2 flex justify-end space-x-2">
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => viewScanDetails(scan.id)}
                        >
                          <Eye className="h-4 w-4 mr-2" />
                          View Results
                        </Button>
                      </div>
                    </Card>
                  ))}
                </div>
              )}
            </TabsContent>
          </Tabs>
        </div>
      )}
    </div>
  );
}