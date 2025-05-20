import React, { useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from "recharts";
import { formatNumber } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { AlertTriangle, CheckCircle, ShieldAlert, Zap } from "lucide-react";

interface RiskDashboardProps {
  scans?: any[];
  findings?: any[];
  isLoading?: boolean;
}

export function RiskDashboard({ scans = [], findings = [], isLoading = false }: RiskDashboardProps) {
  const severityColors = {
    critical: "#ff4d6a",
    high: "#ff7e30",
    medium: "#ffad41",
    low: "#ffce25",
    info: "#2E97EB"
  };

  // Calculate statistics from findings
  const stats = useMemo(() => {
    if (!findings || findings.length === 0) {
      return {
        totalFindings: 0,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        byCategory: {},
        verifiedCount: 0,
        falsePositiveCount: 0,
        riskScore: 0,
      };
    }

    const bySeverity = findings.reduce((acc: any, finding: any) => {
      acc[finding.severity] = (acc[finding.severity] || 0) + 1;
      return acc;
    }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });

    // Extract categories from finding titles (for demo purposes)
    const byCategory = findings.reduce((acc: any, finding: any) => {
      // Extract a category from the title - this is a simple heuristic
      const titleParts = finding.title.split(" ");
      const category = titleParts[0] === "Cross-Site" ? "XSS" : 
                      finding.title.includes("SQL") ? "SQL Injection" :
                      finding.title.includes("Command") ? "Command Injection" :
                      finding.title.includes("Authentication") ? "Authentication" :
                      finding.title.includes("Data") ? "Data Exposure" :
                      "Other";
      
      acc[category] = (acc[category] || 0) + 1;
      return acc;
    }, {});

    const verifiedCount = findings.filter((f: any) => f.verified).length;
    const falsePositiveCount = findings.filter((f: any) => f.falsePositive).length;

    // Calculate risk score
    // Critical = 10 points, High = 5 points, Medium = 2 points, Low = 1 point
    const riskScore = (bySeverity.critical * 10) + 
                      (bySeverity.high * 5) + 
                      (bySeverity.medium * 2) + 
                      bySeverity.low;

    return {
      totalFindings: findings.length,
      bySeverity,
      byCategory,
      verifiedCount,
      falsePositiveCount,
      riskScore
    };
  }, [findings]);

  // Format data for charts
  const severityChartData = useMemo(() => {
    return Object.entries(stats.bySeverity).map(([severity, count]) => ({
      name: severity.charAt(0).toUpperCase() + severity.slice(1),
      value: count,
    }));
  }, [stats.bySeverity]);

  const categoryChartData = useMemo(() => {
    return Object.entries(stats.byCategory).map(([category, count]) => ({
      name: category,
      value: count,
    }));
  }, [stats.byCategory]);

  const scanActivityData = useMemo(() => {
    // Get last 7 scans or fewer
    const recentScans = [...scans].sort((a, b) => 
      new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()
    ).slice(0, 7);

    return recentScans.map(scan => {
      const findings = scan.findings || [];
      const findingCounts = findings.reduce((acc: any, finding: any) => {
        acc[finding.severity] = (acc[finding.severity] || 0) + 1;
        return acc;
      }, {});

      return {
        name: scan.target.length > 20 ? scan.target.substring(0, 20) + '...' : scan.target,
        critical: findingCounts.critical || 0,
        high: findingCounts.high || 0,
        medium: findingCounts.medium || 0,
        low: findingCounts.low || 0,
        info: findingCounts.info || 0,
      };
    });
  }, [scans]);

  // Calculate risk level
  const getRiskLevel = (score: number) => {
    if (score >= 50) return { level: "Critical", color: severityColors.critical };
    if (score >= 30) return { level: "High", color: severityColors.high };
    if (score >= 10) return { level: "Medium", color: severityColors.medium };
    return { level: "Low", color: severityColors.low };
  };

  const riskLevel = getRiskLevel(stats.riskScore);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-lg text-muted-foreground">Loading dashboard data...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Vulnerabilities */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Total Vulnerabilities
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center">
              <ShieldAlert className="w-6 h-6 mr-2 text-primary" />
              <div className="text-2xl font-bold">{formatNumber(stats.totalFindings)}</div>
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              Across {scans.length} security scans
            </p>
          </CardContent>
        </Card>

        {/* Risk Score */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Overall Risk Score
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center">
              <Zap className="w-6 h-6 mr-2 text-primary" />
              <div className="text-2xl font-bold">{stats.riskScore}</div>
              <Badge className="ml-2" style={{ backgroundColor: riskLevel.color }}>
                {riskLevel.level}
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              Based on severity distribution
            </p>
          </CardContent>
        </Card>

        {/* Verified Findings */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Verified Findings
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center">
              <CheckCircle className="w-6 h-6 mr-2 text-green-500" />
              <div className="text-2xl font-bold">{stats.verifiedCount}</div>
              <span className="text-xs ml-2 text-muted-foreground">
                ({Math.round((stats.verifiedCount / stats.totalFindings) * 100) || 0}%)
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              Findings confirmed as actual vulnerabilities
            </p>
          </CardContent>
        </Card>

        {/* False Positives */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              False Positives
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center">
              <AlertTriangle className="w-6 h-6 mr-2 text-yellow-500" />
              <div className="text-2xl font-bold">{stats.falsePositiveCount}</div>
              <span className="text-xs ml-2 text-muted-foreground">
                ({Math.round((stats.falsePositiveCount / stats.totalFindings) * 100) || 0}%)
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              Findings identified as false alarms
            </p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="distribution">
        <TabsList>
          <TabsTrigger value="distribution">Vulnerability Distribution</TabsTrigger>
          <TabsTrigger value="history">Scan History</TabsTrigger>
        </TabsList>
        
        <TabsContent value="distribution" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Severity Distribution */}
            <Card>
              <CardHeader>
                <CardTitle>Severity Distribution</CardTitle>
                <CardDescription>Breakdown of findings by severity level</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-80">
                  {stats.totalFindings > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={severityChartData}
                          cx="50%"
                          cy="50%"
                          innerRadius={70}
                          outerRadius={90}
                          paddingAngle={2}
                          dataKey="value"
                          label={({ name, percent }) => 
                            `${name} ${(percent * 100).toFixed(0)}%`
                          }
                        >
                          {severityChartData.map((entry, index) => {
                            const severity = entry.name.toLowerCase();
                            return (
                              <Cell 
                                key={`cell-${index}`} 
                                fill={severityColors[severity as keyof typeof severityColors] || '#8884d8'} 
                              />
                            );
                          })}
                        </Pie>
                        <Tooltip />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex items-center justify-center h-full">
                      <p className="text-muted-foreground">No findings data available</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Vulnerability Categories */}
            <Card>
              <CardHeader>
                <CardTitle>Vulnerability Categories</CardTitle>
                <CardDescription>Types of security issues found</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-80">
                  {Object.keys(stats.byCategory).length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={categoryChartData}
                        layout="vertical"
                        margin={{ top: 5, right: 30, left: 80, bottom: 5 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis type="number" />
                        <YAxis type="category" dataKey="name" width={80} />
                        <Tooltip />
                        <Bar dataKey="value" fill="#6366F1" radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex items-center justify-center h-full">
                      <p className="text-muted-foreground">No category data available</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="history">
          <Card>
            <CardHeader>
              <CardTitle>Scan Activity</CardTitle>
              <CardDescription>History of recent security scans</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-96">
                {scanActivityData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={scanActivityData}
                      margin={{ top: 20, right: 30, left: 20, bottom: 60 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="name" angle={-45} textAnchor="end" height={80} />
                      <YAxis label={{ value: 'Findings', angle: -90, position: 'insideLeft' }} />
                      <Tooltip />
                      <Legend />
                      <Bar dataKey="critical" name="Critical" stackId="a" fill={severityColors.critical} />
                      <Bar dataKey="high" name="High" stackId="a" fill={severityColors.high} />
                      <Bar dataKey="medium" name="Medium" stackId="a" fill={severityColors.medium} />
                      <Bar dataKey="low" name="Low" stackId="a" fill={severityColors.low} />
                      <Bar dataKey="info" name="Info" stackId="a" fill={severityColors.info} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex items-center justify-center h-full">
                    <p className="text-muted-foreground">No scan history available</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Top Vulnerable Assets */}
      <Card>
        <CardHeader>
          <CardTitle>Top Vulnerable Assets</CardTitle>
          <CardDescription>Targets with the highest risk scores</CardDescription>
        </CardHeader>
        <CardContent>
          {scans.length > 0 ? (
            <div className="space-y-4">
              {scans
                .slice(0, 5)
                .sort((a, b) => {
                  const aFindings = a.findings || [];
                  const bFindings = b.findings || [];
                  const aScore = (aFindings.filter((f: any) => f.severity === 'critical').length * 10) +
                                (aFindings.filter((f: any) => f.severity === 'high').length * 5) +
                                (aFindings.filter((f: any) => f.severity === 'medium').length * 2) +
                                (aFindings.filter((f: any) => f.severity === 'low').length);
                  const bScore = (bFindings.filter((f: any) => f.severity === 'critical').length * 10) +
                                (bFindings.filter((f: any) => f.severity === 'high').length * 5) +
                                (bFindings.filter((f: any) => f.severity === 'medium').length * 2) +
                                (bFindings.filter((f: any) => f.severity === 'low').length);
                  return bScore - aScore;
                })
                .map((scan, index) => {
                  const findings = scan.findings || [];
                  const criticalCount = findings.filter((f: any) => f.severity === 'critical').length;
                  const highCount = findings.filter((f: any) => f.severity === 'high').length;
                  const score = (criticalCount * 10) + (highCount * 5) + 
                              (findings.filter((f: any) => f.severity === 'medium').length * 2) +
                              (findings.filter((f: any) => f.severity === 'low').length);
                  const riskLevel = getRiskLevel(score);
                
                  return (
                    <div key={index} className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <div className="font-medium truncate max-w-xs">
                          {scan.target}
                        </div>
                      </div>
                      <div className="flex items-center space-x-4">
                        <div className="flex space-x-2 text-sm">
                          {criticalCount > 0 && (
                            <Badge style={{ backgroundColor: severityColors.critical }}>
                              {criticalCount} Critical
                            </Badge>
                          )}
                          {highCount > 0 && (
                            <Badge style={{ backgroundColor: severityColors.high }}>
                              {highCount} High
                            </Badge>
                          )}
                        </div>
                        <Badge style={{ backgroundColor: riskLevel.color }}>
                          Score: {score}
                        </Badge>
                      </div>
                      <Separator className="my-2" />
                    </div>
                  );
                })}
            </div>
          ) : (
            <div className="flex items-center justify-center h-20">
              <p className="text-muted-foreground">No scan data available</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}