import React from "react";
import { useQuery } from "@tanstack/react-query";
import { RiskDashboard } from "@/components/dashboard/risk-dashboard";
import { PageNav } from "@/components/layout/page-nav";
import { getQueryFn } from "@/lib/queryClient";

export default function Dashboard() {
  // Fetch all scans
  const { data: scans = [], isLoading: isLoadingScans } = useQuery<any[]>({
    queryKey: ["/api/scans"],
    queryFn: getQueryFn<any[]>({ on401: "returnNull" }),
  });

  // Extract all findings from scans for dashboard analysis
  const findings = React.useMemo(() => {
    if (!scans || !Array.isArray(scans)) return [];
    
    // Flatten all findings from all scans
    return scans.flatMap((scan: any) => {
      if (!scan.findings || !Array.isArray(scan.findings)) return [];
      return scan.findings.map((finding: any) => ({
        ...finding,
        scanId: scan.id,
        scanTarget: scan.target,
      }));
    });
  }, [scans]);

  return (
    <div className="container py-10 max-w-7xl mx-auto">
      <PageNav
        title="Vulnerability Dashboard"
        description="Interactive visualizations of your security posture and risk metrics"
      />

      <RiskDashboard 
        scans={scans || []} 
        findings={findings} 
        isLoading={isLoadingScans} 
      />
    </div>
  );
}