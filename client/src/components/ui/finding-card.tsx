import { useState } from "react";
import { SeverityBadge } from "./severity-badge";
import { Button } from "./button";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface FindingCardProps {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  location: string;
  description: string;
  evidence?: string;
  impact?: string;
  remediation?: string;
  codeFix?: string;
  falsePositive?: boolean;
  verified?: boolean;
}

export function FindingCard({
  id,
  severity,
  title,
  location,
  description,
  evidence,
  impact,
  remediation,
  codeFix,
  falsePositive = false,
  verified = false,
}: FindingCardProps) {
  const [isOpen, setIsOpen] = useState(false);
  const { toast } = useToast();

  const falsePositiveMutation = useMutation({
    mutationFn: async (isFalse: boolean) => {
      await apiRequest("POST", `/api/finding/${id}/false-positive`, { isFalse });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scans"] });
      toast({
        title: "Success",
        description: falsePositive
          ? "Finding marked as valid"
          : "Finding marked as false positive",
      });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: `Failed to update finding: ${error.message}`,
        variant: "destructive",
      });
    },
  });

  const verifyMutation = useMutation({
    mutationFn: async (isVerified: boolean) => {
      await apiRequest("POST", `/api/finding/${id}/verify`, { isVerified });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scans"] });
      toast({
        title: "Success",
        description: verified
          ? "Fix marked as unverified"
          : "Fix marked as verified",
      });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: `Failed to update finding: ${error.message}`,
        variant: "destructive",
      });
    },
  });

  const toggleFinding = () => setIsOpen(!isOpen);

  return (
    <div className="bg-dark-surface rounded-lg overflow-hidden border border-dark-border scan-result-card">
      <div className="p-4 cursor-pointer" onClick={toggleFinding}>
        <div className="flex items-start justify-between">
          <div className="flex">
            <SeverityBadge severity={severity} className="mr-3" />
            <div>
              <h3 className="font-medium">{title}</h3>
              <p className="text-sm text-gray-400">Found in: {location}</p>
            </div>
          </div>
          <span
            className={`material-icons transform transition-transform ${
              isOpen ? "rotate-180" : ""
            }`}
          >
            expand_more
          </span>
        </div>
      </div>

      {isOpen && (
        <div className="px-4 pb-4">
          <div className="mb-4 border-t border-dark-border pt-4">
            <h4 className="font-medium mb-2">Description</h4>
            <p className="text-sm text-gray-300">{description}</p>

            {evidence && (
              <>
                <h4 className="font-medium mt-4 mb-2">Evidence</h4>
                <div className="bg-dark-bg p-3 rounded font-mono text-xs whitespace-pre overflow-x-auto">
                  {evidence}
                </div>
              </>
            )}

            {impact && (
              <>
                <h4 className="font-medium mt-4 mb-2">Impact</h4>
                <p className="text-sm text-gray-300">{impact}</p>
              </>
            )}

            {remediation && (
              <>
                <h4 className="font-medium mt-4 mb-2">Remediation</h4>
                <p className="text-sm text-gray-300 whitespace-pre-line">
                  {remediation}
                </p>
              </>
            )}

            {codeFix && (
              <div className={`bg-severity-${severity} bg-opacity-10 border-l-4 border-severity-${severity} p-3 rounded mt-4`}>
                <h4 className={`font-medium mb-1 text-severity-${severity}`}>
                  Code Fix Example
                </h4>
                <div className="font-mono text-xs whitespace-pre overflow-x-auto">
                  {codeFix}
                </div>
              </div>
            )}

            <div className="flex justify-end mt-4">
              <Button
                variant="secondary"
                className="mr-2 text-sm"
                onClick={() => falsePositiveMutation.mutate(!falsePositive)}
                disabled={falsePositiveMutation.isPending}
              >
                {falsePositive
                  ? "Mark as Valid Finding"
                  : "Mark as False Positive"}
              </Button>
              <Button
                className={`bg-severity-${severity} hover:bg-severity-${severity} hover:brightness-90 text-white text-sm flex items-center`}
                onClick={() => verifyMutation.mutate(!verified)}
                disabled={verifyMutation.isPending}
              >
                <span className="material-icons text-sm mr-1">check_circle</span>
                <span>{verified ? "Unverify Fix" : "Verify Fix"}</span>
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
