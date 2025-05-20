import { Button } from "@/components/ui/button";
import { FindingCard } from "@/components/ui/finding-card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { useState } from "react";
import { Severity } from "@shared/schema";

interface ScanResultsProps {
  findings: any[];
  scanTime?: string;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export function ScanResults({
  findings,
  scanTime = "2 minutes ago",
  severityCounts,
}: ScanResultsProps) {
  const [filters, setFilters] = useState<Severity[]>([
    "critical",
    "high",
    "medium",
  ]);
  const [sortBy, setSortBy] = useState("severity");
  const [showAllFindings, setShowAllFindings] = useState(false);

  // Filter findings based on selected severity levels
  const filteredFindings = findings.filter((finding) =>
    filters.includes(finding.severity as Severity)
  );

  // Sort findings based on sort option
  const sortedFindings = [...filteredFindings].sort((a, b) => {
    if (sortBy === "severity") {
      const severityOrder = {
        critical: 0,
        high: 1,
        medium: 2,
        low: 3,
        info: 4,
      };
      return severityOrder[a.severity] - severityOrder[b.severity];
    } else if (sortBy === "location") {
      return a.location.localeCompare(b.location);
    } else {
      // By type/title
      return a.title.localeCompare(b.title);
    }
  });

  // Limit the number of findings shown unless "View All" is clicked
  const visibleFindings = showAllFindings
    ? sortedFindings
    : sortedFindings.slice(0, 3);

  // Toggle a severity filter
  const toggleFilter = (severity: Severity) => {
    if (filters.includes(severity)) {
      setFilters(filters.filter((f) => f !== severity));
    } else {
      setFilters([...filters, severity]);
    }
  };

  return (
    <div className="mb-6">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between mb-4">
        <h2 className="text-xl font-bold">Scan Results</h2>
        <div className="flex items-center space-x-2 mt-2 md:mt-0">
          <span className="text-sm text-gray-400">Last scan: {scanTime}</span>
          <Button
            variant="secondary"
            className="bg-gray-700 hover:bg-gray-600 text-white flex items-center"
          >
            <span className="material-icons text-sm mr-1">file_download</span>
            <span>Export</span>
          </Button>
        </div>
      </div>

      {/* Severity Summary */}
      <div className="bg-dark-surface rounded-lg p-4 md:p-6 mb-6">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-opacity-10 bg-severity-critical p-4 rounded-lg flex flex-col items-center">
            <div className="text-severity-critical text-2xl font-bold">
              {severityCounts.critical}
            </div>
            <div className="text-sm text-gray-300">Critical</div>
          </div>
          <div className="bg-opacity-10 bg-severity-high p-4 rounded-lg flex flex-col items-center">
            <div className="text-severity-high text-2xl font-bold">
              {severityCounts.high}
            </div>
            <div className="text-sm text-gray-300">High</div>
          </div>
          <div className="bg-opacity-10 bg-severity-medium p-4 rounded-lg flex flex-col items-center">
            <div className="text-severity-medium text-2xl font-bold">
              {severityCounts.medium}
            </div>
            <div className="text-sm text-gray-300">Medium</div>
          </div>
          <div className="bg-opacity-10 bg-severity-low p-4 rounded-lg flex flex-col items-center">
            <div className="text-severity-low text-2xl font-bold">
              {severityCounts.low}
            </div>
            <div className="text-sm text-gray-300">Low</div>
          </div>
          <div className="bg-opacity-10 bg-severity-info p-4 rounded-lg flex flex-col items-center">
            <div className="text-severity-info text-2xl font-bold">
              {severityCounts.info}
            </div>
            <div className="text-sm text-gray-300">Info</div>
          </div>
        </div>
      </div>

      {/* Filter options */}
      <div className="bg-dark-surface rounded-lg p-4 md:px-6 md:py-3 mb-6 flex flex-wrap gap-3 items-center">
        <div className="text-sm font-medium text-gray-400">Filter by:</div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            className={`bg-dark-bg hover:bg-gray-800 text-white px-3 py-1 rounded-full text-sm flex items-center ${
              !filters.includes("critical") ? "opacity-50" : ""
            }`}
            onClick={() => toggleFilter("critical")}
          >
            <span className="w-2 h-2 bg-severity-critical rounded-full mr-1"></span>
            Critical
          </button>
          <button
            type="button"
            className={`bg-dark-bg hover:bg-gray-800 text-white px-3 py-1 rounded-full text-sm flex items-center ${
              !filters.includes("high") ? "opacity-50" : ""
            }`}
            onClick={() => toggleFilter("high")}
          >
            <span className="w-2 h-2 bg-severity-high rounded-full mr-1"></span>
            High
          </button>
          <button
            type="button"
            className={`bg-dark-bg hover:bg-gray-800 text-white px-3 py-1 rounded-full text-sm flex items-center ${
              !filters.includes("medium") ? "opacity-50" : ""
            }`}
            onClick={() => toggleFilter("medium")}
          >
            <span className="w-2 h-2 bg-severity-medium rounded-full mr-1"></span>
            Medium
          </button>
          <button
            type="button"
            className={`bg-dark-bg hover:bg-gray-800 text-white px-3 py-1 rounded-full text-sm flex items-center ${
              !filters.includes("low") ? "opacity-50" : ""
            }`}
            onClick={() => toggleFilter("low")}
          >
            <span className="w-2 h-2 bg-severity-low rounded-full mr-1"></span>
            Low
          </button>
          <button
            type="button"
            className={`bg-dark-bg hover:bg-gray-800 text-white px-3 py-1 rounded-full text-sm flex items-center ${
              !filters.includes("info") ? "opacity-50" : ""
            }`}
            onClick={() => toggleFilter("info")}
          >
            <span className="w-2 h-2 bg-severity-info rounded-full mr-1"></span>
            Info
          </button>
        </div>

        <div className="ml-auto">
          <select
            className="bg-dark-bg border border-dark-border text-white rounded-lg text-sm p-2 focus:ring-2 focus:ring-primary focus:border-primary outline-none"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
          >
            <option value="severity">Sort by Severity</option>
            <option value="type">Sort by Type</option>
            <option value="location">Sort by Location</option>
          </select>
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-4">
        {visibleFindings.length > 0 ? (
          visibleFindings.map((finding) => (
            <FindingCard
              key={finding.id}
              id={finding.id}
              severity={finding.severity}
              title={finding.title}
              location={finding.location}
              description={finding.description}
              evidence={finding.evidence}
              impact={finding.impact}
              remediation={finding.remediation}
              codeFix={finding.codeFix}
              falsePositive={finding.falsePositive}
              verified={finding.verified}
            />
          ))
        ) : (
          <div className="bg-dark-surface rounded-lg p-6 text-center">
            <p className="text-gray-400">
              No findings match the selected filters.
            </p>
          </div>
        )}
      </div>

      {filteredFindings.length > 3 && !showAllFindings && (
        <div className="flex justify-center mt-6">
          <Button
            variant="secondary"
            className="bg-dark-bg hover:bg-gray-800 text-white flex items-center"
            onClick={() => setShowAllFindings(true)}
          >
            <span className="material-icons text-sm mr-1">visibility</span>
            <span>View All Findings ({filteredFindings.length})</span>
          </Button>
        </div>
      )}
    </div>
  );
}
