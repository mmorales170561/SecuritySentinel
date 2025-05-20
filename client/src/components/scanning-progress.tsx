import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";

interface ScanningProgressProps {
  target: string;
  progress: number;
  log: string[];
  onStopScan: () => void;
}

export function ScanningProgress({
  target,
  progress,
  log,
  onStopScan,
}: ScanningProgressProps) {
  return (
    <div className="bg-dark-surface rounded-lg p-4 md:p-6 mb-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold">Scanning {target}...</h2>
        <Button
          variant="secondary"
          className="bg-gray-700 hover:bg-gray-600 text-white flex items-center"
          onClick={onStopScan}
        >
          <span className="material-icons text-sm mr-1">stop</span>
          <span>Stop Scan</span>
        </Button>
      </div>

      <div className="mb-4">
        <div className="flex justify-between mb-1">
          <span>Progress</span>
          <span>{progress}%</span>
        </div>
        <Progress value={progress} className="w-full bg-dark-bg h-2.5" />
      </div>

      <div className="bg-dark-bg rounded-lg p-4 max-h-40 overflow-auto font-mono text-xs">
        {log.map((entry, index) => {
          const isInfo = entry.startsWith("[INFO]");
          const isLow = entry.startsWith("[LOW]");
          const isMedium = entry.startsWith("[MEDIUM]");
          const isHigh = entry.startsWith("[HIGH]");
          const isCritical = entry.startsWith("[CRITICAL]");

          let className = "text-gray-400";
          if (isLow) className = "text-severity-low";
          if (isMedium) className = "text-severity-medium";
          if (isHigh) className = "text-severity-high";
          if (isCritical) className = "text-severity-critical";

          return (
            <div key={index} className={className}>
              {entry}
            </div>
          );
        })}
      </div>
    </div>
  );
}
