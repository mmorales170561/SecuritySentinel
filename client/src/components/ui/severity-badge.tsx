import { cn } from "@/lib/utils";

interface SeverityBadgeProps {
  severity: "critical" | "high" | "medium" | "low" | "info";
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <div
      className={cn(
        "severity-badge",
        `bg-severity-${severity} bg-opacity-20 text-severity-${severity}`,
        className
      )}
    >
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </div>
  );
}
