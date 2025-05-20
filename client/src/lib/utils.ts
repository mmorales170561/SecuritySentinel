import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDateTime(date: Date | string): string {
  if (!date) return '';
  
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true
  });
}

export function truncateText(text: string, maxLength: number = 100): string {
  if (!text) return '';
  if (text.length <= maxLength) return text;
  
  return text.slice(0, maxLength) + '...';
}

/**
 * Format a number with commas
 * @param num Number to format
 * @returns Formatted number string
 */
export function formatNumber(num: number): string {
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/**
 * Validates a URL string
 * @param url URL to validate
 * @returns True if valid URL
 */
export function isValidUrl(url: string): boolean {
  try {
    // Add protocol if missing
    if (!/^https?:\/\//i.test(url)) {
      url = 'http://' + url;
    }
    new URL(url);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Calculate severity class suffix
 * @param severity The severity level
 * @returns CSS class suffix
 */
export function getSeverityClass(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    case 'info':
      return 'info';
    default:
      return 'info';
  }
}
