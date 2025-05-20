import axios from 'axios';
import { JSDOM } from 'jsdom';
import * as https from 'https';
import * as url from 'url';

interface WebScanResult {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  location: string;
  evidence?: string;
  impact?: string;
  remediation?: string;
}

interface WebScanOptions {
  includeSubdomains?: boolean;
  maxPages?: number;
  followRedirects?: boolean;
  checkXSS?: boolean;
  checkSQLi?: boolean;
  checkHeaders?: boolean;
  userAgent?: string;
  timeout?: number;
}

const defaultOptions: WebScanOptions = {
  includeSubdomains: false,
  maxPages: 10,
  followRedirects: true,
  checkXSS: true,
  checkSQLi: true,
  checkHeaders: true,
  userAgent: 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
  timeout: 10000,
};

/**
 * Simple web security scanner implementation
 */
export class WebScanner {
  private visitedUrls: Set<string> = new Set();
  private findings: WebScanResult[] = [];
  private baseUrl: string = '';
  private options: WebScanOptions;
  
  constructor(options: WebScanOptions = {}) {
    this.options = { ...defaultOptions, ...options };
  }
  
  /**
   * Main scan method
   */
  async scan(targetUrl: string): Promise<WebScanResult[]> {
    // Normalize the URL for consistency
    this.baseUrl = this.normalizeUrl(targetUrl);
    
    try {
      // Test initial connectivity
      await this.fetchUrl(this.baseUrl);
      
      // Add initial URL to the list
      this.visitedUrls.add(this.baseUrl);
      
      // Start the crawl with the base URL
      await this.crawlPage(this.baseUrl, 0);
      
      // Scan headers of the main page
      if (this.options.checkHeaders) {
        await this.checkSecurityHeaders(this.baseUrl);
      }
      
      return this.findings;
    } catch (error) {
      console.error('Error scanning website:', error);
      this.findings.push({
        id: this.generateId(),
        severity: 'info',
        title: 'Scan Error',
        description: `Could not complete scan: ${error instanceof Error ? error.message : 'Unknown error'}`,
        location: targetUrl,
      });
      return this.findings;
    }
  }
  
  /**
   * Crawl a page and find links to other pages
   */
  private async crawlPage(url: string, depth: number): Promise<void> {
    // Check if we've reached the maximum crawl depth
    if (this.visitedUrls.size >= this.options.maxPages!) {
      return;
    }
    
    try {
      // Fetch the page content
      const response = await this.fetchUrl(url);
      const html = response.data;
      
      // Parse the HTML
      const { document } = new JSDOM(html).window;
      
      // Check for vulnerabilities
      if (this.options.checkXSS) {
        this.checkForXSS(url, html, document);
      }
      
      if (this.options.checkSQLi) {
        this.checkForSQLInjection(url, html);
      }
      
      // Extract all links from the page
      const links = Array.from(document.querySelectorAll('a'))
        .map(a => a.href)
        .filter(href => href && !href.startsWith('javascript:') && !href.startsWith('#'));
      
      // Normalize and filter links
      const normalizedLinks = links
        .map(link => this.resolveUrl(url, link))
        .filter(link => this.shouldCrawl(link));
      
      // Visit each link
      for (const link of normalizedLinks) {
        if (!this.visitedUrls.has(link)) {
          this.visitedUrls.add(link);
          await this.crawlPage(link, depth + 1);
        }
      }
    } catch (error) {
      console.error(`Error crawling ${url}:`, error);
    }
  }
  
  /**
   * Check if a URL should be crawled
   */
  private shouldCrawl(url: string): boolean {
    // Skip if already visited
    if (this.visitedUrls.has(url)) {
      return false;
    }
    
    // Parse the URLs
    const baseUrlParsed = new URL(this.baseUrl);
    const currentUrlParsed = new URL(url);
    
    // Only crawl the same domain (or subdomains if enabled)
    if (this.options.includeSubdomains) {
      if (!currentUrlParsed.hostname.endsWith(baseUrlParsed.hostname)) {
        return false;
      }
    } else {
      if (currentUrlParsed.hostname !== baseUrlParsed.hostname) {
        return false;
      }
    }
    
    return true;
  }
  
  /**
   * Fetch a URL and get its contents
   */
  private async fetchUrl(url: string) {
    return axios.get(url, {
      headers: {
        'User-Agent': this.options.userAgent!,
      },
      timeout: this.options.timeout,
      maxRedirects: this.options.followRedirects ? 5 : 0,
      validateStatus: (status) => status < 400, // Only accept 2xx and 3xx status codes
      httpsAgent: new https.Agent({
        rejectUnauthorized: false, // Allow self-signed certificates
      }),
    });
  }
  
  /**
   * Check for common security headers
   */
  private async checkSecurityHeaders(url: string) {
    try {
      const response = await axios.head(url, {
        headers: {
          'User-Agent': this.options.userAgent!,
        },
        timeout: this.options.timeout,
        validateStatus: () => true,
      });
      
      const headers = response.headers;
      
      // Check for X-XSS-Protection header
      if (!headers['x-xss-protection']) {
        this.findings.push({
          id: this.generateId(),
          severity: 'low',
          title: 'Missing X-XSS-Protection Header',
          description: 'The X-XSS-Protection header is not set, which can help prevent some XSS attacks in older browsers.',
          location: url,
          impact: 'Limited impact on modern browsers, but older browsers may be more vulnerable to XSS attacks.',
          remediation: 'Add the header "X-XSS-Protection: 1; mode=block" to your server responses.',
        });
      }
      
      // Check for X-Content-Type-Options header
      if (!headers['x-content-type-options']) {
        this.findings.push({
          id: this.generateId(),
          severity: 'low',
          title: 'Missing X-Content-Type-Options Header',
          description: 'The X-Content-Type-Options header is not set, which can prevent MIME type sniffing attacks.',
          location: url,
          impact: 'Browsers may interpret the content in ways not intended by the server, potentially leading to security issues.',
          remediation: 'Add the header "X-Content-Type-Options: nosniff" to your server responses.',
        });
      }
      
      // Check for Content-Security-Policy header
      if (!headers['content-security-policy']) {
        this.findings.push({
          id: this.generateId(),
          severity: 'medium',
          title: 'Missing Content-Security-Policy Header',
          description: 'The Content-Security-Policy header is not set, which helps prevent various types of attacks including XSS and data injection.',
          location: url,
          impact: 'The website may be more vulnerable to XSS and other injection attacks.',
          remediation: 'Implement a Content Security Policy appropriate for your website. Start with a simple policy and expand it based on your needs.',
        });
      }
      
      // Check for Strict-Transport-Security header
      if (url.startsWith('https://') && !headers['strict-transport-security']) {
        this.findings.push({
          id: this.generateId(),
          severity: 'medium',
          title: 'Missing Strict-Transport-Security Header',
          description: 'The Strict-Transport-Security header is not set, which helps ensure that browsers always use HTTPS.',
          location: url,
          impact: 'Users may be vulnerable to downgrade attacks and man-in-the-middle attacks.',
          remediation: 'Add the header "Strict-Transport-Security: max-age=31536000; includeSubDomains" to your server responses.',
        });
      }
      
      // Check for X-Frame-Options header
      if (!headers['x-frame-options']) {
        this.findings.push({
          id: this.generateId(),
          severity: 'low',
          title: 'Missing X-Frame-Options Header',
          description: 'The X-Frame-Options header is not set, which can help prevent clickjacking attacks.',
          location: url,
          impact: 'The website may be vulnerable to clickjacking attacks where it is loaded in an iframe on a malicious site.',
          remediation: 'Add the header "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" to your server responses.',
        });
      }
      
    } catch (error) {
      console.error('Error checking security headers:', error);
    }
  }
  
  /**
   * Check for potential XSS vulnerabilities
   */
  private checkForXSS(url: string, html: string, document: Document) {
    try {
      // Look for reflected parameters in the URL and HTML
      const parsedUrl = new URL(url);
      const params = new URLSearchParams(parsedUrl.search);
      
      for (const [param, value] of params.entries()) {
        if (value && html.includes(value)) {
          // Check if the value appears to be unsanitized
          if (this.containsUnsanitizedValue(html, value)) {
            this.findings.push({
              id: this.generateId(),
              severity: 'high',
              title: 'Potential Reflected XSS Vulnerability',
              description: `The parameter "${param}" from the URL appears to be reflected in the page without proper sanitization.`,
              location: `${url} (parameter: ${param})`,
              evidence: `URL parameter "${param}=${value}" is reflected in the page response.`,
              impact: 'An attacker could craft a malicious URL that, when visited by a victim, executes arbitrary JavaScript in the victim\'s browser context.',
              remediation: 'Properly sanitize or encode all user-controlled input before reflecting it in HTML responses. Consider implementing a Content Security Policy.',
            });
          }
        }
      }
      
      // Check for DOM-based XSS sources and sinks
      const dangerousSinks = [
        ...Array.from(document.querySelectorAll('script')),
        ...Array.from(document.querySelectorAll('[onload]')),
        ...Array.from(document.querySelectorAll('[onerror]')),
        ...Array.from(document.querySelectorAll('[onclick]')),
      ];
      
      for (const sink of dangerousSinks) {
        const sinkContent = sink.textContent || sink.getAttribute('onload') || 
                           sink.getAttribute('onerror') || sink.getAttribute('onclick') || '';
        
        if (sinkContent.includes('location.') || 
            sinkContent.includes('document.URL') || 
            sinkContent.includes('document.documentURI') || 
            sinkContent.includes('document.referrer')) {
          
          this.findings.push({
            id: this.generateId(),
            severity: 'high',
            title: 'Potential DOM-based XSS Vulnerability',
            description: 'JavaScript code on the page uses unfiltered data from the URL in a potentially unsafe way.',
            location: url,
            evidence: `Potentially vulnerable code: ${sinkContent.substring(0, 100)}${sinkContent.length > 100 ? '...' : ''}`,
            impact: 'An attacker could craft a malicious URL that, when visited by a victim, executes arbitrary JavaScript in the victim\'s browser context.',
            remediation: 'Use safe DOM APIs or sanitize URL data before using it in JavaScript. Consider implementing a Content Security Policy.',
          });
        }
      }
    } catch (error) {
      console.error('Error checking for XSS:', error);
    }
  }
  
  /**
   * Check if a value appears to be unsanitized in HTML
   */
  private containsUnsanitizedValue(html: string, value: string): boolean {
    // Simple check for now - a more comprehensive version would parse the HTML
    // and check if the value is inside a script tag, event handler, etc.
    
    // Test if the value contains special characters that might be used for XSS
    const hasSpecialChars = /[<>"'&]/.test(value);
    if (!hasSpecialChars) {
      return false; // No special chars to exploit
    }
    
    // Check if the value appears unchanged in the HTML
    return html.includes(value);
  }
  
  /**
   * Check for potential SQL injection vulnerabilities
   */
  private checkForSQLInjection(url: string, html: string) {
    try {
      // Look for common SQL error messages
      const sqlErrorPatterns = [
        'SQL syntax',
        'mysql_fetch_array',
        'pg_query',
        'sqlite_query',
        'SQL server',
        'ORA-01756',  // Oracle error
        'Microsoft SQL Native Client error',
        'ODBC Driver error',
        'MySQLSyntaxErrorException',
        'Microsoft OLE DB Provider for SQL Server',
        'SQLite3::query',
        'postgresql.util.PSQLException',
        'ERROR: syntax error at or near',
        'Unclosed quotation mark after the character string',
      ];
      
      for (const pattern of sqlErrorPatterns) {
        if (html.includes(pattern)) {
          this.findings.push({
            id: this.generateId(),
            severity: 'critical',
            title: 'Potential SQL Injection Vulnerability',
            description: 'SQL error messages were detected in the page response, which might indicate a SQL injection vulnerability.',
            location: url,
            evidence: `SQL error pattern detected: "${pattern}"`,
            impact: 'An attacker could potentially execute arbitrary SQL commands on the database, leading to unauthorized access, data leakage, or data manipulation.',
            remediation: 'Use parameterized queries or prepared statements instead of string concatenation. Implement proper error handling to avoid leaking technical details in error messages.',
          });
          break; // One finding is enough for this type of check
        }
      }
      
      // Check URL for SQL injection testing patterns
      const parsedUrl = new URL(url);
      const params = new URLSearchParams(parsedUrl.search);
      
      const sqlInjectionTestPatterns = ["'", "''", "1=1", "1=2", "' OR '1'='1", "' OR '1'='1' --", "1' OR '1'='1", "admin' --"];
      
      for (const [param, value] of params.entries()) {
        for (const pattern of sqlInjectionTestPatterns) {
          if (value.includes(pattern)) {
            this.findings.push({
              id: this.generateId(),
              severity: 'info',
              title: 'SQL Injection Test Pattern Detected',
              description: `A URL parameter contains what appears to be a SQL injection test pattern.`,
              location: `${url} (parameter: ${param})`,
              evidence: `Parameter "${param}" contains a potential SQL injection test pattern: "${value}"`,
              impact: 'This is informational only. However, if the parameter is vulnerable to SQL injection, an attacker could potentially execute arbitrary SQL commands.',
              remediation: 'Ensure that all user input is properly validated and sanitized before being used in SQL queries. Use parameterized queries or prepared statements.',
            });
            break;
          }
        }
      }
    } catch (error) {
      console.error('Error checking for SQL injection:', error);
    }
  }
  
  /**
   * Normalize a URL for consistency
   */
  private normalizeUrl(urlString: string): string {
    // Add protocol if missing
    if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
      urlString = 'https://' + urlString;
    }
    
    try {
      const parsedUrl = new URL(urlString);
      
      // Remove fragments
      parsedUrl.hash = '';
      
      // Normalize the path
      if (parsedUrl.pathname === '') {
        parsedUrl.pathname = '/';
      }
      
      return parsedUrl.toString();
    } catch (error) {
      return urlString; // Return as is if can't parse
    }
  }
  
  /**
   * Resolve a relative URL against a base URL
   */
  private resolveUrl(baseUrl: string, relativeUrl: string): string {
    try {
      return new URL(relativeUrl, baseUrl).href;
    } catch (error) {
      return baseUrl; // Return base URL if can't resolve
    }
  }
  
  /**
   * Generate a unique ID for findings
   */
  private generateId(): string {
    return Math.random().toString(36).substring(2, 15);
  }
}