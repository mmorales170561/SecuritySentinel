import { v4 as uuidv4 } from "uuid";
import { 
  type User, 
  type InsertUser, 
  type Scan, 
  type InsertScan, 
  type Finding, 
  type InsertFinding,
  type ScanResult,
  type WebScanRequest,
  type CodeAnalysisRequest,
  type SeverityType,
  findings,
  scans,
  users
} from "@shared/schema";
import { IStorage } from "./storage";
import { db } from "./db";
import { eq } from "drizzle-orm";

// Database implementation of the storage interface
export class DatabaseStorage implements IStorage {
  // User methods
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user || undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(insertUser)
      .returning();
    return user;
  }
  
  // Scan methods
  async createScan(insertScan: InsertScan): Promise<Scan> {
    const [scan] = await db
      .insert(scans)
      .values(insertScan)
      .returning();
    return scan;
  }
  
  async getScan(id: number): Promise<Scan | undefined> {
    const [scan] = await db.select().from(scans).where(eq(scans.id, id));
    return scan || undefined;
  }
  
  async getScansByTarget(target: string): Promise<Scan[]> {
    return await db.select().from(scans).where(eq(scans.target, target));
  }
  
  async updateScanStatus(id: number, status: string, findings?: any): Promise<Scan | undefined> {
    const [scan] = await db
      .update(scans)
      .set({ 
        status, 
        findings: findings ? findings : undefined,
        completedAt: status === 'completed' ? new Date() : undefined
      })
      .where(eq(scans.id, id))
      .returning();
      
    return scan || undefined;
  }
  
  async getAllScans(): Promise<Scan[]> {
    return await db.select().from(scans);
  }
  
  // Finding methods
  async createFinding(insertFinding: InsertFinding): Promise<Finding> {
    const [finding] = await db
      .insert(findings)
      .values(insertFinding)
      .returning();
    return finding;
  }
  
  async getFindingsByScanId(scanId: number): Promise<Finding[]> {
    return await db.select().from(findings).where(eq(findings.scanId, scanId));
  }
  
  async markFindingAsFalsePositive(id: number, isFalse: boolean): Promise<Finding | undefined> {
    const [finding] = await db
      .update(findings)
      .set({ falsePositive: isFalse })
      .where(eq(findings.id, id))
      .returning();
      
    return finding || undefined;
  }
  
  async markFindingAsVerified(id: number, isVerified: boolean): Promise<Finding | undefined> {
    const [finding] = await db
      .update(findings)
      .set({ verified: isVerified })
      .where(eq(findings.id, id))
      .returning();
      
    return finding || undefined;
  }

  // Simulate a web security scan
  async simulateWebScan(request: WebScanRequest): Promise<ScanResult> {
    // This would typically call external tools or APIs
    // For demo purposes, we'll return mock results after a delay
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Generate mock findings based on scan type
    const findings = this.generateMockWebFindings(request.url, request.scanType);
    
    // Count findings by severity
    const stats = this.countFindingsBySeverity(findings);

    return {
      target: request.url,
      scanType: request.scanType,
      startedAt: new Date(),
      completedAt: new Date(),
      status: "completed",
      findings,
      stats,
    };
  }

  // Simulate code analysis
  async simulateCodeAnalysis(request: CodeAnalysisRequest): Promise<ScanResult> {
    // Simulate processing time
    await new Promise(resolve => setTimeout(resolve, 1500));

    // Generate mock findings based on code and language
    const findings = this.generateMockCodeFindings(request.code, request.language);
    
    // Count findings by severity
    const stats = this.countFindingsBySeverity(findings);

    return {
      target: `Code snippet (${request.language})`,
      scanType: "code-analysis",
      startedAt: new Date(),
      completedAt: new Date(),
      status: "completed",
      findings,
      stats,
    };
  }

  // Helper to generate mock web findings
  private generateMockWebFindings(url: string, scanType: string) {
    const findings = [
      {
        id: uuidv4(),
        severity: "critical" as SeverityType,
        title: "Cross-Site Scripting (XSS) Vulnerability",
        location: "/search?query= parameter",
        description: "The application doesn't properly sanitize user input in the search query parameter, allowing attackers to inject malicious JavaScript code that will execute in users' browsers.",
        evidence: `GET /search?query=<script>alert(document.cookie)</script> HTTP/1.1
Host: ${url}

HTTP/1.1 200 OK
Content-Type: text/html
...

<div class="search-results">
    <h2>Search results for: <script>alert(document.cookie)</script></h2>
    ...
</div>`,
        impact: "Attackers can steal session cookies, perform actions on behalf of the victim, or redirect users to malicious websites. This vulnerability may lead to complete account takeover.",
        remediation: "1. Implement proper input validation and output encoding using a well-tested library.\n2. Use Content-Security-Policy headers to mitigate XSS attacks.\n3. Set the HttpOnly and Secure flags on sensitive cookies.",
        codeFix: `// Before
const searchQuery = req.query.q;
res.send(\`<h2>Search results for: \${searchQuery}</h2>\`);

// After
const searchQuery = req.query.q;
const sanitizedQuery = escapeHtml(searchQuery);
res.send(\`<h2>Search results for: \${sanitizedQuery}</h2>\`);

// Helper function
function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}`,
        falsePositive: false,
        verified: false,
      },
      {
        id: uuidv4(),
        severity: "critical" as const,
        title: "SQL Injection Vulnerability",
        location: "/login endpoint",
        description: "The login endpoint is vulnerable to SQL injection attacks. User-supplied input is directly concatenated into an SQL query without proper parameterization.",
        evidence: `POST /login HTTP/1.1
Host: ${url}
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=anything

HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`,
        impact: "An attacker can bypass authentication, extract sensitive data from the database, modify database data, or execute administrative operations on the database.",
        remediation: "1. Use parameterized queries or prepared statements instead of string concatenation.\n2. Implement an ORM (Object-Relational Mapping) library that handles SQL escaping.\n3. Apply the principle of least privilege to database accounts used by the application.",
        codeFix: `# Before
def authenticate(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    result = connection.execute(query)
    
# After
def authenticate(username, password):
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    result = connection.execute(query, (username, password))`,
        falsePositive: false,
        verified: false,
      },
      {
        id: uuidv4(),
        severity: "high" as const,
        title: "Sensitive Data Exposure",
        location: "/admin/ directory",
        description: "The application's admin directory is accessible without proper authentication, potentially exposing sensitive administrative functions and data.",
        evidence: `GET /admin/ HTTP/1.1
Host: ${url}

HTTP/1.1 200 OK
Content-Type: text/html
...

<html>
<head><title>Admin Panel</title></head>
<body>
    <h1>Admin Panel</h1>
    <ul>
        <li><a href="/admin/users">User Management</a></li>
        <li><a href="/admin/settings">System Settings</a></li>
        <li><a href="/admin/logs">System Logs</a></li>
    </ul>
</body>
</html>`,
        impact: "Attackers can access administrative functions, view or modify user data, change system settings, or obtain information about the system that could facilitate further attacks.",
        remediation: "1. Implement proper authentication and authorization for all administrative pages.\n2. Use network-level access controls to restrict admin pages to specific IP addresses.\n3. Consider moving the admin panel to a separate subdomain with additional security measures.\n4. Implement multi-factor authentication for administrative access.",
        falsePositive: false,
        verified: false,
      }
    ];

    // Add more findings based on scan type
    if (scanType === "authentication" || scanType === "full") {
      findings.push({
        id: uuidv4(),
        severity: "high" as const,
        title: "Weak Password Policy",
        location: "/signup endpoint",
        description: "The application does not enforce a strong password policy, allowing users to create accounts with weak passwords.",
        evidence: `POST /signup HTTP/1.1
Host: ${url}
Content-Type: application/x-www-form-urlencoded

username=testuser&password=123456

HTTP/1.1 302 Found
Location: /dashboard`,
        impact: "Weak passwords are more susceptible to brute force attacks, potentially leading to unauthorized account access.",
        remediation: "1. Implement a strong password policy requiring minimum length, complexity, and preventing common passwords.\n2. Use a password strength meter on the client side to guide users.\n3. Consider implementing additional authentication factors for sensitive operations.",
        falsePositive: false,
        verified: false,
      });
    }

    if (scanType === "injection" || scanType === "full") {
      findings.push({
        id: uuidv4(),
        severity: "medium" as const,
        title: "Command Injection Vulnerability",
        location: "/api/ping endpoint",
        description: "The application's ping utility endpoint passes user input directly to a system command without proper validation.",
        evidence: `GET /api/ping?host=example.com;cat%20/etc/passwd HTTP/1.1
Host: ${url}

HTTP/1.1 200 OK
Content-Type: text/plain
...

PING example.com (93.184.216.34): 56 data bytes
64 bytes from 93.184.216.34: icmp_seq=0 ttl=56 time=11.632 ms
...
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...`,
        impact: "Attackers can execute arbitrary commands on the server, potentially gaining unauthorized access to the system, reading sensitive files, or further compromising the server.",
        remediation: "1. Validate and sanitize all user input before passing it to system commands.\n2. Implement a whitelist of allowed characters and patterns.\n3. Consider using libraries that provide safer alternatives to direct command execution.",
        codeFix: `// Before
app.get('/api/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 4 ' + host, (error, stdout) => {
    res.send(stdout);
  });
});

// After
app.get('/api/ping', (req, res) => {
  const host = req.query.host;
  // Validate input - only allow alphanumeric characters, dots, and hyphens
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
    return res.status(400).send('Invalid hostname');
  }
  
  exec('ping -c 4 ' + host, (error, stdout) => {
    res.send(stdout);
  });
});`,
        falsePositive: false,
        verified: false,
      });
    }

    return findings;
  }

  // Helper to generate mock code findings
  private generateMockCodeFindings(code: string, language: string) {
    // The findings we generate will depend on the language and code content
    // For this demo, we'll generate findings based on common issues
    
    const findings = [];
    
    // Check for SQL injection in Python code
    if (language === "python" && code.includes("SELECT") && code.includes("+")) {
      findings.push({
        id: uuidv4(),
        severity: "critical" as const,
        title: "SQL Injection Vulnerability",
        location: "authenticate function",
        description: "The function concatenates user input directly into an SQL query, creating a SQL injection vulnerability.",
        evidence: code,
        impact: "Attackers can bypass authentication, extract or modify data from the database, or perform database administrative operations.",
        remediation: "Use parameterized queries or an ORM instead of string concatenation to build SQL queries.",
        codeFix: `# Before
def authenticate(username, password):
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    result = connection.execute(query)
    
# After
def authenticate(username, password):
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    result = connection.execute(query, (username, password))`,
        falsePositive: false,
        verified: false,
      });
    }
    
    // Check for XSS in JavaScript
    if (language === "javascript" && code.includes("innerHTML") && !code.includes("DOMPurify")) {
      findings.push({
        id: uuidv4(),
        severity: "high" as const,
        title: "Cross-Site Scripting (XSS) Vulnerability",
        location: "DOM manipulation",
        description: "The application uses innerHTML with unsanitized user input, which can lead to XSS attacks.",
        evidence: code,
        impact: "Attackers can inject malicious scripts that execute in the user's browser, potentially stealing cookies, session tokens, or redirecting to malicious sites.",
        remediation: "Use textContent instead of innerHTML for plain text, or sanitize input with a library like DOMPurify before using innerHTML.",
        codeFix: `// Before
const userInput = document.getElementById('input').value;
document.getElementById('output').innerHTML = userInput;

// After
// For plain text:
const userInput = document.getElementById('input').value;
document.getElementById('output').textContent = userInput;

// OR for HTML content:
// import DOMPurify from 'dompurify';
const userInput = document.getElementById('input').value;
document.getElementById('output').innerHTML = DOMPurify.sanitize(userInput);`,
        falsePositive: false,
        verified: false,
      });
    }
    
    // Check for insecure random numbers in JavaScript
    if (language === "javascript" && code.includes("Math.random") && code.includes("password")) {
      findings.push({
        id: uuidv4(),
        severity: "medium",
        title: "Insecure Randomness",
        location: "Password generation",
        description: "The application uses Math.random() for generating security-sensitive values like passwords or tokens, which is not cryptographically secure.",
        evidence: code,
        impact: "Math.random() is not cryptographically secure and can be predicted by attackers, potentially leading to token or password prediction.",
        remediation: "Use the Web Crypto API (crypto.getRandomValues) for generating secure random values in JavaScript.",
        codeFix: `// Before
function generatePassword(length) {
    const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let password = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        password += charset[randomIndex];
    }
    return password;
}

// After
function generatePassword(length) {
    const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    const randomValues = new Uint32Array(length);
    crypto.getRandomValues(randomValues);
    
    let password = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = randomValues[i] % charset.length;
        password += charset[randomIndex];
    }
    return password;
}`,
        falsePositive: false,
        verified: false,
      });
    }
    
    return findings;
  }

  // Helper to count findings by severity
  private countFindingsBySeverity(findings: any[]) {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    
    findings.forEach(finding => {
      // Make sure the severity is one of the valid keys
      const severity = finding.severity as keyof typeof counts;
      if (counts.hasOwnProperty(severity)) {
        counts[severity]++;
      }
    });
    
    return counts;
  }
}