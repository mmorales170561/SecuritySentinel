import { Severity } from "@shared/schema";

export interface MockFinding {
  id: string;
  severity: Severity;
  title: string;
  location: string;
  description: string;
  evidence?: string;
  impact?: string;
  remediation?: string;
  codeFix?: string;
  falsePositive: boolean;
  verified: boolean;
}

export const mockWebFindings: MockFinding[] = [
  {
    id: "f1",
    severity: "critical",
    title: "Cross-Site Scripting (XSS) Vulnerability",
    location: "/search?query= parameter",
    description: "The application doesn't properly sanitize user input in the search query parameter, allowing attackers to inject malicious JavaScript code that will execute in users' browsers.",
    evidence: `GET /search?query=<script>alert(document.cookie)</script> HTTP/1.1
Host: example.com

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
    id: "f2",
    severity: "critical",
    title: "SQL Injection Vulnerability",
    location: "/login endpoint",
    description: "The login endpoint is vulnerable to SQL injection attacks. User-supplied input is directly concatenated into an SQL query without proper parameterization.",
    evidence: `POST /login HTTP/1.1
Host: example.com
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
    id: "f3",
    severity: "high",
    title: "Sensitive Data Exposure",
    location: "/admin/ directory",
    description: "The application's admin directory is accessible without proper authentication, potentially exposing sensitive administrative functions and data.",
    evidence: `GET /admin/ HTTP/1.1
Host: example.com

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

export const mockCodeFindings: MockFinding[] = [
  {
    id: "c1",
    severity: "critical",
    title: "SQL Injection in Authentication Function",
    location: "authenticate function",
    description: "The function concatenates user input directly into an SQL query, creating a SQL injection vulnerability.",
    evidence: `def authenticate(username, password):
    # Connect to database
    connection = connect_to_db()
    
    # Execute query
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    result = connection.execute(query)
    
    # Check if user exists
    if result.rowcount > 0:
        return True
    else:
        return False`,
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
  },
  {
    id: "c2",
    severity: "high",
    title: "Insecure Password Storage",
    location: "authenticate function",
    description: "Passwords are stored and compared in plain text, which is highly insecure.",
    evidence: `def authenticate(username, password):
    # Connect to database
    connection = connect_to_db()
    
    # Execute query
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    result = connection.execute(query)`,
    impact: "If the database is compromised, attackers will have immediate access to all user passwords. This could lead to account takeover not just on your system but on other systems where users might reuse their passwords.",
    remediation: "1. Use a strong, slow hashing algorithm like bcrypt, Argon2, or PBKDF2 with a high number of iterations.\n2. Never store or compare plain text passwords.\n3. Implement password policies to ensure strong passwords.",
    codeFix: `# Before
def authenticate(username, password):
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    result = connection.execute(query, (username, password))
    
# After
import bcrypt

def authenticate(username, password):
    query = "SELECT * FROM users WHERE username = %s"
    result = connection.execute(query, (username,))
    user = result.fetchone()
    
    if user:
        # Compare hashed password
        return bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8'))
    return False`,
    falsePositive: false,
    verified: false,
  },
  {
    id: "c3",
    severity: "medium",
    title: "Missing Error Handling",
    location: "authenticate function",
    description: "The function does not include any error handling for database connection failures or query execution errors.",
    evidence: `def authenticate(username, password):
    # Connect to database
    connection = connect_to_db()
    
    # Execute query
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    result = connection.execute(query)
    
    # Check if user exists
    if result.rowcount > 0:
        return True
    else:
        return False`,
    impact: "Without proper error handling, the application might crash or behave unexpectedly when encountering database issues. This could lead to denial of service or information leakage through unhandled exceptions.",
    remediation: "Implement comprehensive error handling with try/except blocks to catch and properly manage database connection and query execution errors.",
    codeFix: `# Before
def authenticate(username, password):
    connection = connect_to_db()
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    result = connection.execute(query, (username, password))
    return result.rowcount > 0
    
# After
def authenticate(username, password):
    try:
        connection = connect_to_db()
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        result = connection.execute(query, (username, password))
        return result.rowcount > 0
    except DatabaseConnectionError:
        logger.error("Failed to connect to database during authentication")
        raise AuthenticationError("Service temporarily unavailable")
    except QueryExecutionError as e:
        logger.error(f"Query error during authentication: {str(e)}")
        raise AuthenticationError("Authentication service error")`,
    falsePositive: false,
    verified: false,
  }
];
