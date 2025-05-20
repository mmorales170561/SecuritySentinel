/**
 * Code Analyzer - A simple security code analyzer inspired by Semgrep and other SAST tools
 * 
 * This analyzer uses regular expressions and pattern matching to identify common
 * security issues in source code from different languages.
 */

interface CodeVulnerability {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  location: {
    line: number;
    column?: number;
    snippet: string;
  };
  language: string;
  remediation?: string;
  cwe?: string; // Common Weakness Enumeration ID
}

interface AnalysisOptions {
  language?: string;
  checkSensitiveData?: boolean;
  checkInjection?: boolean;
  checkAuthentication?: boolean;
  checkCryptography?: boolean;
}

const defaultOptions: AnalysisOptions = {
  language: 'auto',
  checkSensitiveData: true,
  checkInjection: true,
  checkAuthentication: true,
  checkCryptography: true,
};

export class CodeAnalyzer {
  private options: AnalysisOptions;
  
  constructor(options: AnalysisOptions = {}) {
    this.options = { ...defaultOptions, ...options };
  }
  
  /**
   * Main method to analyze code
   */
  analyze(code: string, language?: string): CodeVulnerability[] {
    // If language is not provided, use the one from options
    language = language || this.options.language;
    
    // If language is 'auto', try to detect it
    if (language === 'auto') {
      language = this.detectLanguage(code);
    }
    
    // Get the appropriate analyzer for the language
    const languageAnalyzer = this.getLanguageAnalyzer(language!);
    
    // Run the analyzer
    return languageAnalyzer(code);
  }
  
  /**
   * Detect the language from code content (very simplistic)
   */
  private detectLanguage(code: string): string {
    if (code.includes('<?php')) {
      return 'php';
    } else if (code.includes('import java.') || code.includes('public class ')) {
      return 'java';
    } else if (code.includes('using System;') || code.includes('namespace ')) {
      return 'csharp';
    } else if (code.includes('def ') && code.includes(':') && !code.includes('{')) {
      return 'python';
    } else if (code.includes('function ') && (code.includes('=>') || code.includes('{'))) {
      return 'javascript';
    } else if (code.includes('<html') || code.includes('<!DOCTYPE html')) {
      return 'html';
    } else if (code.includes('package ') && code.includes('func ')) {
      return 'go';
    } else if (code.includes('#include') && (code.includes('int main(') || code.includes('void main('))) {
      return 'c';
    } else {
      // Default to JavaScript as it's common
      return 'javascript';
    }
  }
  
  /**
   * Get language-specific analyzer function
   */
  private getLanguageAnalyzer(language: string): (code: string) => CodeVulnerability[] {
    switch (language.toLowerCase()) {
      case 'javascript':
      case 'js':
      case 'typescript':
      case 'ts':
        return this.analyzeJavaScript.bind(this);
      case 'python':
      case 'py':
        return this.analyzePython.bind(this);
      case 'java':
        return this.analyzeJava.bind(this);
      case 'php':
        return this.analyzePHP.bind(this);
      case 'csharp':
      case 'cs':
      case 'c#':
        return this.analyzeCSharp.bind(this);
      default:
        // Fall back to a generic analyzer
        return this.analyzeGeneric.bind(this);
    }
  }
  
  /**
   * JavaScript analyzer
   */
  private analyzeJavaScript(code: string): CodeVulnerability[] {
    const vulnerabilities: CodeVulnerability[] = [];
    
    // Split the code into lines for better location tracking
    const lines = code.split('\n');
    
    // Helper function to add vulnerabilities with code location
    const addVulnerability = (lineNumber: number, pattern: RegExp, vulnerability: Omit<CodeVulnerability, 'id' | 'location'>) => {
      const line = lines[lineNumber];
      const match = line.match(pattern);
      
      if (match) {
        vulnerabilities.push({
          id: this.generateId(),
          location: {
            line: lineNumber + 1,
            column: match.index,
            snippet: line.trim(),
          },
          language: 'javascript',
          ...vulnerability,
        });
      }
    };
    
    // Check for XSS vulnerabilities with innerHTML
    if (this.options.checkInjection) {
      lines.forEach((line, lineNumber) => {
        if (line.includes('innerHTML') && !line.includes('textContent') && !line.includes('DOMPurify')) {
          addVulnerability(lineNumber, /\.innerHTML\s*=/i, {
            severity: 'high',
            title: 'Cross-Site Scripting (XSS) Vulnerability',
            description: 'Using innerHTML with unsanitized input can lead to Cross-Site Scripting attacks.',
            remediation: 'Use textContent instead of innerHTML for plain text, or use a sanitization library like DOMPurify before setting innerHTML.',
            cwe: 'CWE-79',
          });
        }
      });
      
      // Check for eval usage
      lines.forEach((line, lineNumber) => {
        if (line.includes('eval(')) {
          addVulnerability(lineNumber, /eval\s*\(/i, {
            severity: 'high',
            title: 'Arbitrary Code Execution Risk',
            description: 'The use of eval() can lead to arbitrary code execution if user input is included.',
            remediation: 'Avoid using eval(). Consider safer alternatives like JSON.parse() for JSON data.',
            cwe: 'CWE-95',
          });
        }
      });
      
      // Check for SQL Injection in Node.js
      lines.forEach((line, lineNumber) => {
        if ((line.includes('query(') || line.includes('execute(')) && line.includes('+') && !line.includes('?')) {
          addVulnerability(lineNumber, /(query|execute)\s*\(\s*['"`][^'"`]*\$\{|\+/i, {
            severity: 'critical',
            title: 'SQL Injection Vulnerability',
            description: 'String concatenation in database queries can lead to SQL Injection attacks.',
            remediation: 'Use parameterized queries with prepared statements or an ORM instead of string concatenation.',
            cwe: 'CWE-89',
          });
        }
      });
    }
    
    // Check for weak crypto
    if (this.options.checkCryptography) {
      lines.forEach((line, lineNumber) => {
        if (line.includes('createCipher(') && (line.includes('"aes-128-"') || line.includes("'aes-128-'"))) {
          addVulnerability(lineNumber, /createCipher\s*\(/i, {
            severity: 'medium',
            title: 'Weak Cryptography',
            description: 'AES-128 is less secure than AES-256 for encryption.',
            remediation: 'Use AES-256 for encryption with createCipheriv() and a proper IV.',
            cwe: 'CWE-327',
          });
        }
        
        // Check for use of MD5 or SHA1
        if (line.includes('createHash(') && (line.includes('"md5"') || line.includes("'md5'") || 
                                             line.includes('"sha1"') || line.includes("'sha1'"))) {
          addVulnerability(lineNumber, /createHash\s*\(\s*['"](?:md5|sha1)['"]/i, {
            severity: 'medium',
            title: 'Weak Hashing Algorithm',
            description: 'MD5 and SHA1 are cryptographically broken and unsuitable for further use.',
            remediation: 'Use SHA-256, SHA-3, or Argon2 for hashing sensitive data. For passwords, use a specialized library like bcrypt.',
            cwe: 'CWE-327',
          });
        }
      });
    }
    
    // Check for hardcoded secrets
    if (this.options.checkSensitiveData) {
      lines.forEach((line, lineNumber) => {
        // Check for what looks like API keys, tokens, etc.
        const secretRegex = /['"`]((?:api|jwt|token|secret|password|auth)(?:_?key)?|access_token)['"`]\s*(?::|=)\s*['"`][A-Za-z0-9_\-\.]+['"`]/i;
        if (secretRegex.test(line)) {
          addVulnerability(lineNumber, secretRegex, {
            severity: 'high',
            title: 'Hardcoded Secret',
            description: 'Hardcoded API keys, tokens, or passwords were found in the code.',
            remediation: 'Move secrets to environment variables or a secure vault service.',
            cwe: 'CWE-798',
          });
        }
      });
    }
    
    // Check for insecure authentication
    if (this.options.checkAuthentication) {
      // Check for basic authentication without HTTPS
      let usesBasicAuth = false;
      let usesHttps = false;
      
      lines.forEach((line, lineNumber) => {
        if (line.includes('Authorization: Basic') || line.includes('Authorization: \'Basic') || 
            line.includes('Authorization: "Basic')) {
          usesBasicAuth = true;
        }
        
        if (line.includes('https://') || line.includes('HTTPS')) {
          usesHttps = true;
        }
      });
      
      if (usesBasicAuth && !usesHttps) {
        vulnerabilities.push({
          id: this.generateId(),
          severity: 'high',
          title: 'Insecure Authentication',
          description: 'Basic authentication is used without HTTPS, which can lead to credential theft.',
          location: {
            line: 1,
            snippet: 'Basic authentication without HTTPS',
          },
          language: 'javascript',
          remediation: 'Always use HTTPS when transmitting credentials, especially with Basic authentication.',
          cwe: 'CWE-319',
        });
      }
    }
    
    return vulnerabilities;
  }
  
  /**
   * Python analyzer
   */
  private analyzePython(code: string): CodeVulnerability[] {
    const vulnerabilities: CodeVulnerability[] = [];
    
    // Split the code into lines for better location tracking
    const lines = code.split('\n');
    
    // Helper function to add vulnerabilities with code location
    const addVulnerability = (lineNumber: number, pattern: RegExp, vulnerability: Omit<CodeVulnerability, 'id' | 'location'>) => {
      const line = lines[lineNumber];
      const match = line.match(pattern);
      
      if (match) {
        vulnerabilities.push({
          id: this.generateId(),
          location: {
            line: lineNumber + 1,
            column: match.index,
            snippet: line.trim(),
          },
          language: 'python',
          ...vulnerability,
        });
      }
    };
    
    // Check for SQL Injection vulnerabilities
    if (this.options.checkInjection) {
      lines.forEach((line, lineNumber) => {
        if ((line.includes('execute(') || line.includes('executemany(')) && 
            (line.includes('%') || line.includes('+') || line.includes('format(')) && 
            !line.includes('?') && !line.includes('%s')) {
          
          addVulnerability(lineNumber, /(execute|executemany)\s*\(/i, {
            severity: 'critical',
            title: 'SQL Injection Vulnerability',
            description: 'String concatenation or formatting in database queries can lead to SQL Injection attacks.',
            remediation: 'Use parameterized queries with placeholders (?, %s) or an ORM instead of string concatenation or formatting.',
            cwe: 'CWE-89',
          });
        }
      });
      
      // Check for OS command injection
      lines.forEach((line, lineNumber) => {
        if ((line.includes('os.system(') || line.includes('subprocess.call(') || 
             line.includes('subprocess.Popen(') || line.includes('exec(')) && 
            (line.includes('+') || line.includes('format(') || line.includes('f"') || line.includes("f'"))) {
          
          addVulnerability(lineNumber, /(os\.system|subprocess\.call|subprocess\.Popen|exec)\s*\(/i, {
            severity: 'critical',
            title: 'Command Injection Vulnerability',
            description: 'User input in OS commands can lead to command injection attacks.',
            remediation: 'Use subprocess modules with shell=False and pass arguments as a list instead of a single string.',
            cwe: 'CWE-78',
          });
        }
      });
    }
    
    // Check for weak cryptography
    if (this.options.checkCryptography) {
      lines.forEach((line, lineNumber) => {
        if (line.includes('hashlib.md5(') || line.includes('hashlib.sha1(')) {
          addVulnerability(lineNumber, /hashlib\.(md5|sha1)\s*\(/i, {
            severity: 'medium',
            title: 'Weak Hashing Algorithm',
            description: 'MD5 and SHA1 are cryptographically broken and unsuitable for further use.',
            remediation: 'Use SHA-256 or SHA-3 for hashing. For passwords, use a specialized library like bcrypt or Argon2.',
            cwe: 'CWE-327',
          });
        }
      });
    }
    
    // Check for hardcoded secrets
    if (this.options.checkSensitiveData) {
      lines.forEach((line, lineNumber) => {
        // Check for what looks like API keys, tokens, etc.
        const secretRegex = /(api_key|token|secret|password|auth_key|access_token)\s*=\s*['""][A-Za-z0-9_\-\.]+['""](?!\s*\()/i;
        if (secretRegex.test(line)) {
          addVulnerability(lineNumber, secretRegex, {
            severity: 'high',
            title: 'Hardcoded Secret',
            description: 'Hardcoded API keys, tokens, or passwords were found in the code.',
            remediation: 'Move secrets to environment variables or a secure vault service.',
            cwe: 'CWE-798',
          });
        }
      });
    }
    
    // Check for insecure deserialization
    if (this.options.checkInjection) {
      lines.forEach((line, lineNumber) => {
        if (line.includes('pickle.loads(') || line.includes('yaml.load(') && !line.includes('yaml.safe_load(')) {
          addVulnerability(lineNumber, /(pickle\.loads|yaml\.load)\s*\(/i, {
            severity: 'high',
            title: 'Insecure Deserialization',
            description: 'Deserializing untrusted data can lead to remote code execution.',
            remediation: 'Use safe alternatives like JSON or yaml.safe_load() instead of pickle.loads() or yaml.load().',
            cwe: 'CWE-502',
          });
        }
      });
    }
    
    return vulnerabilities;
  }
  
  /**
   * Java analyzer
   */
  private analyzeJava(code: string): CodeVulnerability[] {
    const vulnerabilities: CodeVulnerability[] = [];
    
    // Split the code into lines for better location tracking
    const lines = code.split('\n');
    
    // Helper function to add vulnerabilities with code location
    const addVulnerability = (lineNumber: number, pattern: RegExp, vulnerability: Omit<CodeVulnerability, 'id' | 'location'>) => {
      const line = lines[lineNumber];
      const match = line.match(pattern);
      
      if (match) {
        vulnerabilities.push({
          id: this.generateId(),
          location: {
            line: lineNumber + 1,
            column: match.index,
            snippet: line.trim(),
          },
          language: 'java',
          ...vulnerability,
        });
      }
    };
    
    // Check for SQL Injection
    if (this.options.checkInjection) {
      lines.forEach((line, lineNumber) => {
        if ((line.includes('executeQuery(') || line.includes('executeUpdate(') || line.includes('execute(')) && 
            (line.includes('+') || line.includes('concat')) && 
            !line.includes('PreparedStatement')) {
          
          addVulnerability(lineNumber, /(executeQuery|executeUpdate|execute)\s*\(/i, {
            severity: 'critical',
            title: 'SQL Injection Vulnerability',
            description: 'String concatenation in SQL queries can lead to SQL Injection attacks.',
            remediation: 'Use PreparedStatement with parameterized queries instead of string concatenation.',
            cwe: 'CWE-89',
          });
        }
      });
      
      // Check for XSS in Java web applications
      lines.forEach((line, lineNumber) => {
        if ((line.includes('getParameter(') || line.includes('getHeader(')) && 
            (line.includes('print') || line.includes('writer.write') || line.includes('response.getWriter()'))) {
          
          addVulnerability(lineNumber, /(getParameter|getHeader)\s*\(/i, {
            severity: 'high',
            title: 'Cross-Site Scripting (XSS) Vulnerability',
            description: 'Unsanitized user input is written directly to the response.',
            remediation: 'Sanitize user input before writing it to the response, or use a template engine that automatically escapes output.',
            cwe: 'CWE-79',
          });
        }
      });
    }
    
    // Check for hardcoded secrets
    if (this.options.checkSensitiveData) {
      lines.forEach((line, lineNumber) => {
        // Check for what looks like API keys, tokens, etc.
        const secretRegex = /(String|final)\s+(API_KEY|TOKEN|SECRET|PASSWORD|AUTH_KEY|ACCESS_TOKEN)\s*=\s*["'][A-Za-z0-9_\-\.]+["']/i;
        if (secretRegex.test(line)) {
          addVulnerability(lineNumber, secretRegex, {
            severity: 'high',
            title: 'Hardcoded Secret',
            description: 'Hardcoded API keys, tokens, or passwords were found in the code.',
            remediation: 'Move secrets to environment variables, properties files that are not checked into version control, or a secure vault service.',
            cwe: 'CWE-798',
          });
        }
      });
    }
    
    // Check for weak cryptography
    if (this.options.checkCryptography) {
      let usesMD5orSHA1 = false;
      
      lines.forEach((line, lineNumber) => {
        if (line.includes('MessageDigest.getInstance("MD5")') || line.includes('MessageDigest.getInstance("SHA-1")')) {
          addVulnerability(lineNumber, /MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-1)["']\s*\)/i, {
            severity: 'medium',
            title: 'Weak Hashing Algorithm',
            description: 'MD5 and SHA-1 are cryptographically broken and unsuitable for further use.',
            remediation: 'Use SHA-256 or SHA-3 for general hashing needs. For password storage, use a specialized library that implements bcrypt, PBKDF2, or Argon2.',
            cwe: 'CWE-327',
          });
        }
      });
    }
    
    return vulnerabilities;
  }
  
  /**
   * PHP analyzer
   */
  private analyzePHP(code: string): CodeVulnerability[] {
    const vulnerabilities: CodeVulnerability[] = [];
    
    // Split the code into lines
    const lines = code.split('\n');
    
    // Helper function to add vulnerabilities with code location
    const addVulnerability = (lineNumber: number, pattern: RegExp, vulnerability: Omit<CodeVulnerability, 'id' | 'location'>) => {
      const line = lines[lineNumber];
      const match = line.match(pattern);
      
      if (match) {
        vulnerabilities.push({
          id: this.generateId(),
          location: {
            line: lineNumber + 1,
            column: match.index,
            snippet: line.trim(),
          },
          language: 'php',
          ...vulnerability,
        });
      }
    };
    
    // Check for SQL Injection
    if (this.options.checkInjection) {
      lines.forEach((line, lineNumber) => {
        if ((line.includes('mysql_query(') || line.includes('mysqli_query(') || line.includes('->query(')) && 
            (line.includes('$_GET') || line.includes('$_POST') || line.includes('$_REQUEST'))) {
          
          addVulnerability(lineNumber, /(mysql_query|mysqli_query|\->query)\s*\(/i, {
            severity: 'critical',
            title: 'SQL Injection Vulnerability',
            description: 'Unsanitized user input in SQL queries can lead to SQL Injection attacks.',
            remediation: 'Use prepared statements with PDO or mysqli_prepare() instead of directly including user input in queries.',
            cwe: 'CWE-89',
          });
        }
      });
      
      // Check for XSS
      lines.forEach((line, lineNumber) => {
        if ((line.includes('echo') || line.includes('print')) && 
            (line.includes('$_GET') || line.includes('$_POST') || line.includes('$_REQUEST')) && 
            !line.includes('htmlspecialchars') && !line.includes('htmlentities')) {
          
          addVulnerability(lineNumber, /(echo|print)\s+/i, {
            severity: 'high',
            title: 'Cross-Site Scripting (XSS) Vulnerability',
            description: 'Unsanitized user input is output directly to the page.',
            remediation: 'Use htmlspecialchars() or htmlentities() to sanitize user input before outputting it.',
            cwe: 'CWE-79',
          });
        }
      });
    }
    
    // Check for hardcoded secrets
    if (this.options.checkSensitiveData) {
      lines.forEach((line, lineNumber) => {
        const secretRegex = /\$(API_KEY|TOKEN|SECRET|PASSWORD|AUTH_KEY|ACCESS_TOKEN)\s*=\s*["'][A-Za-z0-9_\-\.]+["']/i;
        if (secretRegex.test(line)) {
          addVulnerability(lineNumber, secretRegex, {
            severity: 'high',
            title: 'Hardcoded Secret',
            description: 'Hardcoded API keys, tokens, or passwords were found in the code.',
            remediation: 'Move secrets to environment variables or a secure configuration file that is not checked into version control.',
            cwe: 'CWE-798',
          });
        }
      });
    }
    
    // Check for dangerous PHP functions
    const dangerousFunctions = [
      'eval', 'exec', 'passthru', 'system', 'shell_exec', 'popen', 'proc_open', 'pcntl_exec',
      'assert', 'preg_replace' // with /e modifier, though it's deprecated
    ];
    
    dangerousFunctions.forEach(func => {
      lines.forEach((line, lineNumber) => {
        const pattern = new RegExp(`${func}\\s*\\(`, 'i');
        if (pattern.test(line)) {
          addVulnerability(lineNumber, pattern, {
            severity: 'high',
            title: 'Dangerous Function Usage',
            description: `The ${func}() function can be dangerous when used with user input as it might lead to code or command execution.`,
            remediation: 'Avoid using dangerous functions, especially with user input. Consider safer alternatives or properly validate and sanitize inputs.',
            cwe: func === 'eval' ? 'CWE-95' : 'CWE-78',
          });
        }
      });
    });
    
    return vulnerabilities;
  }
  
  /**
   * C# analyzer
   */
  private analyzeCSharp(code: string): CodeVulnerability[] {
    const vulnerabilities: CodeVulnerability[] = [];
    
    // Split the code into lines
    const lines = code.split('\n');
    
    // Helper function to add vulnerabilities with code location
    const addVulnerability = (lineNumber: number, pattern: RegExp, vulnerability: Omit<CodeVulnerability, 'id' | 'location'>) => {
      const line = lines[lineNumber];
      const match = line.match(pattern);
      
      if (match) {
        vulnerabilities.push({
          id: this.generateId(),
          location: {
            line: lineNumber + 1,
            column: match.index,
            snippet: line.trim(),
          },
          language: 'csharp',
          ...vulnerability,
        });
      }
    };
    
    // Check for SQL Injection
    if (this.options.checkInjection) {
      lines.forEach((line, lineNumber) => {
        if ((line.includes('ExecuteReader(') || line.includes('ExecuteNonQuery(') || 
             line.includes('ExecuteScalar(') || line.includes('ExecuteDataSet(')) && 
            line.includes('+') && !line.includes('Parameters.Add')) {
          
          addVulnerability(lineNumber, /(ExecuteReader|ExecuteNonQuery|ExecuteScalar|ExecuteDataSet)\s*\(/i, {
            severity: 'critical',
            title: 'SQL Injection Vulnerability',
            description: 'String concatenation in SQL queries can lead to SQL Injection attacks.',
            remediation: 'Use parameterized queries with SqlParameter objects instead of string concatenation.',
            cwe: 'CWE-89',
          });
        }
      });
      
      // Check for XSS in Web applications
      lines.forEach((line, lineNumber) => {
        if ((line.includes('Response.Write(') || line.includes('<%=')) && 
            (line.includes('Request.QueryString') || line.includes('Request.Form') || 
             line.includes('Request.Params')) && 
            !line.includes('HtmlEncode') && !line.includes('AntiXss')) {
          
          addVulnerability(lineNumber, /(Response\.Write|<%=)/i, {
            severity: 'high',
            title: 'Cross-Site Scripting (XSS) Vulnerability',
            description: 'Unsanitized user input is output directly to the page.',
            remediation: 'Sanitize user input using HttpUtility.HtmlEncode() or the AntiXss library before outputting it.',
            cwe: 'CWE-79',
          });
        }
      });
    }
    
    // Check for hardcoded secrets
    if (this.options.checkSensitiveData) {
      lines.forEach((line, lineNumber) => {
        const secretRegex = /(private|public|protected|const)\s+(string|var)\s+(API_KEY|TOKEN|SECRET|PASSWORD|AUTH_KEY|ACCESS_TOKEN)\s*=\s*["'][A-Za-z0-9_\-\.]+["']/i;
        if (secretRegex.test(line)) {
          addVulnerability(lineNumber, secretRegex, {
            severity: 'high',
            title: 'Hardcoded Secret',
            description: 'Hardcoded API keys, tokens, or passwords were found in the code.',
            remediation: 'Move secrets to configuration files, environment variables, or the Secret Manager.',
            cwe: 'CWE-798',
          });
        }
      });
    }
    
    // Check for insecure deserialization
    if (this.options.checkInjection) {
      lines.forEach((line, lineNumber) => {
        if ((line.includes('BinaryFormatter') || line.includes('XmlSerializer') || 
             line.includes('SoapFormatter') || line.includes('NetDataContractSerializer')) && 
            (line.includes('Deserialize') || line.includes('ReadObject'))) {
          
          addVulnerability(lineNumber, /(BinaryFormatter|XmlSerializer|SoapFormatter|NetDataContractSerializer)/i, {
            severity: 'high',
            title: 'Insecure Deserialization',
            description: 'Using binary or XML deserialization with untrusted data can lead to remote code execution.',
            remediation: 'Use safe alternatives like JSON.NET with type handling disabled, or implement serialization surrogate handlers.',
            cwe: 'CWE-502',
          });
        }
      });
    }
    
    // Check for weak cryptography
    if (this.options.checkCryptography) {
      lines.forEach((line, lineNumber) => {
        if (line.includes('MD5.Create()') || line.includes('SHA1.Create()') || 
            line.includes('new MD5CryptoServiceProvider') || line.includes('new SHA1CryptoServiceProvider')) {
          
          addVulnerability(lineNumber, /(MD5|SHA1)(\.|CryptoServiceProvider)/i, {
            severity: 'medium',
            title: 'Weak Hashing Algorithm',
            description: 'MD5 and SHA1 are cryptographically broken and unsuitable for further use.',
            remediation: 'Use SHA-256 or SHA-3 for general hashing. For password storage, use a specialized library or the built-in Rfc2898DeriveBytes (PBKDF2).',
            cwe: 'CWE-327',
          });
        }
      });
    }
    
    return vulnerabilities;
  }
  
  /**
   * Generic analyzer for languages without specific rules
   */
  private analyzeGeneric(code: string): CodeVulnerability[] {
    const vulnerabilities: CodeVulnerability[] = [];
    
    // Split the code into lines
    const lines = code.split('\n');
    
    // Generic checker for hardcoded secrets
    if (this.options.checkSensitiveData) {
      const secretPatterns = [
        /(['"`])(api[_-]?key|jwt|token|secret|password|auth|access[_-]?token)(['"`])\s*[:=]\s*(['"`])([A-Za-z0-9_\-\.]{8,})(['"`])/i,
        /const\s+(API_KEY|TOKEN|SECRET|PASSWORD|AUTH|ACCESS_TOKEN)\s*=\s*(['"`])([A-Za-z0-9_\-\.]{8,})(['"`])/i,
        /var\s+(API_KEY|TOKEN|SECRET|PASSWORD|AUTH|ACCESS_TOKEN)\s*=\s*(['"`])([A-Za-z0-9_\-\.]{8,})(['"`])/i,
      ];
      
      lines.forEach((line, lineNumber) => {
        for (const pattern of secretPatterns) {
          if (pattern.test(line)) {
            vulnerabilities.push({
              id: this.generateId(),
              severity: 'high',
              title: 'Potential Hardcoded Secret',
              description: 'A potential hardcoded API key, token, or password was found in the code.',
              location: {
                line: lineNumber + 1,
                snippet: line.trim(),
              },
              language: 'generic',
              remediation: 'Move secrets to environment variables or a secure configuration system.',
              cwe: 'CWE-798',
            });
            break;
          }
        }
      });
    }
    
    // Generic checker for common vulnerable patterns
    const vulnerablePatterns = [
      {
        regex: /eval\s*\(/i,
        title: 'Potential Code Injection',
        description: 'Use of eval() can lead to code injection if user input is included.',
        severity: 'high',
        cwe: 'CWE-95',
      },
      {
        regex: /(SELECT|INSERT|UPDATE|DELETE).*\+/i,
        title: 'Potential SQL Injection',
        description: 'String concatenation in SQL queries can lead to SQL Injection attacks.',
        severity: 'high',
        cwe: 'CWE-89',
      },
      {
        regex: /md5|sha1/i,
        title: 'Potentially Weak Cryptography',
        description: 'MD5 and SHA1 are cryptographically broken for security applications.',
        severity: 'medium',
        cwe: 'CWE-327',
      },
      {
        regex: /exec\s*\(|system\s*\(|popen\s*\(/i,
        title: 'Potential Command Injection',
        description: 'Command execution functions can lead to OS command injection if user input is included.',
        severity: 'high',
        cwe: 'CWE-78',
      },
    ];
    
    lines.forEach((line, lineNumber) => {
      for (const pattern of vulnerablePatterns) {
        if (pattern.regex.test(line)) {
          vulnerabilities.push({
            id: this.generateId(),
            severity: pattern.severity as any,
            title: pattern.title,
            description: pattern.description,
            location: {
              line: lineNumber + 1,
              snippet: line.trim(),
            },
            language: 'generic',
            cwe: pattern.cwe,
          });
        }
      }
    });
    
    return vulnerabilities;
  }
  
  /**
   * Generate a unique ID for vulnerabilities
   */
  private generateId(): string {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  }
}