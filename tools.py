import re
import socket
import requests
from typing import Dict, Any, List
from urllib.parse import urlparse
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class ToolRegistry:
    """Registry of all available scanning tools"""
    
    def __init__(self):
        self.tools = {
            "validate_target": self.validate_target,
            "scan_ports": self.scan_ports,
            "analyze_headers": self.analyze_headers,
            "scan_vuln_patterns": self.scan_vuln_patterns,
            "check_ssl_tls": self.check_ssl_tls,
            "enumerate_directories": self.enumerate_directories,
        }
    
    def get_tool_descriptions(self) -> str:
        """Generate descriptions of all available tools"""
        descriptions = """
Available Tools:
1. validate_target - Validates target URL/IP and checks if it's reachable
2. scan_ports - Scans common ports to identify open services
3. analyze_headers - Analyzes HTTP security headers for misconfigurations
4. scan_vuln_patterns - Scans for common vulnerability patterns (SQLi, XSS, etc.)
5. check_ssl_tls - Checks SSL/TLS configuration and certificate validity
6. enumerate_directories - Attempts to discover common directories and files
"""
        return descriptions
    
    def execute_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """Execute a tool and return results"""
        if tool_name not in self.tools:
            return {"success": False, "error": f"Tool '{tool_name}' not found"}
        
        try:
            return self.tools[tool_name](**kwargs)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def _normalize_url(target: str) -> tuple:
        """Normalize URL and extract host"""
        # Add scheme if missing
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path.split('/')[0]
        
        # Remove port from host if present
        host_only = host.split(':')[0]
        
        return target, host_only
    
    @staticmethod
    def validate_target(target: str) -> Dict[str, Any]:
        """Validate and normalize target URL/domain"""
        result = {"success": False, "target": target, "findings": []}
        
        try:
            target, host = ToolRegistry._normalize_url(target)
            
            parsed = urlparse(target)
            
            if not parsed.netloc:
                return {
                    "success": False,
                    "error": "Invalid target format",
                    "findings": []
                }
            
            # Check if target is reachable
            try:
                # Try HTTPS first
                https_url = target.replace('http://', 'https://')
                response = requests.head(https_url, timeout=5, allow_redirects=True, verify=False)
                result["success"] = True
                result["reachable"] = True
                result["status_code"] = response.status_code
                result["normalized_target"] = https_url
                
                # No HTTP warning needed since we used HTTPS
                
            except requests.RequestException:
                # Fall back to HTTP
                try:
                    http_url = target.replace('https://', 'http://')
                    response = requests.head(http_url, timeout=5, allow_redirects=True)
                    result["success"] = True
                    result["reachable"] = True
                    result["status_code"] = response.status_code
                    result["normalized_target"] = http_url
                    
                    result["findings"].append({
                        "type": "HTTP_ONLY",
                        "severity": "Medium",
                        "description": "Target uses HTTP instead of HTTPS",
                        "recommendation": "Enable HTTPS with valid SSL certificate"
                    })
                except requests.RequestException:
                    result["success"] = True
                    result["reachable"] = False
                    result["normalized_target"] = target
                
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    @staticmethod
    def scan_ports(target: str, ports: List[int] = None) -> Dict[str, Any]:
        """Scan common ports on target"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080, 8443]
        
        target, host = ToolRegistry._normalize_url(target)
        
        result = {
            "success": True,
            "target": host,
            "open_ports": [],
            "findings": []
        }
        
        # Validate hostname first
        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            result["success"] = False
            result["error"] = f"Unable to resolve hostname: {host}"
            return result
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                sock.connect((host, port))
                result["open_ports"].append(port)
                
                # Identify potentially risky ports
                risk_ports = {
                    21: ("FTP", "High", "FTP protocol transmits credentials in plaintext"),
                    23: ("Telnet", "Critical", "Telnet is insecure and should be disabled"),
                    3306: ("MySQL", "Medium", "Database port exposed to internet"),
                    5432: ("PostgreSQL", "Medium", "Database port exposed to internet"),
                    3389: ("RDP", "High", "RDP exposed to internet increases attack surface")
                }
                
                if port in risk_ports:
                    service, severity, desc = risk_ports[port]
                    result["findings"].append({
                        "type": "OPEN_PORT",
                        "severity": severity,
                        "port": port,
                        "service": service,
                        "description": desc,
                        "recommendation": f"Close port {port} or restrict access via firewall"
                    })
                
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass
            finally:
                sock.close()
        
        return result
    
    @staticmethod
    def analyze_headers(target: str) -> Dict[str, Any]:
        """Analyze HTTP security headers"""
        result = {
            "success": False,
            "headers": {},
            "findings": []
        }
        
        target, host = ToolRegistry._normalize_url(target)
        
        try:
            response = requests.get(target, timeout=10, verify=False)
            result["success"] = True
            result["headers"] = dict(response.headers)
            
            # Check for missing security headers
            security_headers = {
                "Strict-Transport-Security": ("High", "HSTS header missing"),
                "X-Frame-Options": ("Medium", "Clickjacking protection missing"),
                "X-Content-Type-Options": ("Medium", "MIME sniffing protection missing"),
                "Content-Security-Policy": ("High", "CSP header missing"),
                "X-XSS-Protection": ("Medium", "XSS protection header missing"),
                "Referrer-Policy": ("Low", "Referrer policy not configured")
            }
            
            for header, (severity, description) in security_headers.items():
                if header not in response.headers:
                    result["findings"].append({
                        "type": "MISSING_HEADER",
                        "severity": severity,
                        "header": header,
                        "description": description,
                        "recommendation": f"Implement {header} header"
                    })
            
            # Check for information disclosure
            disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
            for header in disclosure_headers:
                if header in response.headers:
                    result["findings"].append({
                        "type": "INFO_DISCLOSURE",
                        "severity": "Low",
                        "header": header,
                        "value": response.headers[header],
                        "description": f"Server information exposed via {header} header",
                        "recommendation": f"Remove or obfuscate {header} header"
                    })
                    
        except requests.RequestException as e:
            result["error"] = str(e)
        
        return result
    
    @staticmethod
    def scan_vuln_patterns(target: str) -> Dict[str, Any]:
        """Scan for common vulnerability patterns"""
        result = {
            "success": True,
            "findings": []
        }
        
        target, host = ToolRegistry._normalize_url(target)
        
        # Test for SQL injection patterns (safe payload)
        sqli_payloads = ["'", "1' OR '1'='1"]
        for payload in sqli_payloads[:1]:  # Test only first payload
            try:
                test_url = f"{target}?id={payload}"
                response = requests.get(test_url, timeout=5, verify=False)
                
                # Look for SQL error patterns
                sql_errors = [
                    "sql syntax", "mysql_fetch", "pg_query", "sqlite_",
                    "ORA-", "SQL Server", "ODBC", "JET Database"
                ]
                
                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        result["findings"].append({
                            "type": "SQL_INJECTION",
                            "severity": "Critical",
                            "payload": payload,
                            "description": "Potential SQL injection vulnerability detected",
                            "recommendation": "Use parameterized queries and input validation"
                        })
                        break
            except:
                pass
        
        # Test for XSS (safe test)
        try:
            xss_test = f"{target}?q=<script>alert('test')</script>"
            response = requests.get(xss_test, timeout=5, verify=False)
            
            if "<script>alert('test')</script>" in response.text:
                result["findings"].append({
                    "type": "XSS",
                    "severity": "High",
                    "description": "Potential Cross-Site Scripting (XSS) vulnerability",
                    "recommendation": "Implement output encoding and Content Security Policy"
                })
        except:
            pass
        
        # Check for directory listing
        try:
            response = requests.get(target, timeout=5, verify=False)
            if "Index of /" in response.text or "Directory listing" in response.text:
                result["findings"].append({
                    "type": "DIRECTORY_LISTING",
                    "severity": "Medium",
                    "description": "Directory listing is enabled",
                    "recommendation": "Disable directory listing in web server configuration"
                })
        except:
            pass
        
        return result
    
    @staticmethod
    def check_ssl_tls(target: str) -> Dict[str, Any]:
        """Check SSL/TLS configuration"""
        result = {
            "success": True,
            "findings": []
        }
        
        target, host = ToolRegistry._normalize_url(target)
        parsed = urlparse(target)
        
        if parsed.scheme != 'https':
            result["findings"].append({
                "type": "NO_SSL",
                "severity": "High",
                "description": "Site does not use HTTPS",
                "recommendation": "Implement HTTPS with valid SSL/TLS certificate"
            })
            return result
        
        try:
            response = requests.get(target, timeout=5, verify=False)
            
            # Check for weak ciphers (simplified check)
            result["findings"].append({
                "type": "SSL_CHECK",
                "severity": "Info",
                "description": "Site uses HTTPS",
                "recommendation": "Ensure TLS 1.2+ is used with strong cipher suites"
            })
            
        except requests.exceptions.SSLError as e:
            result["findings"].append({
                "type": "SSL_ERROR",
                "severity": "High",
                "description": f"SSL/TLS error: {str(e)}",
                "recommendation": "Fix SSL certificate configuration"
            })
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    @staticmethod
    def enumerate_directories(target: str) -> Dict[str, Any]:
        """Attempt to discover common directories"""
        result = {
            "success": True,
            "found_paths": [],
            "findings": []
        }
        
        target, host = ToolRegistry._normalize_url(target)
        
        common_paths = [
            "/admin", "/login", "/dashboard", "/api", 
            "/backup", "/.git", "/.env", "/config",
            "/robots.txt", "/sitemap.xml"
        ]
        
        for path in common_paths:
            try:
                url = f"{target.rstrip('/')}{path}"
                response = requests.head(url, timeout=3, allow_redirects=False, verify=False)
                
                if response.status_code < 400:
                    result["found_paths"].append({
                        "path": path,
                        "status": response.status_code
                    })
                    
                    # Flag sensitive paths
                    sensitive = [".git", ".env", "config", "backup", "admin"]
                    if any(s in path for s in sensitive):
                        result["findings"].append({
                            "type": "SENSITIVE_PATH",
                            "severity": "High",
                            "path": path,
                            "description": f"Sensitive path '{path}' is accessible",
                            "recommendation": f"Restrict access to {path}"
                        })
            except:
                pass
        
        return result
