"""
XYZ API Client
HTTP client for interacting with the XYZ Vulnerability API
"""

import requests
import json
import os
from typing import Dict, List, Optional, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration file path
CONFIG_DIR = os.path.expanduser("~/.xyz")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

class XYZAPIClient:
    """Client for XYZ Vulnerability API"""
    
    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        """
        Initialize the XYZ API client
        
        Args:
            api_key: API key for authentication (can also be set via XYZ_API_KEY env var)
            base_url: Base URL for the API (can also be set via XYZ_API_URL env var)
        """
        self.base_url = base_url or os.getenv('XYZ_API_URL', 'http://localhost:8000')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'xyz-cli/1.0.0'
        })
        
        # Load credentials from config file or fallback to API key
        self._load_credentials()
        
        if 'Authorization' not in self.session.headers:
            # Fallback to legacy API key if no token is loaded
            self.api_key = api_key or os.getenv('XYZ_API_KEY')
            if self.api_key:
                if not self.api_key.startswith('sk_xyz_'):
                    raise ValueError("Invalid API key format. Must start with 'sk_xyz_'.")
                self.session.headers['Authorization'] = f'Bearer {self.api_key}'
            else:
                # No credentials found at all
                pass # Don't raise error here, let commands handle it
    
    def _load_credentials(self):
        """Load credentials from config file"""
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                token = config.get('access_token')
                if token:
                    self.session.headers['Authorization'] = f'Bearer {token}'

    def _save_credentials(self, config: Dict):
        """Save credentials to config file"""
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        os.chmod(CONFIG_FILE, 0o600) # Secure permissions

    def login(self, email: str, password: str) -> Dict[str, Any]:
        """Login to get access token"""
        url = f"{self.base_url.rstrip('/')}/api/v1/auth/login"
        try:
            response = self.session.post(url, data={'username': email, 'password': password})
            response.raise_for_status()
            
            data = response.json()
            self._save_credentials(data)
            self.session.headers['Authorization'] = f"Bearer {data['access_token']}"
            return data
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise ValueError("Login failed: Incorrect email or password.")
            else:
                raise ValueError(f"Login failed: {e.response.text}")
        except Exception as e:
            raise ValueError(f"An error occurred during login: {e}")

    def logout(self):
        """Logout and clear credentials"""
        if os.path.exists(CONFIG_FILE):
            os.remove(CONFIG_FILE)
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']

    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """Get current user info from config file"""
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                return config.get('user_info')
        return None

    def _make_request(self, method: str, endpoint: str, params: Optional[Dict] = None,
                     data: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Make HTTP request to the API
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (without base URL)
            params: Query parameters
            data: Request body data
            
        Returns:
            Response data as dictionary
            
        Raises:
            requests.exceptions.RequestException: For HTTP errors
            ValueError: For invalid responses
        """
        url = f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=data
            )
            response.raise_for_status()
            
            if response.status_code == 204:  # No content
                return {}
            
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            # Try to extract error message from response
            try:
                error_data = response.json()
                error_msg = error_data.get('detail', error_data.get('error', str(e)))
            except:
                error_msg = str(e)
            
            if response.status_code == 401:
                raise ValueError(f"Authentication failed: {error_msg}")
            elif response.status_code == 403:
                raise ValueError(f"Permission denied: {error_msg}")
            elif response.status_code == 429:
                raise ValueError(f"Rate limit exceeded: {error_msg}")
            else:
                raise ValueError(f"API request failed: {error_msg}")
                
        except requests.exceptions.ConnectionError:
            raise ValueError(f"Failed to connect to API at {self.base_url}. Is the API server running?")
        except requests.exceptions.Timeout:
            raise ValueError("API request timed out")
        except requests.exceptions.RequestException as e:
            raise ValueError(f"Request failed: {str(e)}")
    
    def health_check(self) -> Dict[str, Any]:
        """Check API health status"""
        return self._make_request('GET', '/health')
    
    def get_api_info(self) -> Dict[str, Any]:
        """Get API information and capabilities"""
        return self._make_request('GET', '/api/v1/info')
    
    # Vulnerability Search Methods
    def search_vulnerability_by_id(self, vuln_id: str, include_exploits: bool = False) -> Dict[str, Any]:
        """
        Search for a vulnerability by ID (CVE, GHSA, OSV, etc.)
        
        Args:
            vuln_id: Vulnerability ID
            include_exploits: Include exploit information
            
        Returns:
            Vulnerability data
        """
        params = {'include_exploits': include_exploits}
        return self._make_request('GET', f'/api/v1/vulnerabilities/{vuln_id}', params=params)
    
    def search_vulnerabilities(self, query: str, ecosystem: Optional[str] = None, 
                             severity: Optional[str] = None, limit: int = 50, 
                             offset: int = 0, include_exploits: bool = False) -> Dict[str, Any]:
        """
        Search vulnerabilities with flexible criteria
        
        Args:
            query: Search query
            ecosystem: Ecosystem filter
            severity: Severity filter
            limit: Maximum results
            offset: Pagination offset
            include_exploits: Include exploit information
            
        Returns:
            Search results
        """
        params = {
            'q': query,
            'limit': limit,
            'offset': offset,
            'include_exploits': include_exploits
        }
        if ecosystem:
            params['ecosystem'] = ecosystem
        if severity:
            params['severity'] = severity
        
        return self._make_request('GET', '/api/v1/vulnerabilities/search', params=params)
    
    def get_recent_vulnerabilities(self, days: int = 7, limit: int = 50, 
                                 include_exploits: bool = False) -> Dict[str, Any]:
        """
        Get recent vulnerabilities
        
        Args:
            days: Number of days to look back
            limit: Maximum results
            include_exploits: Include exploit information
            
        Returns:
            Recent vulnerabilities
        """
        params = {
            'days': days,
            'limit': limit,
            'include_exploits': include_exploits
        }
        return self._make_request('GET', '/api/v1/vulnerabilities/recent', params=params)
    
    # Package Search Methods
    def search_package_vulnerabilities(self, package_name: str, ecosystem: Optional[str] = None,
                                     version: Optional[str] = None, severity: Optional[str] = None,
                                     limit: int = 50, offset: int = 0,
                                     include_exploits: bool = False, machine_name: str = None,
                                     os_type: str = None, computer_name: str = None,
                                     scan_command: str = None) -> Dict[str, Any]:
        """
        Search for vulnerabilities affecting a specific package
        
        Args:
            package_name: Package name
            package_name: Package name
            ecosystem: Ecosystem filter
            version: Package version
            severity: Severity filter
            limit: Maximum results
            offset: Pagination offset
            include_exploits: Include exploit information
            machine_name: Name of the machine being scanned
            os_type: OS type of the machine being scanned
            computer_name: Computer name of the machine being scanned
            scan_command: The command that was run to initiate the scan
            
        Returns:
            Package vulnerability data
        """
        params = {
            'q': package_name,
            'limit': limit,
            'offset': offset,
            'include_exploits': include_exploits,
            'machine_name': machine_name,
            'os_type': os_type,
            'computer_name': computer_name,
            'scan_command': scan_command
        }
        if ecosystem:
            params['ecosystem'] = ecosystem
        if version:
            params['version'] = version
        if severity:
            params['severity'] = severity
        
        return self._make_request('GET', '/api/v1/packages/search', params=params)
    
    def get_package_vulnerabilities(self, package_name: str, ecosystem: Optional[str] = None,
                                  include_exploits: bool = False) -> Dict[str, Any]:
        """
        Get all vulnerabilities for a specific package
        
        Args:
            package_name: Package name
            ecosystem: Ecosystem filter
            include_exploits: Include exploit information
            
        Returns:
            Package vulnerability data
        """
        params = {'include_exploits': include_exploits}
        if ecosystem:
            params['ecosystem'] = ecosystem
        
        return self._make_request('GET', f'/api/v1/packages/{package_name}', params=params)
    
    # System Scanning Methods
    def scan_python_packages(self, include_exploits: bool = False, machine_name: str = None, os_type: str = None, computer_name: str = None) -> Dict[str, Any]:
        """
        Scan installed Python packages for vulnerabilities
        
        Args:
            include_exploits: Include exploit information
            machine_name: Name of the machine being scanned
            os_type: OS type of the machine being scanned
            computer_name: Computer name of the machine being scanned
            
        Returns:
            Scan results
        """
        params = {'include_exploits': include_exploits, 'machine_name': machine_name, 'os_type': os_type, 'computer_name': computer_name}
        return self._make_request('POST', '/api/v1/system/scan/python', params=params)
    
    def scan_npm_packages(self, include_exploits: bool = False, machine_name: str = None, os_type: str = None, computer_name: str = None) -> Dict[str, Any]:
        """
        Scan npm packages for vulnerabilities
        
        Args:
            include_exploits: Include exploit information
            machine_name: Name of the machine being scanned
            os_type: OS type of the machine being scanned
            computer_name: Computer name of the machine being scanned
            
        Returns:
            Scan results
        """
        params = {'include_exploits': include_exploits, 'machine_name': machine_name, 'os_type': os_type, 'computer_name': computer_name}
        return self._make_request('POST', '/api/v1/system/scan/npm', params=params)

    def scan_java_packages(self, include_exploits: bool = False, machine_name: str = None, os_type: str = None, computer_name: str = None) -> Dict[str, Any]:
        """Scan installed Java packages for vulnerabilities"""
        params = {'include_exploits': include_exploits, 'machine_name': machine_name, 'os_type': os_type, 'computer_name': computer_name}
        return self._make_request('POST', '/api/v1/system/scan/java', params=params)

    def scan_go_packages(self, include_exploits: bool = False, machine_name: str = None, os_type: str = None, computer_name: str = None) -> Dict[str, Any]:
        """Scan installed Go packages for vulnerabilities"""
        params = {'include_exploits': include_exploits, 'machine_name': machine_name, 'os_type': os_type, 'computer_name': computer_name}
        return self._make_request('POST', '/api/v1/system/scan/go', params=params)

    def scan_php_packages(self, include_exploits: bool = False, machine_name: str = None, os_type: str = None, computer_name: str = None) -> Dict[str, Any]:
        """Scan installed PHP packages for vulnerabilities"""
        params = {'include_exploits': include_exploits, 'machine_name': machine_name, 'os_type': os_type, 'computer_name': computer_name}
        return self._make_request('POST', '/api/v1/system/scan/php', params=params)

    def scan_microsoft_packages(self, include_exploits: bool = False, machine_name: str = None, os_type: str = None, computer_name: str = None) -> Dict[str, Any]:
        """Scan installed Microsoft packages for vulnerabilities"""
        params = {'include_exploits': include_exploits, 'machine_name': machine_name, 'os_type': os_type, 'computer_name': computer_name}
        return self._make_request('POST', '/api/v1/system/scan/microsoft', params=params)

    def list_packages(self, package_types: List[str], machine_name: str = None, os_type: str = None, computer_name: str = None) -> Dict[str, Any]:
        """List installed packages"""
        params = {'package_types': package_types, 'machine_name': machine_name, 'os_type': os_type, 'computer_name': computer_name}
        return self._make_request('GET', '/api/v1/system/packages', params=params)
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information and scanning capabilities"""
        return self._make_request('GET', '/api/v1/system/info')

    def send_go_audit(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send Go audit data to the backend"""
        return self._make_request('POST', '/api/v1/scans', data={
            "scan_type": "go_audit",
            "scan_command": "xyz audit go",
            "scan_results": audit_data.get("scan_results"),
            "machine_name": audit_data.get("machine_name"),
            "os_type": audit_data.get("os_type"),
            "computer_name": audit_data.get("computer_name")
        })
    
    def send_python_audit(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send Python audit data to the backend"""
        return self._make_request('POST', '/api/v1/scans', data={
            "scan_type": "python",
            "scan_command": "xyz audit python",
            "scan_results": audit_data.get("scan_results"),
            "machine_name": audit_data.get("machine_name"),
            "os_type": audit_data.get("os_type"),
            "computer_name": audit_data.get("computer_name")
        })

    # Statistics Methods
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        return self._make_request('GET', '/api/v1/vulnerabilities/stats')
    
    def get_ecosystem_stats(self) -> Dict[str, Any]:
        """Get ecosystem statistics"""
        return self._make_request('GET', '/api/v1/packages/ecosystems/stats')
