#!/usr/bin/env python3
"""
SD-WAN Chaos Monkey - Complete Version with Mixed Chaos Support

A comprehensive chaos engineering tool for SD-WAN networks that tests resilience by:
1. WAN Interface Chaos - Systematically fails WAN interfaces to test failover
2. VRRP Chaos - Tests VRRP failover by bringing down interfaces on MASTER
3. Mixed Chaos (ALL) - Randomly selects between WAN and VRRP chaos each cycle

Usage:
    python3 sdwan_chaos_monkey.py --token YOUR_API_TOKEN --chaos-type wan-interface [options]
    python3 sdwan_chaos_monkey.py --token YOUR_API_TOKEN --chaos-type vrrp [options]
    python3 sdwan_chaos_monkey.py --token YOUR_API_TOKEN --chaos-type all [options]
"""

import argparse
import json
import logging
import time
import sys
import random
from datetime import datetime
from typing import Dict, Optional, Tuple, List, Union
from dataclasses import dataclass
from enum import Enum
import yaml
import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AuthMethod(Enum):
    """Authentication method enumeration"""
    HEADER_TOKEN = "header_token"
    QUERY_TOKEN = "query_token"
    BASIC_AUTH = "basic_auth"


class ChaosType(Enum):
    """Chaos engineering target types"""
    WAN_INTERFACE = "wan-interface"
    VRRP = "vrrp"
    ALL = "all"


@dataclass
class WANInterface:
    """WAN interface data structure"""
    nepk: str
    interface_name: str
    label_name: str
    ip_address: str = ""
    
    @property
    def display_name(self) -> str:
        return f"{self.interface_name} ({self.label_name})" if self.label_name else self.interface_name


@dataclass
class VRRPInstance:
    """VRRP instance data structure"""
    nepk: str
    appliance_name: str
    interface_name: str
    vrid: int
    current_priority: int
    backup_priority: int
    original_priority: int
    state: str = "UNKNOWN"
    
    @property
    def display_name(self) -> str:
        return f"VRRP {self.vrid} on {self.interface_name}"


@dataclass
class MixedChaosTarget:
    """Mixed chaos target that contains both WAN and VRRP targets"""
    wan_targets: List[WANInterface] = None
    vrrp_targets: List[VRRPInstance] = None
    
    def __post_init__(self):
        if self.wan_targets is None:
            self.wan_targets = []
        if self.vrrp_targets is None:
            self.vrrp_targets = []
    
    @property
    def total_targets(self) -> int:
        return len(self.wan_targets) + len(self.vrrp_targets)


@dataclass
class TestResult:
    """Test result data structure"""
    cycle: int
    target_name: str
    appliance_name: str
    chaos_type: ChaosType
    success: bool
    timestamp: datetime
    duration_seconds: float = 0.0
    details: Dict = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


@dataclass
class ApplianceInfo:
    """Appliance information data structure"""
    nepk: str
    name: str
    site: str = "Unknown"
    model: str = "Unknown"
    deployment: Optional[Dict] = None
    wan_interfaces: List[WANInterface] = None
    vrrp_instances: List[VRRPInstance] = None
    
    def __post_init__(self):
        if self.wan_interfaces is None:
            self.wan_interfaces = []
        if self.vrrp_instances is None:
            self.vrrp_instances = []


class SDWANChaosMonkey:
    """SD-WAN Chaos Monkey - Unified chaos engineering platform with mixed chaos support"""
    
    # Constants
    DEFAULT_TIMEOUT = 30
    DEFAULT_RETRY_COUNT = 3
    DEFAULT_BACKOFF_FACTOR = 0.3
    LINK_LOCAL_PREFIX = "169.254."
    
    def __init__(self, base_url: str, chaos_type: ChaosType, auth_token: str = None,
                 username: str = None, password: str = None, duration_min: int = 30,
                 duration_max: int = None, verify_ssl: bool = True, use_query_auth: bool = False,
                 randomize: bool = True, random_seed: Optional[int] = None,
                 node_filter: Optional[Dict] = None):
        """
        Initialize the SD-WAN Chaos Monkey

        Args:
            base_url: Base URL of the orchestrator
            chaos_type: Type of chaos to introduce (wan-interface, vrrp, or all)
            auth_token: API token for authentication (preferred)
            username: Username for basic auth (fallback)
            password: Password for basic auth (fallback)
            duration_min: Minimum chaos duration in seconds (default: 30)
            duration_max: Maximum chaos duration in seconds (enables random duration)
            verify_ssl: Whether to verify SSL certificates
            use_query_auth: Use apiKey query parameter instead of X-Auth-Token header
            randomize: Whether to randomize target selection (default: True)
            random_seed: Seed for random number generator (for reproducible testing)
            node_filter: Dict with 'include' and/or 'exclude' lists of hostnames
        """
        self.base_url = base_url.rstrip('/')
        self.chaos_type = chaos_type
        self.duration_min = duration_min
        self.duration_max = duration_max
        self.verify_ssl = verify_ssl
        self.auth_token = auth_token
        self.randomize = randomize
        self.node_filter = node_filter or {}

        # Initialize logger first (before anything that might log)
        self.logger = logging.getLogger(__name__)

        # Setup randomization
        if random_seed is not None:
            random.seed(random_seed)
            self.logger.info(f"Using random seed: {random_seed} (for reproducible testing)")
        elif randomize:
            # Use current timestamp as seed for true randomness
            seed = int(time.time())
            random.seed(seed)
            self.logger.info(f"Using random seed: {seed}")

        # Setup authentication method
        self.auth_method = self._determine_auth_method(auth_token, username, password, use_query_auth)
        self.username = username
        self.password = password

        # Setup session with retry strategy
        self.session = self._create_session()

        self.logger.info(f"Base URL: {self.base_url}")
        self.logger.info(f"Chaos Type: {self.chaos_type.value}")
        self.logger.info(f"Authentication method: {self.auth_method.value}")
        self.logger.info(f"Randomization: {'Enabled' if self.randomize else 'Disabled'}")
        if self.duration_max and self.duration_max > self.duration_min:
            self.logger.info(f"Chaos Duration: {self.duration_min}-{self.duration_max} seconds (random)")
        else:
            self.logger.info(f"Chaos Duration: {self.duration_min} seconds (fixed)")
        if self.node_filter:
            if self.node_filter.get('include'):
                self.logger.info(f"Node filter (include): {self.node_filter['include']}")
            if self.node_filter.get('exclude'):
                self.logger.info(f"Node filter (exclude): {self.node_filter['exclude']}")

        # Test connectivity
        self._test_connectivity()

        # Storage for discovered data
        self.appliances: Dict[str, ApplianceInfo] = {}
        self.chaos_targets: List = []  # Will contain WANInterface, VRRPInstance, or both for ALL type
        self.mixed_targets: Optional[MixedChaosTarget] = None  # For 'all' chaos type
        self.current_test_index = 0
    
    def _determine_auth_method(self, auth_token: str, username: str, password: str, 
                              use_query_auth: bool) -> AuthMethod:
        """Determine the authentication method to use"""
        if auth_token:
            return AuthMethod.QUERY_TOKEN if use_query_auth else AuthMethod.HEADER_TOKEN
        elif username and password:
            return AuthMethod.BASIC_AUTH
        else:
            self.logger.warning("No authentication provided - requests may fail")
            return AuthMethod.BASIC_AUTH
    
    def _get_chaos_duration(self) -> int:
        """Get chaos duration, randomized if max is set"""
        if self.duration_max and self.duration_max > self.duration_min:
            duration = random.randint(self.duration_min, self.duration_max)
            self.logger.debug(f"Random chaos duration selected: {duration}s "
                            f"(range: {self.duration_min}-{self.duration_max}s)")
            return duration
        return self.duration_min

    def _filter_appliances(self, appliances: Dict[str, ApplianceInfo]) -> Dict[str, ApplianceInfo]:
        """Filter appliances based on node include/exclude lists"""
        if not self.node_filter:
            return appliances

        include_list = self.node_filter.get('include')
        exclude_list = self.node_filter.get('exclude')

        # Normalize to lowercase for case-insensitive matching
        if include_list:
            include_set = {h.lower() for h in include_list}
        if exclude_list:
            exclude_set = {h.lower() for h in exclude_list}

        filtered = {}
        for nepk, appliance in appliances.items():
            hostname = appliance.name.lower()

            if include_list:
                if hostname not in include_set:
                    self.logger.info(f"   Skipping {appliance.name} (not in include list)")
                    continue
            if exclude_list:
                if hostname in exclude_set:
                    self.logger.info(f"   Skipping {appliance.name} (in exclude list)")
                    continue

            filtered[nepk] = appliance

        skipped = len(appliances) - len(filtered)
        if skipped:
            self.logger.info(f"Node filter applied: {len(filtered)} included, {skipped} excluded")

        return filtered

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry strategy and proper configuration"""
        session = requests.Session()
        
        # Setup retry strategy (compatible with both old and new urllib3)
        retry_kwargs = {
            'total': self.DEFAULT_RETRY_COUNT,
            'status_forcelist': [429, 500, 502, 503, 504],
            'backoff_factor': self.DEFAULT_BACKOFF_FACTOR
        }

        # Handle urllib3 version differences (method_whitelist deprecated in 1.26, removed in 2.0)
        try:
            retry_strategy = Retry(allowed_methods=["HEAD", "GET", "OPTIONS", "POST"], **retry_kwargs)
        except TypeError:
            retry_strategy = Retry(method_whitelist=["HEAD", "GET", "OPTIONS", "POST"], **retry_kwargs)
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Setup headers
        session.headers.update({'Content-Type': 'application/json'})
        
        # Setup authentication
        if self.auth_method == AuthMethod.HEADER_TOKEN and self.auth_token:
            session.headers['X-Auth-Token'] = self.auth_token
        elif self.auth_method == AuthMethod.BASIC_AUTH and self.username and self.password:
            session.auth = HTTPBasicAuth(self.username, self.password)
        
        return session
    
    def _test_connectivity(self):
        """Test basic connectivity to the orchestrator"""
        self.logger.info("Testing connectivity to orchestrator...")
        try:
            response = self._make_request('GET', f"{self.base_url}/gms/rest/appliance", timeout=10)
            
            if response is not None:
                self.logger.info("Connectivity test: SUCCESS")
            else:
                self.logger.error("Connectivity test: FAILED")
                
        except requests.exceptions.RequestException as e:
            self._handle_connection_error(e)
    
    def _handle_connection_error(self, error: Exception):
        """Handle different types of connection errors with specific guidance"""
        if isinstance(error, requests.exceptions.ConnectTimeout):
            self.logger.error("Connection timeout! Check the URL and network connectivity.")
        elif isinstance(error, requests.exceptions.ConnectionError):
            self.logger.error("Connection error! Check the URL and network connectivity.")
        elif isinstance(error, requests.exceptions.SSLError):
            self.logger.error("SSL error! Try using --no-verify-ssl flag.")
        else:
            self.logger.error(f"Connectivity test failed: {error}")
    
    def _build_url_with_auth(self, url: str) -> str:
        """Build URL with query parameter authentication if needed"""
        if self.auth_method == AuthMethod.QUERY_TOKEN and self.auth_token:
            separator = '&' if '?' in url else '?'
            return f"{url}{separator}apiKey={self.auth_token}"
        return url
    
    def _make_request(self, method: str, url: str, data: Dict = None, 
                     timeout: int = None) -> Optional[Union[Dict, List]]:
        """Make HTTP request with proper error handling and response parsing"""
        if timeout is None:
            timeout = self.DEFAULT_TIMEOUT
        
        url = self._build_url_with_auth(url)
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, verify=self.verify_ssl, timeout=timeout)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, verify=self.verify_ssl, timeout=timeout)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return self._parse_response(response)
            
        except requests.exceptions.HTTPError as e:
            self._log_http_error(e)
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {e}")
        
        return None
    
    def _parse_response(self, response: requests.Response) -> Optional[Union[Dict, List]]:
        """Parse HTTP response with proper error handling"""
        if not response.text:
            return {}
        
        try:
            return response.json()
        except json.JSONDecodeError:
            self.logger.warning(f"Response is not valid JSON: {response.text[:200]}...")
            return {'raw_response': response.text}
    
    def _log_http_error(self, error: requests.exceptions.HTTPError):
        """Log HTTP errors with appropriate detail level"""
        if error.response is not None:
            status_code = error.response.status_code
            self.logger.error(f"HTTP {status_code} error")
            
            if status_code == 401:
                self.logger.error("Authentication failed! Check your token/credentials.")
            elif status_code == 403:
                self.logger.error("Access denied! Check your permissions.")
            elif status_code >= 500:
                self.logger.error("Server error - the orchestrator may be experiencing issues.")
            
            if error.response.text:
                self.logger.debug(f"Response body: {error.response.text[:500]}")
    
    def get_all_appliances(self) -> Dict[str, ApplianceInfo]:
        """Get all appliances and return as ApplianceInfo objects"""
        self.logger.info("Discovering appliances...")
        
        result = self._make_request('GET', f"{self.base_url}/gms/rest/appliance")
        if not result:
            self.logger.error("Failed to retrieve appliances")
            return {}
        
        appliances = {}
        appliance_list = self._extract_appliance_list(result)
        
        for appliance_data in appliance_list:
            nepk = appliance_data.get('nePk')
            if not nepk:
                continue
            
            appliance_info = ApplianceInfo(
                nepk=str(nepk),
                name=appliance_data.get('hostName', f"Appliance-{nepk}"),
                site=appliance_data.get('site', 'Unknown'),
                model=appliance_data.get('model', 'Unknown')
            )
            
            appliances[str(nepk)] = appliance_info
            self.logger.info(f"   Found: {appliance_info.name} (NEPK: {nepk}, Site: {appliance_info.site})")
        
        self.logger.info(f"Total appliances discovered: {len(appliances)}")

        # Apply node filter
        appliances = self._filter_appliances(appliances)

        return appliances

    def _extract_appliance_list(self, result: Union[Dict, List]) -> List[Dict]:
        """Extract appliance list from API response with various formats"""
        if isinstance(result, list):
            return result
        
        if isinstance(result, dict):
            for key in ['appliances', 'nodes', 'data', 'items']:
                if key in result and isinstance(result[key], list):
                    return result[key]
            
            if 'nePk' in result:
                return [result]
        
        return []
    
    def get_deployment_details(self, nepk: str) -> Optional[Dict]:
        """Get deployment details for a specific appliance"""
        self.logger.debug(f"Getting deployment details for appliance {nepk}...")
        
        url = f"{self.base_url}/gms/rest/deployment?nePk={nepk}"
        result = self._make_request('GET', url)
        
        if result:
            self.logger.debug(f"Successfully retrieved deployment details for {nepk}")
            return result
        
        self.logger.warning(f"Failed to retrieve deployment details for {nepk}")
        return None
    
    # WAN Interface Methods
    def extract_wan_interfaces(self, appliance: ApplianceInfo) -> List[WANInterface]:
        """Extract WAN interfaces from appliance deployment details"""
        if not appliance.deployment:
            self.logger.warning(f"No deployment data for appliance {appliance.nepk}")
            return []
        
        self.logger.debug(f"Extracting WAN interfaces for {appliance.name}...")
        wan_interfaces = []
        
        wan_labels = self._get_wan_labels_mapping(appliance.deployment)
        
        mode_ifs = appliance.deployment.get('modeIfs', [])
        for mode_if in mode_ifs:
            wan_interfaces.extend(
                self._process_interface_ips(mode_if, wan_labels, appliance.nepk)
            )
        
        if not wan_interfaces:
            self.logger.warning(f"No WAN interfaces found for appliance {appliance.name}")
        
        return wan_interfaces
    
    def _get_wan_labels_mapping(self, deployment: Dict) -> Dict[str, str]:
        """Extract WAN label mappings from deployment configuration"""
        sys_config = deployment.get('sysConfig', {})
        if_labels = sys_config.get('ifLabels', {})
        wan_labels = {}
        
        for label in if_labels.get('wan', []):
            label_id = str(label.get('id', ''))
            label_name = label.get('name', '')
            if label_id and label_name:
                wan_labels[label_id] = label_name
        
        return wan_labels
    
    def _process_interface_ips(self, mode_if: Dict, wan_labels: Dict[str, str], 
                              nepk: str) -> List[WANInterface]:
        """Process IP configurations for a single interface"""
        interfaces = []
        if_name = mode_if.get('ifName', '')
        appliance_ips = mode_if.get('applianceIPs', [])
        
        for ip_config in appliance_ips:
            if not ip_config.get('wanSide', False):
                continue
            
            ip_address = ip_config.get('ip', '')
            
            if ip_address.startswith(self.LINK_LOCAL_PREFIX):
                self.logger.debug(f"   Skipping link-local IP {ip_address} on {if_name}")
                continue
            
            full_if_name = if_name
            vlan = ip_config.get('vlan')
            if vlan:
                full_if_name = f"{if_name}.{vlan}"
            
            label_id = str(ip_config.get('label', ''))
            label_name = wan_labels.get(label_id, f"WAN-{label_id}" if label_id else "WAN")
            
            wan_interface = WANInterface(
                nepk=nepk,
                interface_name=full_if_name,
                label_name=label_name,
                ip_address=ip_address
            )
            
            interfaces.append(wan_interface)
            self.logger.info(f"   Found WAN interface: {wan_interface.display_name} - IP: {ip_address}")
        
        return interfaces
    
    # VRRP Methods
    def get_vrrp_instances(self, nepk: str) -> List[Dict]:
        """Get VRRP instances for a specific appliance using the VRRP API"""
        self.logger.debug(f"Getting VRRP instances for appliance {nepk}...")
        
        url = f"{self.base_url}/gms/rest/appliance/rest?nePk={nepk}&url=vrrp&cached=false"
        result = self._make_request('GET', url)
        
        if result and isinstance(result, list):
            self.logger.debug(f"Successfully retrieved {len(result)} VRRP instances for {nepk}")
            return result
        elif result:
            self.logger.debug(f"Retrieved VRRP data for {nepk}, but format is unexpected")
            return [result] if isinstance(result, dict) else []
        
        self.logger.warning(f"Failed to retrieve VRRP instances for {nepk}")
        return []
    
    def extract_vrrp_instances(self, appliance: ApplianceInfo) -> List[VRRPInstance]:
        """Extract VRRP instances from appliance using VRRP status API"""
        self.logger.debug(f"Extracting VRRP instances for {appliance.name}...")
        vrrp_instances = []
        
        # Get VRRP status from the API
        vrrp_data = self.get_vrrp_instances(appliance.nepk)
        
        for vrrp_config in vrrp_data:
            group_id = vrrp_config.get('groupId')
            interface_name = vrrp_config.get('interface', '')
            priority = vrrp_config.get('priority', 100)
            current_mode = vrrp_config.get('mode', 'unknown')
            vip_address = vrrp_config.get('vipaddr', '')
            enable_status = vrrp_config.get('enable', 'Down')
            
            if group_id is not None and interface_name and enable_status.lower() == 'up':
                # Calculate backup priority (lower than current)
                backup_priority = max(1, priority - 50)
                
                vrrp_instance = VRRPInstance(
                    nepk=appliance.nepk,
                    appliance_name=appliance.name,
                    interface_name=interface_name,
                    vrid=group_id,
                    current_priority=priority,
                    backup_priority=backup_priority,
                    original_priority=priority,
                    state=current_mode.upper()
                )
                
                vrrp_instances.append(vrrp_instance)
                self.logger.info(f"   Found VRRP: Group {group_id} on {interface_name} "
                               f"(Priority: {priority}, Mode: {current_mode}, VIP: {vip_address})")
            else:
                if enable_status.lower() != 'up':
                    self.logger.debug(f"   Skipping disabled VRRP group {group_id} on {interface_name}")
                else:
                    self.logger.debug(f"   Skipping incomplete VRRP config: groupId={group_id}, interface={interface_name}")
        
        if not vrrp_instances:
            self.logger.warning(f"No active VRRP instances found for appliance {appliance.name}")
        
        return vrrp_instances
    
    def get_interface_status(self, nepk: str, interface: str) -> Optional[Dict]:
        """Get operational status of a specific interface"""
        url = f"{self.base_url}/gms/rest/appliance/rest?nePk={nepk}&url=networkInterfaces"
        result = self._make_request('GET', url)
        
        if not result:
            return None
        
        interfaces = self._extract_interfaces_list(result)
        return self._find_interface_in_list(interfaces, interface)
    
    def _extract_interfaces_list(self, result: Union[Dict, List]) -> List[Dict]:
        """Extract interfaces list from API response"""
        if isinstance(result, list):
            return result
        
        if isinstance(result, dict):
            for key in ['interfaces', 'ifInfo']:
                if key in result and isinstance(result[key], list):
                    return result[key]
            
            if 'ifname' in result:
                return [result]
        
        return []
    
    def _find_interface_in_list(self, interfaces: List[Dict], target_interface: str) -> Optional[Dict]:
        """Find specific interface in interfaces list"""
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
                
            interface_names = [
                interface.get('ifname'),
                interface.get('name'),
                interface.get('interface')
            ]
            
            if target_interface in interface_names:
                return interface
        
        return None
    
    def set_interface_state(self, wan_interface: WANInterface, admin_up: bool) -> bool:
        """Enable or disable an interface while preserving all other settings"""
        appliance = self.appliances[wan_interface.nepk]
        state_str = "UP" if admin_up else "DOWN"

        self.logger.info(f"Setting {wan_interface.display_name} to {state_str} "
                        f"on {appliance.name}...")

        # First, get current interface state (preserves MAC address and other fields)
        url = f"{self.base_url}/gms/rest/appliance/rest?nePk={wan_interface.nepk}&url=networkInterfaces"
        current_state = self._make_request('GET', url)

        if not current_state or 'ifInfo' not in current_state:
            self.logger.error(f"Failed to get current interface state for {appliance.name}")
            return False

        # Find and modify only the target interface's admin state
        interface_found = False
        for iface in current_state['ifInfo']:
            if iface.get('ifname') == wan_interface.interface_name:
                iface['admin'] = admin_up
                interface_found = True
                self.logger.debug(f"Found interface {wan_interface.interface_name}, setting admin={admin_up}")
                break

        if not interface_found:
            self.logger.error(f"Interface {wan_interface.interface_name} not found in current state")
            return False

        # Send back the complete payload with only admin modified
        result = self._make_request('POST', url, current_state)
        success = result is not None

        if success:
            self.logger.info(f"Successfully set {wan_interface.display_name} to {state_str}")
        else:
            self.logger.error(f"Failed to set {wan_interface.display_name} to {state_str}")

        return success
    
    def verify_interface_operational(self, wan_interface: WANInterface, max_wait: int = 60) -> bool:
        """Verify that an interface is operationally up"""
        appliance = self.appliances[wan_interface.nepk]
        self.logger.info(f"Verifying {wan_interface.display_name} is operational on {appliance.name}...")
        
        start_time = time.time()
        check_interval = 5
        
        while time.time() - start_time < max_wait:
            status = self.get_interface_status(wan_interface.nepk, wan_interface.interface_name)
            
            if status:
                admin_status = status.get('admin', False)
                oper_status = status.get('oper', False)
                
                if admin_status and oper_status:
                    self.logger.info(f"Interface {wan_interface.display_name} is operational")
                    return True
                elif admin_status:
                    elapsed = int(time.time() - start_time)
                    self.logger.info(f"   Interface admin UP, waiting for operational... ({elapsed}s)")
                else:
                    self.logger.warning(f"   Interface not administratively up: {admin_status}")
            
            time.sleep(check_interval)
        
        self.logger.error(f"Interface {wan_interface.display_name} did not become operational "
                         f"after {max_wait} seconds")
        return False
    
    def get_vrrp_status_by_group(self, nepk: str, group_id: int) -> Optional[Dict]:
        """Get VRRP status for a specific group ID"""
        vrrp_instances = self.get_vrrp_instances(nepk)
        
        for instance in vrrp_instances:
            if instance.get('groupId') == group_id:
                return instance
        
        self.logger.warning(f"VRRP group {group_id} not found on appliance {nepk}")
        return None
    
    # Discovery Methods
    def discover_chaos_targets(self) -> List:
        """Discover chaos targets based on chaos type"""
        self.logger.info("=" * 60)
        if self.chaos_type == ChaosType.ALL:
            self.logger.info("DISCOVERING ALL CHAOS TARGETS (WAN + VRRP)")
        else:
            self.logger.info(f"DISCOVERING {self.chaos_type.value.upper()} CHAOS TARGETS")
        self.logger.info("=" * 60)
        
        self.appliances = self.get_all_appliances()
        if not self.appliances:
            self.logger.error("No appliances found!")
            return []
        
        if self.chaos_type == ChaosType.ALL:
            return self._discover_all_chaos_targets()
        else:
            return self._discover_single_type_targets()
    
    def _discover_all_chaos_targets(self) -> List:
        """Discover both WAN interface and VRRP targets for mixed chaos testing"""
        wan_targets = []
        vrrp_targets = []
        
        for nepk, appliance in self.appliances.items():
            self.logger.info(f"\nProcessing: {appliance.name} (NEPK: {nepk})")
            
            # Get deployment details for WAN interfaces
            appliance.deployment = self.get_deployment_details(nepk)
            if appliance.deployment:
                appliance.wan_interfaces = self.extract_wan_interfaces(appliance)
                wan_targets.extend(appliance.wan_interfaces)
            
            # Get VRRP instances
            appliance.vrrp_instances = self.extract_vrrp_instances(appliance)
            # Only add MASTER instances as targets
            master_instances = [vrrp for vrrp in appliance.vrrp_instances 
                              if vrrp.state.upper() == 'MASTER']
            vrrp_targets.extend(master_instances)
            
            if len(appliance.vrrp_instances) > len(master_instances):
                backup_count = len(appliance.vrrp_instances) - len(master_instances)
                self.logger.info(f"   Note: Found {backup_count} BACKUP VRRP instances (not included as chaos targets)")
        
        # Create mixed targets container
        self.mixed_targets = MixedChaosTarget(
            wan_targets=wan_targets,
            vrrp_targets=vrrp_targets
        )
        
        self._log_mixed_discovery_summary(wan_targets, vrrp_targets)
        
        # For mixed chaos, we return a combined list for counting purposes
        # but actual target selection will use random selection from mixed_targets
        all_targets = wan_targets + vrrp_targets
        
        # Apply randomization if enabled (affects selection order)
        if self.randomize and all_targets:
            self._randomize_mixed_targets(all_targets)
        
        return all_targets
    
    def _discover_single_type_targets(self) -> List:
        """Discover targets for a single chaos type (WAN or VRRP)"""
        all_targets = []
        
        for nepk, appliance in self.appliances.items():
            self.logger.info(f"\nProcessing: {appliance.name} (NEPK: {nepk})")
            
            if self.chaos_type == ChaosType.WAN_INTERFACE:
                # For WAN interfaces, we need deployment details
                appliance.deployment = self.get_deployment_details(nepk)
                if not appliance.deployment:
                    continue
                appliance.wan_interfaces = self.extract_wan_interfaces(appliance)
                all_targets.extend(appliance.wan_interfaces)
            elif self.chaos_type == ChaosType.VRRP:
                # For VRRP, we use the VRRP status API directly
                appliance.vrrp_instances = self.extract_vrrp_instances(appliance)
                # Only add MASTER instances as targets (we want to disrupt the master)
                master_instances = [vrrp for vrrp in appliance.vrrp_instances 
                                  if vrrp.state.upper() == 'MASTER']
                all_targets.extend(master_instances)
                
                if len(appliance.vrrp_instances) > len(master_instances):
                    backup_count = len(appliance.vrrp_instances) - len(master_instances)
                    self.logger.info(f"   Note: Found {backup_count} BACKUP VRRP instances (not included as chaos targets)")
        
        self._log_discovery_summary(all_targets)
        
        # Apply randomization if enabled
        if self.randomize and all_targets:
            self._randomize_targets(all_targets)
        
        return all_targets
    
    def _log_mixed_discovery_summary(self, wan_targets: List[WANInterface], vrrp_targets: List[VRRPInstance]):
        """Log discovery summary for mixed chaos testing"""
        self.logger.info("\n" + "=" * 60)
        self.logger.info("MIXED CHAOS DISCOVERY SUMMARY")
        self.logger.info("=" * 60)
        self.logger.info(f"Total Appliances: {len(self.appliances)}")
        self.logger.info(f"Total WAN Interface Targets: {len(wan_targets)}")
        self.logger.info(f"Total VRRP Targets: {len(vrrp_targets)}")
        self.logger.info(f"Total Mixed Targets: {len(wan_targets) + len(vrrp_targets)}")
        
        if wan_targets:
            self.logger.info(f"\nDiscovered WAN Interface Targets:")
            for target in wan_targets:
                appliance_name = self.appliances[target.nepk].name
                self.logger.info(f"   {appliance_name}: {target.display_name}")
        
        if vrrp_targets:
            self.logger.info(f"\nDiscovered VRRP Targets:")
            for target in vrrp_targets:
                self.logger.info(f"   {target.appliance_name}: {target.display_name} (Priority: {target.current_priority})")
    
    def _randomize_mixed_targets(self, all_targets: List):
        """Randomize mixed chaos targets"""
        # For mixed chaos, we don't pre-shuffle since we'll randomly select type each time
        # But we can randomize the individual lists
        if self.mixed_targets:
            random.shuffle(self.mixed_targets.wan_targets)
            random.shuffle(self.mixed_targets.vrrp_targets)
        
        self.logger.info(f"\nMixed Chaos Randomization applied:")
        self.logger.info(f"   WAN targets shuffled: {len(self.mixed_targets.wan_targets) if self.mixed_targets else 0}")
        self.logger.info(f"   VRRP targets shuffled: {len(self.mixed_targets.vrrp_targets) if self.mixed_targets else 0}")
        self.logger.info(f"   Each cycle will randomly choose between WAN and VRRP chaos")
    
    def _randomize_targets(self, targets: List):
        """Randomize the order of chaos targets and starting position"""
        original_count = len(targets)
        
        # Shuffle the target list
        random.shuffle(targets)
        
        # Pick a random starting index
        self.current_test_index = random.randint(0, len(targets) - 1)
        
        self.logger.info(f"\nRandomization applied:")
        self.logger.info(f"   Target order shuffled: {original_count} targets randomized")
        self.logger.info(f"   Random starting position: {self.current_test_index + 1}/{len(targets)}")
        
        # Show the first few targets in the randomized order
        self.logger.info(f"   Next targets to test:")
        for i in range(min(3, len(targets))):
            idx = (self.current_test_index + i) % len(targets)
            target = targets[idx]
            if isinstance(target, WANInterface):
                appliance_name = self.appliances[target.nepk].name
                self.logger.info(f"     {i+1}. {target.display_name} on {appliance_name}")
            elif isinstance(target, VRRPInstance):
                self.logger.info(f"     {i+1}. {target.display_name} on {target.appliance_name}")
        
        if len(targets) > 3:
            self.logger.info(f"     ... and {len(targets) - 3} more targets")
    
    def _log_discovery_summary(self, targets: List):
        """Log discovery summary"""
        self.logger.info("\n" + "=" * 60)
        self.logger.info("DISCOVERY SUMMARY")
        self.logger.info("=" * 60)
        self.logger.info(f"Total Appliances: {len(self.appliances)}")
        self.logger.info(f"Total {self.chaos_type.value.title()} Targets: {len(targets)}")
        
        if targets:
            self.logger.info(f"\nDiscovered {self.chaos_type.value.title()} Targets:")
            for target in targets:
                if isinstance(target, WANInterface):
                    appliance_name = self.appliances[target.nepk].name
                    self.logger.info(f"   {appliance_name}: {target.display_name}")
                elif isinstance(target, VRRPInstance):
                    self.logger.info(f"   {target.appliance_name}: {target.display_name} (Priority: {target.current_priority})")
    
    # Chaos Testing Methods
    def run_single_chaos_test(self, target) -> TestResult:
        """Run a single chaos test based on target type"""
        if isinstance(target, WANInterface):
            return self.run_wan_interface_chaos_test(target)
        elif isinstance(target, VRRPInstance):
            return self.run_vrrp_chaos_test(target)
        else:
            raise ValueError(f"Unsupported chaos target type: {type(target)}")
    
    def run_wan_interface_chaos_test(self, wan_interface: WANInterface) -> TestResult:
        """Run WAN interface chaos test"""
        appliance = self.appliances[wan_interface.nepk]
        chaos_duration = self._get_chaos_duration()

        self.logger.info("\n" + "=" * 60)
        self.logger.info(f"WAN INTERFACE CHAOS: {wan_interface.display_name} on {appliance.name}")
        self.logger.info(f"Chaos Duration: {chaos_duration} seconds")
        self.logger.info("=" * 60)
        
        test_start_time = datetime.now()
        
        if not self._ensure_interface_initially_up(wan_interface):
            return TestResult(0, wan_interface.display_name, appliance.name, 
                            ChaosType.WAN_INTERFACE, False, test_start_time)
        
        shutdown_time = datetime.now()
        if not self.set_interface_state(wan_interface, admin_up=False):
            return TestResult(0, wan_interface.display_name, appliance.name, 
                            ChaosType.WAN_INTERFACE, False, test_start_time)
        
        self._wait_with_countdown(chaos_duration, "interface chaos")

        recovery_time = datetime.now()
        if not self.set_interface_state(wan_interface, admin_up=True):
            return TestResult(0, wan_interface.display_name, appliance.name,
                            ChaosType.WAN_INTERFACE, False, test_start_time)

        operational = self.verify_interface_operational(wan_interface)

        downtime = (recovery_time - shutdown_time).total_seconds()
        
        result = TestResult(
            cycle=0,
            target_name=wan_interface.display_name,
            appliance_name=appliance.name,
            chaos_type=ChaosType.WAN_INTERFACE,
            success=operational,
            timestamp=test_start_time,
            duration_seconds=downtime,
            details={
                'interface': wan_interface.interface_name,
                'ip_address': wan_interface.ip_address,
                'label': wan_interface.label_name
            }
        )
        
        self._log_test_summary(result)
        return result
    
    def run_vrrp_chaos_test(self, vrrp_instance: VRRPInstance) -> TestResult:
        """Run VRRP chaos test by triggering failover on MASTER instance"""
        appliance = self.appliances[vrrp_instance.nepk]
        chaos_duration = self._get_chaos_duration()

        self.logger.info("\n" + "=" * 60)
        self.logger.info(f"VRRP CHAOS: {vrrp_instance.display_name} on {appliance.name}")
        self.logger.info(f"Current Mode: {vrrp_instance.state}")
        self.logger.info(f"Chaos Duration: {chaos_duration} seconds")
        self.logger.info(f"Strategy: Interface down on MASTER to trigger failover")
        self.logger.info("=" * 60)
        
        test_start_time = datetime.now()
        
        # Verify this is actually a MASTER before proceeding
        current_status = self.get_vrrp_status_by_group(vrrp_instance.nepk, vrrp_instance.vrid)
        if not current_status or current_status.get('mode', '').upper() != 'MASTER':
            self.logger.error(f"VRRP instance is not MASTER (current mode: {current_status.get('mode', 'UNKNOWN') if current_status else 'UNAVAILABLE'})")
            return TestResult(0, vrrp_instance.display_name, appliance.name, 
                            ChaosType.VRRP, False, test_start_time)
        
        interface_name = current_status.get('interface', vrrp_instance.interface_name)
        preempt_enabled = current_status.get('preempt', False)
        original_master_nepk = vrrp_instance.nepk
        
        self.logger.info(f"Confirmed MASTER on interface {interface_name}")
        self.logger.info(f"Preemption enabled: {preempt_enabled}")
        
        # Create a temporary WAN interface object for interface manipulation
        temp_interface = WANInterface(
            nepk=vrrp_instance.nepk,
            interface_name=interface_name,
            label_name=f"VRRP-{vrrp_instance.vrid}-Interface"
        )
        
        # Step 1: Ensure interface is initially up
        if not self._ensure_interface_initially_up(temp_interface):
            return TestResult(0, vrrp_instance.display_name, appliance.name, 
                            ChaosType.VRRP, False, test_start_time)
        
        # Step 2: Bring down the interface to trigger VRRP failover
        shutdown_time = datetime.now()
        self.logger.info(f"Bringing down interface {interface_name} to trigger VRRP failover...")
        if not self.set_interface_state(temp_interface, admin_up=False):
            return TestResult(0, vrrp_instance.display_name, appliance.name, 
                            ChaosType.VRRP, False, test_start_time)
        
        # Step 3: Wait and monitor for VRRP state change (should go to BACKUP or INIT)
        self.logger.info("Waiting for VRRP failover to occur...")
        failover_detected = self._verify_vrrp_failover_occurred(vrrp_instance, max_wait=30)
        
        # Step 4: Identify the new master (if failover occurred)
        new_master_info = None
        if failover_detected:
            new_master_info = self._identify_current_master(vrrp_instance.vrid)
            if new_master_info:
                self.logger.info(f"New MASTER: {new_master_info['appliance_name']} (NEPK: {new_master_info['nepk']})")
        
        # Step 5: Wait for chaos duration
        if failover_detected:
            self._wait_with_countdown(chaos_duration, "VRRP chaos (interface down)")
        
        # Step 6: Bring interface back up
        recovery_time = datetime.now()
        self.logger.info(f"Bringing interface {interface_name} back up...")
        if not self.set_interface_state(temp_interface, admin_up=True):
            return TestResult(0, vrrp_instance.display_name, appliance.name, 
                            ChaosType.VRRP, False, test_start_time)
        
        # Step 7: Verify interface becomes operational
        interface_recovered = self.verify_interface_operational(temp_interface)
        
        # Step 8: Monitor VRRP stabilization (may or may not return to original master)
        self.logger.info("Waiting for VRRP to stabilize after recovery...")
        final_state = self._monitor_vrrp_stabilization(vrrp_instance, original_master_nepk, 
                                                      preempt_enabled, max_wait=90)
        
        # Calculate metrics
        total_duration = (recovery_time - shutdown_time).total_seconds()
        success = (failover_detected and interface_recovered and 
                  final_state['stabilized'] and final_state['healthy'])
        
        result = TestResult(
            cycle=0,
            target_name=vrrp_instance.display_name,
            appliance_name=appliance.name,
            chaos_type=ChaosType.VRRP,
            success=success,
            timestamp=test_start_time,
            duration_seconds=total_duration,
            details={
                'interface': interface_name,
                'vrid': vrrp_instance.vrid,
                'original_priority': vrrp_instance.original_priority,
                'original_master_nepk': original_master_nepk,
                'preempt_enabled': preempt_enabled,
                'failover_detected': failover_detected,
                'interface_recovered': interface_recovered,
                'final_master_nepk': final_state.get('current_master_nepk'),
                'final_master_name': final_state.get('current_master_name'),
                'original_master_restored': final_state.get('original_master_restored', False),
                'vrrp_stabilized': final_state['stabilized'],
                'vrrp_healthy': final_state['healthy'],
                'strategy': 'interface_down'
            }
        )
        
        self._log_test_summary(result)
        return result
    
    def _identify_current_master(self, vrid: int) -> Optional[Dict]:
        """Identify which appliance is currently the MASTER for a given VRRP group"""
        for nepk, appliance in self.appliances.items():
            vrrp_status = self.get_vrrp_status_by_group(nepk, vrid)
            if vrrp_status and vrrp_status.get('mode', '').upper() == 'MASTER':
                return {
                    'nepk': nepk,
                    'appliance_name': appliance.name,
                    'interface': vrrp_status.get('interface'),
                    'priority': vrrp_status.get('priority'),
                    'vip': vrrp_status.get('vipaddr')
                }
        return None
    
    def _monitor_vrrp_stabilization(self, vrrp_instance: VRRPInstance, original_master_nepk: str, 
                                   preempt_enabled: bool, max_wait: int = 90) -> Dict:
        """Monitor VRRP stabilization and determine final state"""
        self.logger.info(f"Monitoring VRRP stabilization (preemption: {preempt_enabled})...")
        
        start_time = time.time()
        check_interval = 5
        stabilization_checks = 0
        required_stable_checks = 3  # Need 3 consecutive stable readings
        
        while time.time() - start_time < max_wait:
            # Check status on original master
            original_status = self.get_vrrp_status_by_group(original_master_nepk, vrrp_instance.vrid)
            current_master_info = self._identify_current_master(vrrp_instance.vrid)
            
            elapsed = int(time.time() - start_time)
            
            if original_status and current_master_info:
                original_mode = original_status.get('mode', 'UNKNOWN').upper()
                current_master_nepk = current_master_info['nepk']
                current_master_name = current_master_info['appliance_name']
                
                # Check if we have a stable MASTER/BACKUP state
                if original_mode in ['MASTER', 'BACKUP'] and current_master_nepk:
                    stabilization_checks += 1
                    
                    if original_master_nepk == current_master_nepk:
                        self.logger.info(f"   Original master restored: {self.appliances[original_master_nepk].name} is MASTER ({elapsed}s)")
                    else:
                        self.logger.info(f"   New master active: {current_master_name} is MASTER, "
                                       f"{self.appliances[original_master_nepk].name} is {original_mode} ({elapsed}s)")
                    
                    if stabilization_checks >= required_stable_checks:
                        self.logger.info(f"VRRP has stabilized after {elapsed} seconds")
                        return {
                            'stabilized': True,
                            'healthy': True,
                            'current_master_nepk': current_master_nepk,
                            'current_master_name': current_master_name,
                            'original_master_restored': original_master_nepk == current_master_nepk,
                            'final_original_mode': original_mode
                        }
                else:
                    # Reset stabilization counter if state is not stable
                    stabilization_checks = 0
                    self.logger.info(f"   VRRP not yet stable: original={original_mode}, "
                                   f"current_master={current_master_name if current_master_info else 'NONE'} ({elapsed}s)")
            else:
                stabilization_checks = 0
                self.logger.info(f"   Cannot get VRRP status, waiting... ({elapsed}s)")
            
            time.sleep(check_interval)
        
        # Timeout occurred
        self.logger.warning(f"VRRP did not stabilize within {max_wait} seconds")
        
        # Try to get final status anyway
        final_master_info = self._identify_current_master(vrrp_instance.vrid)
        final_original_status = self.get_vrrp_status_by_group(original_master_nepk, vrrp_instance.vrid)
        
        return {
            'stabilized': False,
            'healthy': final_master_info is not None,  # At least someone is master
            'current_master_nepk': final_master_info['nepk'] if final_master_info else None,
            'current_master_name': final_master_info['appliance_name'] if final_master_info else None,
            'original_master_restored': (final_master_info and 
                                       final_master_info['nepk'] == original_master_nepk),
            'final_original_mode': (final_original_status.get('mode', 'UNKNOWN').upper() 
                                  if final_original_status else 'UNKNOWN')
        }
    
    def _verify_vrrp_failover_occurred(self, vrrp_instance: VRRPInstance, max_wait: int = 30) -> bool:
        """Verify that VRRP has failed over from MASTER state"""
        self.logger.info(f"Verifying VRRP failover from MASTER state...")
        
        start_time = time.time()
        check_interval = 3
        
        while time.time() - start_time < max_wait:
            status = self.get_vrrp_status_by_group(vrrp_instance.nepk, vrrp_instance.vrid)
            
            if status:
                current_mode = status.get('mode', 'UNKNOWN').upper()
                
                if current_mode != 'MASTER':
                    self.logger.info(f"VRRP failover detected: {vrrp_instance.display_name} is now {current_mode}")
                    vrrp_instance.state = current_mode
                    return True
                else:
                    elapsed = int(time.time() - start_time)
                    self.logger.info(f"   VRRP still MASTER, waiting for failover... ({elapsed}s)")
            else:
                elapsed = int(time.time() - start_time)
                self.logger.info(f"   Cannot get VRRP status, waiting... ({elapsed}s)")
            
            time.sleep(check_interval)
        
        self.logger.error(f"VRRP {vrrp_instance.display_name} did not failover from MASTER "
                         f"after {max_wait} seconds")
        return False
    
    def _ensure_interface_initially_up(self, wan_interface: WANInterface) -> bool:
        """Ensure interface is initially up before testing"""
        self.logger.info("Checking initial interface status...")
        
        status = self.get_interface_status(wan_interface.nepk, wan_interface.interface_name)
        if not status:
            self.logger.error("Could not get interface status")
            return False
        
        admin_up = status.get('admin', False)
        oper_up = status.get('oper', False)
        
        self.logger.info(f"   Initial status - Admin: {admin_up}, Oper: {oper_up}")
        
        if not admin_up:
            self.logger.warning("Interface is administratively down, bringing it up...")
            if not self.set_interface_state(wan_interface, admin_up=True):
                return False
            time.sleep(10)
        
        return True
    
    def _wait_with_countdown(self, duration: int, chaos_description: str = "chaos"):
        """Wait with periodic countdown messages"""
        self.logger.info(f"Introducing {chaos_description} for {duration} seconds...")
        
        for remaining in range(duration, 0, -1):
            if remaining % 10 == 0 or remaining <= 5:
                self.logger.info(f"   {remaining} seconds of {chaos_description} remaining...")
            time.sleep(1)
    
    def _log_test_summary(self, result: TestResult):
        """Log individual chaos test summary"""
        self.logger.info("\n" + "=" * 60)
        self.logger.info(f"{result.chaos_type.value.upper()} CHAOS TEST SUMMARY")
        self.logger.info("=" * 60)
        self.logger.info(f"Status: {'PASSED' if result.success else 'FAILED'}")
        self.logger.info(f"Appliance: {result.appliance_name}")
        self.logger.info(f"Target: {result.target_name}")
        self.logger.info(f"Duration: {result.duration_seconds:.1f} seconds")
        
        if result.chaos_type == ChaosType.VRRP and result.details:
            strategy = result.details.get('strategy', 'unknown')
            if strategy == 'interface_down':
                failover_detected = result.details.get('failover_detected', False)
                interface_recovered = result.details.get('interface_recovered', False)
                vrrp_stabilized = result.details.get('vrrp_stabilized', False)
                vrrp_healthy = result.details.get('vrrp_healthy', False)
                original_master_restored = result.details.get('original_master_restored', False)
                final_master_name = result.details.get('final_master_name', 'UNKNOWN')
                preempt_enabled = result.details.get('preempt_enabled', False)
                
                self.logger.info(f"Strategy: Interface down on MASTER")
                self.logger.info(f"Preemption Enabled: {'YES' if preempt_enabled else 'NO'}")
                self.logger.info(f"Failover Detected: {'YES' if failover_detected else 'NO'}")
                self.logger.info(f"Interface Recovered: {'YES' if interface_recovered else 'NO'}")
                self.logger.info(f"VRRP Stabilized: {'YES' if vrrp_stabilized else 'NO'}")
                self.logger.info(f"VRRP Healthy: {'YES' if vrrp_healthy else 'NO'}")
                
                if original_master_restored:
                    self.logger.info(f"Final State: Original master {result.appliance_name} reclaimed MASTER role")
                elif final_master_name and final_master_name != 'UNKNOWN':
                    self.logger.info(f"Final State: {final_master_name} is now MASTER, {result.appliance_name} is BACKUP")
                else:
                    self.logger.info(f"Final State: Unable to determine final VRRP state")
        
        self.logger.info(f"Overall Test Result: {'SUCCESSFUL' if result.success else 'FAILED'}")
        self.logger.info("=" * 60)
    
    def run_continuous_chaos_test(self, cycles: Optional[int] = None, 
                                 wait_between_cycles: int = 300, chaos_selection: str = "sequential"):
        """Run continuous chaos tests with configurable target selection"""
        if self.chaos_type == ChaosType.ALL:
            chaos_name = "MIXED CHAOS MONKEY (WAN + VRRP)"
        else:
            chaos_name = f"{self.chaos_type.value.upper()} CHAOS MONKEY"
        
        self.logger.info(f"STARTING SD-WAN {chaos_name}")
        
        self.chaos_targets = self.discover_chaos_targets()
        if not self.chaos_targets:
            self.logger.error(f"No {self.chaos_type.value} targets found! Aborting chaos test.")
            return
        
        self.logger.info(f"\nChaos Test Configuration:")
        self.logger.info(f"   Chaos Type: {self.chaos_type.value}")
        self.logger.info(f"   Targets: {len(self.chaos_targets)}")
        if self.chaos_type == ChaosType.ALL:
            self.logger.info(f"   Target Selection: Random mixed (WAN + VRRP)")
            self.logger.info(f"   WAN Targets: {len(self.mixed_targets.wan_targets) if self.mixed_targets else 0}")
            self.logger.info(f"   VRRP Targets: {len(self.mixed_targets.vrrp_targets) if self.mixed_targets else 0}")
        else:
            self.logger.info(f"   Target Selection: {chaos_selection}")
        self.logger.info(f"   Wait between cycles: {wait_between_cycles} seconds")
        self.logger.info(f"   Total cycles: {'Infinite' if cycles is None else cycles}")
        if self.duration_max and self.duration_max > self.duration_min:
            self.logger.info(f"   Chaos duration: {self.duration_min}-{self.duration_max} seconds (random)")
        else:
            self.logger.info(f"   Chaos duration: {self.duration_min} seconds (fixed)")
        
        results = []
        cycle_count = 0
        
        try:
            while cycles is None or cycle_count < cycles:
                cycle_count += 1
                
                # Select target based on chaos selection strategy
                target = self._select_next_target(chaos_selection)
                
                self._log_cycle_header(cycle_count, target)
                
                result = self.run_single_chaos_test(target)
                result.cycle = cycle_count
                results.append(result)
                
                # Update index for sequential mode (only for single-type chaos)
                if chaos_selection == "sequential" and self.chaos_type != ChaosType.ALL:
                    self.current_test_index = (self.current_test_index + 1) % len(self.chaos_targets)
                
                if cycles is None or cycle_count < cycles:
                    self._wait_between_cycles(wait_between_cycles)
        
        except KeyboardInterrupt:
            self.logger.info(f"\n{chaos_name} interrupted by user")
        
        self._print_final_summary(results)
    
    def _select_next_target(self, selection_strategy: str):
        """Select next target based on strategy"""
        if self.chaos_type == ChaosType.ALL:
            return self._select_mixed_chaos_target()
        else:
            return self._select_single_type_target(selection_strategy)
    
    def _select_mixed_chaos_target(self) -> Union[WANInterface, VRRPInstance]:
        """Select a random target from mixed chaos targets"""
        if not self.mixed_targets or self.mixed_targets.total_targets == 0:
            raise ValueError("No mixed chaos targets available")
        
        # Randomly choose between WAN and VRRP targets
        wan_count = len(self.mixed_targets.wan_targets)
        vrrp_count = len(self.mixed_targets.vrrp_targets)
        
        if wan_count == 0 and vrrp_count == 0:
            raise ValueError("No targets available for mixed chaos")
        elif wan_count == 0:
            # Only VRRP targets available
            target = random.choice(self.mixed_targets.vrrp_targets)
            target_type = "VRRP"
        elif vrrp_count == 0:
            # Only WAN targets available
            target = random.choice(self.mixed_targets.wan_targets)
            target_type = "WAN Interface"
        else:
            # Both types available, randomly choose
            if random.choice([True, False]):  # 50/50 chance
                target = random.choice(self.mixed_targets.wan_targets)
                target_type = "WAN Interface"
            else:
                target = random.choice(self.mixed_targets.vrrp_targets)
                target_type = "VRRP"
        
        # Log the selection
        if isinstance(target, WANInterface):
            appliance_name = self.appliances[target.nepk].name
            target_desc = f"{target.display_name} on {appliance_name}"
        elif isinstance(target, VRRPInstance):
            target_desc = f"{target.display_name} on {target.appliance_name}"
        else:
            target_desc = str(target)
        
        self.logger.info(f"Mixed chaos selection: {target_type} - {target_desc}")
        return target
    
    def _select_single_type_target(self, selection_strategy: str):
        """Select target for single chaos type (original logic)"""
        if selection_strategy == "random":
            # Pure random selection
            target = random.choice(self.chaos_targets)
            target_index = self.chaos_targets.index(target)
        elif selection_strategy == "weighted-random":
            # Weighted random - less likely to pick recently tested targets
            weights = []
            for i, _ in enumerate(self.chaos_targets):
                # Give higher weight to targets further from current index
                distance = abs(i - self.current_test_index)
                weight = max(1, distance)  # Minimum weight of 1
                weights.append(weight)
            
            target = random.choices(self.chaos_targets, weights=weights)[0]
            target_index = self.chaos_targets.index(target)
        else:  # sequential (default)
            target = self.chaos_targets[self.current_test_index]
            target_index = self.current_test_index
        
        # Log selection info for non-sequential modes
        if selection_strategy != "sequential":
            total_targets = len(self.chaos_targets)
            if isinstance(target, WANInterface):
                appliance_name = self.appliances[target.nepk].name
                target_desc = f"{target.display_name} on {appliance_name}"
            elif isinstance(target, VRRPInstance):
                target_desc = f"{target.display_name} on {target.appliance_name}"
            else:
                target_desc = str(target)
            
            self.logger.info(f"Target selection: {target_desc} "
                           f"(position {target_index + 1}/{total_targets})")
        
        return target
    
    def _log_cycle_header(self, cycle: int, target):
        """Log cycle header information"""
        total_targets = len(self.chaos_targets)
        current_position = self.current_test_index + 1
        
        if isinstance(target, WANInterface):
            appliance_name = self.appliances[target.nepk].name
            target_name = target.display_name
            target_type = "WAN Interface"
        elif isinstance(target, VRRPInstance):
            appliance_name = target.appliance_name
            target_name = target.display_name
            target_type = "VRRP"
        else:
            appliance_name = "Unknown"
            target_name = str(target)
            target_type = "Unknown"
        
        self.logger.info("\n" + "#" * 60)
        if self.chaos_type == ChaosType.ALL:
            self.logger.info(f"# CYCLE {cycle} - {target_type} Chaos")
        else:
            self.logger.info(f"# CYCLE {cycle} - {self.chaos_type.value.title()} {current_position} of {total_targets}")
        self.logger.info(f"# Target: {target_name} on {appliance_name}")
        self.logger.info("#" * 60)
    
    def _wait_between_cycles(self, wait_time: int):
        """Wait between test cycles with periodic updates"""
        self.logger.info(f"\nWaiting {wait_time} seconds before next cycle...")
        
        update_interval = min(30, wait_time // 4) if wait_time > 30 else wait_time
        
        for remaining in range(wait_time, 0, -update_interval):
            self.logger.info(f"   Next test in {remaining} seconds...")
            time.sleep(min(update_interval, remaining))
    
    def _print_final_summary(self, results: List[TestResult]):
        """Print comprehensive final chaos test summary"""
        if not results:
            self.logger.info("No chaos test results to summarize")
            return
        
        if self.chaos_type == ChaosType.ALL:
            chaos_name = "SD-WAN MIXED CHAOS MONKEY (WAN + VRRP)"
        else:
            chaos_name = f"SD-WAN {self.chaos_type.value.upper()} CHAOS MONKEY"
        
        self.logger.info("\n" + "=" * 80)
        self.logger.info(f"{chaos_name} - FINAL SUMMARY")
        self.logger.info("=" * 80)
        
        total_tests = len(results)
        successful_tests = sum(1 for r in results if r.success)
        success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0
        
        self.logger.info(f"Total Chaos Events: {total_tests}")
        self.logger.info(f"Successful Recoveries: {successful_tests}")
        self.logger.info(f"Failed Recoveries: {total_tests - successful_tests}")
        self.logger.info(f"Recovery Success Rate: {success_rate:.1f}%")
        
        # Break down by chaos type if mixed
        if self.chaos_type == ChaosType.ALL:
            wan_results = [r for r in results if r.chaos_type == ChaosType.WAN_INTERFACE]
            vrrp_results = [r for r in results if r.chaos_type == ChaosType.VRRP]
            
            self.logger.info(f"\nBreakdown by Chaos Type:")
            self.logger.info(f"   WAN Interface Tests: {len(wan_results)} "
                           f"({sum(1 for r in wan_results if r.success)}/{len(wan_results)} successful)")
            self.logger.info(f"   VRRP Tests: {len(vrrp_results)} "
                           f"({sum(1 for r in vrrp_results if r.success)}/{len(vrrp_results)} successful)")
        
        self.logger.info(f"\nChaos Event Results:")
        for result in results:
            status = "PASS" if result.success else "FAIL"
            timestamp = result.timestamp.strftime('%H:%M:%S')
            chaos_type_str = result.chaos_type.value.upper() if result.chaos_type != ChaosType.ALL else "MIXED"
            self.logger.info(f"   Cycle {result.cycle:2d} [{timestamp}] {status} - "
                           f"{chaos_type_str}: {result.target_name} on {result.appliance_name} "
                           f"({result.duration_seconds:.1f}s duration)")
        
        self._log_per_appliance_summary(results)
        self._log_performance_metrics(results)
        
        self.logger.info("=" * 80)
    
    def _log_per_appliance_summary(self, results: List[TestResult]):
        """Log per-appliance test summary"""
        appliance_stats = {}
        
        for result in results:
            appliance = result.appliance_name
            if appliance not in appliance_stats:
                appliance_stats[appliance] = {'total': 0, 'success': 0, 'total_duration': 0.0}
            
            stats = appliance_stats[appliance]
            stats['total'] += 1
            stats['total_duration'] += result.duration_seconds
            if result.success:
                stats['success'] += 1
        
        if self.chaos_type == ChaosType.ALL:
            self.logger.info(f"\nPer-Appliance Mixed Chaos Resilience Results:")
        else:
            self.logger.info(f"\nPer-Appliance {self.chaos_type.value.title()} Resilience Results:")
        
        for appliance, stats in appliance_stats.items():
            rate = (stats['success'] / stats['total'] * 100) if stats['total'] > 0 else 0
            avg_duration = stats['total_duration'] / stats['total'] if stats['total'] > 0 else 0
            self.logger.info(f"   {appliance}: {stats['success']}/{stats['total']} "
                           f"({rate:.1f}% recovery rate) - Avg duration: {avg_duration:.1f}s")
    
    def _log_performance_metrics(self, results: List[TestResult]):
        """Log performance metrics from test results"""
        if not results:
            return
        
        successful_results = [r for r in results if r.success]
        
        if successful_results:
            durations = [r.duration_seconds for r in successful_results]
            avg_duration = sum(durations) / len(durations)
            min_duration = min(durations)
            max_duration = max(durations)
            
            if self.chaos_type == ChaosType.ALL:
                self.logger.info(f"\nMixed Chaos Engineering Metrics:")
            else:
                self.logger.info(f"\n{self.chaos_type.value.title()} Chaos Engineering Metrics:")
            
            self.logger.info(f"   Average duration: {avg_duration:.1f}s")
            self.logger.info(f"   Minimum duration: {min_duration:.1f}s")
            self.logger.info(f"   Maximum duration: {max_duration:.1f}s")


def setup_logging(debug: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='SD-WAN Chaos Monkey - Unified chaos engineering platform for SD-WAN networks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # WAN Interface chaos testing (randomized by default)
  python3 sdwan_chaos_monkey.py --chaos-type wan-interface --token YOUR_TOKEN

  # Run with random chaos duration between 15-60 seconds
  python3 sdwan_chaos_monkey.py --chaos-type wan-interface --token YOUR_TOKEN --duration-min 15 --duration-max 60

  # VRRP chaos testing with pure random selection
  python3 sdwan_chaos_monkey.py --chaos-type vrrp --token YOUR_TOKEN --chaos-selection random

  # Mixed chaos testing - randomly alternates between WAN and VRRP
  python3 sdwan_chaos_monkey.py --chaos-type all --token YOUR_TOKEN --cycles 20

  # Run chaos only on specific nodes (via YAML file)
  python3 sdwan_chaos_monkey.py --chaos-type wan-interface --token YOUR_TOKEN --nodes-file nodes.yaml

  # Deterministic testing (no randomization)
  python3 sdwan_chaos_monkey.py --chaos-type wan-interface --token YOUR_TOKEN --no-randomize

  # Reproducible random testing with seed
  python3 sdwan_chaos_monkey.py --chaos-type all --token YOUR_TOKEN --random-seed 12345

  # Single WAN interface test
  python3 sdwan_chaos_monkey.py --chaos-type wan-interface --token YOUR_TOKEN --single-test 4.NE twan0

  # Single VRRP test
  python3 sdwan_chaos_monkey.py --chaos-type vrrp --token YOUR_TOKEN --single-test 4.NE eth0 1

  # Weighted random selection with limited cycles
  python3 sdwan_chaos_monkey.py --chaos-type wan-interface --token YOUR_TOKEN --chaos-selection weighted-random --cycles 10
        """
    )
    
    # Chaos type (required)
    parser.add_argument(
        '--chaos-type',
        type=str,
        required=True,
        choices=['wan-interface', 'vrrp', 'all'],
        help='Type of chaos to introduce: wan-interface, vrrp, or all (randomly mixed)'
    )
    
    # Authentication options (required - choose one)
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument(
        '--token', 
        help='API token for authentication (uses X-Auth-Token header by default)'
    )
    auth_group.add_argument(
        '--auth', 
        help='Username:password for basic auth'
    )
    
    # Required arguments
    parser.add_argument(
        '--url',
        default='https://jh-bgp-ha-sewan-orchsp-useast1.silverpeak.cloud',
        help='Orchestrator base URL (default: %(default)s)'
    )
    
    # Authentication method
    parser.add_argument(
        '--query-auth',
        action='store_true',
        help='Use apiKey query parameter instead of X-Auth-Token header for token auth'
    )
    
    # Chaos duration options
    parser.add_argument(
        '--duration-min',
        type=int,
        default=30,
        help='Minimum (or fixed) chaos duration in seconds (default: %(default)s)',
        metavar='SECONDS'
    )
    parser.add_argument(
        '--duration-max',
        type=int,
        default=None,
        help='Maximum chaos duration in seconds (enables random duration between min and max)',
        metavar='SECONDS'
    )

    # Node filtering
    parser.add_argument(
        '--nodes-file',
        type=str,
        default=None,
        help='Path to YAML file specifying nodes to include/exclude (see nodes.yaml.example)',
        metavar='FILE'
    )
    
    # Continuous test options
    parser.add_argument(
        '--cycles',
        type=int,
        help='Number of chaos cycles (default: infinite)',
        metavar='N'
    )
    parser.add_argument(
        '--wait',
        type=int,
        default=300,
        help='Wait time between cycles in seconds (default: %(default)s = 5 minutes)',
        metavar='SECONDS'
    )
    
    # Single test mode - flexible for different chaos types
    parser.add_argument(
        '--single-test',
        nargs='+',
        help='Run single test: --single-test NEPK INTERFACE [VRID] (VRID only for VRRP tests)'
    )
    
    # Randomization options
    parser.add_argument(
        '--randomize',
        action='store_true',
        default=True,
        help='Randomize target order and starting position (default: enabled)'
    )
    parser.add_argument(
        '--no-randomize',
        action='store_true',
        help='Disable randomization (use deterministic order)'
    )
    parser.add_argument(
        '--random-seed',
        type=int,
        help='Random seed for reproducible testing',
        metavar='SEED'
    )
    parser.add_argument(
        '--chaos-selection',
        type=str,
        choices=['sequential', 'random', 'weighted-random'],
        default='sequential',
        help='Target selection strategy (default: %(default)s) - ignored for --chaos-type all'
    )
    
    # Other options
    parser.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Disable SSL certificate verification'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='HTTP request timeout in seconds (default: %(default)s)',
        metavar='SECONDS'
    )
    
    return parser.parse_args()


def validate_arguments(args: argparse.Namespace) -> Tuple[Optional[str], Optional[str]]:
    """Validate and parse authentication arguments"""
    username = None
    password = None
    
    if args.auth:
        if ':' not in args.auth:
            raise ValueError("Auth format should be username:password")
        username, password = args.auth.split(':', 1)
    
    # Handle randomization flags
    if hasattr(args, 'no_randomize') and args.no_randomize:
        args.randomize = False
    
    # Validate chaos type
    if args.chaos_type not in ['wan-interface', 'vrrp', 'all']:
        raise ValueError("Chaos type must be 'wan-interface', 'vrrp', or 'all'")
    
    # Validate single test arguments
    if args.single_test:
        if args.chaos_type == 'all':
            raise ValueError("Single test mode not supported with --chaos-type all")
        if args.chaos_type == 'wan-interface' and len(args.single_test) != 2:
            raise ValueError("WAN interface single test requires: NEPK INTERFACE")
        elif args.chaos_type == 'vrrp' and len(args.single_test) != 3:
            raise ValueError("VRRP single test requires: NEPK INTERFACE VRID")
    
    # Validate duration
    if args.duration_min <= 0:
        raise ValueError("Duration minimum must be positive")

    if args.duration_max is not None:
        if args.duration_max <= 0:
            raise ValueError("Duration maximum must be positive")
        if args.duration_max < args.duration_min:
            raise ValueError("Duration maximum must be greater than or equal to duration minimum")

    # Validate wait time
    if args.wait < 0:
        raise ValueError("Wait time cannot be negative")
    
    # Validate cycles
    if args.cycles is not None and args.cycles <= 0:
        raise ValueError("Cycles must be positive")
    
    # Validate timeout
    if args.timeout <= 0:
        raise ValueError("Timeout must be positive")
    
    # Validate random seed
    if args.random_seed is not None and args.random_seed < 0:
        raise ValueError("Random seed must be non-negative")
    
    return username, password


def load_node_filter(nodes_file: Optional[str]) -> Optional[Dict]:
    """Load node include/exclude filter from a YAML file"""
    if not nodes_file:
        return None

    logger = logging.getLogger(__name__)

    try:
        with open(nodes_file, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        raise ValueError(f"Nodes file not found: {nodes_file}")
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in nodes file: {e}")

    if not isinstance(config, dict):
        raise ValueError("Nodes file must contain a YAML mapping with 'include' and/or 'exclude' keys")

    node_filter = {}
    if 'include' in config:
        if not isinstance(config['include'], list):
            raise ValueError("'include' must be a list of hostnames")
        node_filter['include'] = [str(h) for h in config['include']]
        logger.info(f"Loaded {len(node_filter['include'])} nodes to include from {nodes_file}")

    if 'exclude' in config:
        if not isinstance(config['exclude'], list):
            raise ValueError("'exclude' must be a list of hostnames")
        node_filter['exclude'] = [str(h) for h in config['exclude']]
        logger.info(f"Loaded {len(node_filter['exclude'])} nodes to exclude from {nodes_file}")

    if 'include' in node_filter and 'exclude' in node_filter:
        raise ValueError("Nodes file should contain either 'include' or 'exclude', not both")

    if not node_filter:
        logger.warning(f"Nodes file {nodes_file} has no 'include' or 'exclude' keys, ignoring")
        return None

    return node_filter


def create_chaos_monkey(args: argparse.Namespace, username: str, password: str) -> SDWANChaosMonkey:
    """Create and configure the SD-WAN Chaos Monkey"""
    if args.chaos_type == 'wan-interface':
        chaos_type = ChaosType.WAN_INTERFACE
    elif args.chaos_type == 'vrrp':
        chaos_type = ChaosType.VRRP
    else:  # args.chaos_type == 'all'
        chaos_type = ChaosType.ALL

    node_filter = load_node_filter(args.nodes_file)

    return SDWANChaosMonkey(
        base_url=args.url,
        chaos_type=chaos_type,
        auth_token=args.token,
        username=username,
        password=password,
        duration_min=args.duration_min,
        duration_max=args.duration_max,
        verify_ssl=not args.no_verify_ssl,
        use_query_auth=args.query_auth,
        randomize=args.randomize,
        random_seed=args.random_seed,
        node_filter=node_filter
    )


def run_single_test(chaos_monkey: SDWANChaosMonkey, test_args: List[str]) -> int:
    """Run a single chaos test"""
    logger = logging.getLogger(__name__)
    
    # Discover appliances first
    chaos_monkey.appliances = chaos_monkey.get_all_appliances()
    if not chaos_monkey.appliances:
        logger.error("No appliances discovered! Check your URL and authentication.")
        return 1
    
    nepk = test_args[0]
    interface = test_args[1]
    
    if nepk not in chaos_monkey.appliances:
        logger.error(f"Appliance {nepk} not found!")
        available = ', '.join(chaos_monkey.appliances.keys())
        logger.error(f"Available appliances: {available}")
        return 1
    
    # Create appropriate test target
    if chaos_monkey.chaos_type == ChaosType.WAN_INTERFACE:
        target = WANInterface(
            nepk=nepk,
            interface_name=interface,
            label_name="Manual Chaos Test"
        )
        logger.info(f"Running single WAN interface chaos test on {nepk}:{interface}")
    elif chaos_monkey.chaos_type == ChaosType.VRRP:
        if len(test_args) < 3:
            logger.error("VRRP test requires VRID parameter")
            return 1
        
        try:
            vrid = int(test_args[2])
        except ValueError:
            logger.error("VRID must be a valid integer")
            return 1
        
        appliance = chaos_monkey.appliances[nepk]
        target = VRRPInstance(
            nepk=nepk,
            appliance_name=appliance.name,
            interface_name=interface,
            vrid=vrid,
            current_priority=100,  # Will be updated from actual config
            backup_priority=50,
            original_priority=100
        )
        logger.info(f"Running single VRRP chaos test on {nepk}:{interface} VRID {vrid}")
    
    result = chaos_monkey.run_single_chaos_test(target)
    return 0 if result.success else 1


def run_continuous_test(chaos_monkey: SDWANChaosMonkey, cycles: Optional[int], 
                       wait_between_cycles: int, chaos_selection: str) -> int:
    """Run continuous chaos tests"""
    logger = logging.getLogger(__name__)
    
    logger.info(f"Starting {chaos_monkey.chaos_type.value} chaos engineering tests...")
    chaos_monkey.run_continuous_chaos_test(
        cycles=cycles,
        wait_between_cycles=wait_between_cycles,
        chaos_selection=chaos_selection
    )
    return 0


def main() -> int:
    """Main function with improved error handling and logging"""
    try:
        args = parse_arguments()
        setup_logging(args.debug)
        
        logger = logging.getLogger(__name__)
        
        # Validate arguments
        username, password = validate_arguments(args)
        
        # Create chaos monkey
        chaos_monkey = create_chaos_monkey(args, username, password)
        
        # Log startup information
        logger.info("SD-WAN Chaos Monkey Starting...")
        logger.info(f"Chaos Type: {args.chaos_type}")
        if args.chaos_type == 'all':
            logger.info(f"   Mixed chaos mode - randomly alternates between WAN and VRRP")
        logger.info(f"Orchestrator URL: {args.url}")
        logger.info(f"Authentication: {'Token' if args.token else 'Basic Auth'}")
        logger.info(f"SSL Verification: {not args.no_verify_ssl}")
        if args.duration_max and args.duration_max > args.duration_min:
            logger.info(f"Chaos Duration: {args.duration_min}-{args.duration_max} seconds (random)")
        else:
            logger.info(f"Chaos Duration: {args.duration_min} seconds (fixed)")
        logger.info(f"Randomization: {'Enabled' if args.randomize else 'Disabled'}")
        if args.random_seed is not None:
            logger.info(f"Random Seed: {args.random_seed}")
        
        # Run appropriate test mode
        if args.single_test:
            return run_single_test(chaos_monkey, args.single_test)
        else:
            return run_continuous_test(chaos_monkey, args.cycles, args.wait, args.chaos_selection)
    
    except KeyboardInterrupt:
        logger = logging.getLogger(__name__)
        logger.info("\nChaos test interrupted by user")
        return 130
    
    except ValueError as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Invalid argument: {e}")
        return 2
    
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Unexpected error: {e}")
        if '--debug' in sys.argv:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
