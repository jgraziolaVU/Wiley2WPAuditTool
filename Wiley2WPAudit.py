import streamlit as st
import requests
import os
import json
import datetime
from pathlib import Path
import urllib.parse
import zipfile
import tarfile
import tempfile
import shutil
import csv
import io
import logging
import socket
import hashlib
import threading
import time
import base64
import xml.etree.ElementTree as ET
import re
from urllib.parse import urlparse

# --- Configuration ---
LOCAL_BACKUP_DIR = Path("./backups")
DOWNLOADS_DIR = Path("./downloads")
LOGS_DIR = Path("./logs")

# Ensure directories exist
LOCAL_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Enhanced A2 Hosting configuration with extensive troubleshooting
A2_HOSTING_CONFIG = {
    'default_ports': {
        'secure': '2083',
        'non_secure': '2082'
    },
    'softaculous_paths': [
        '/frontend/jupiter/softaculous/index.live.php',
        '/frontend/paper_lantern/softaculous/index.live.php',
        '/frontend/x3/softaculous/index.live.php',
        '/softaculous/index.php',
        '/cpanel/softaculous/index.php',
        '/frontend/jupiter/softaculous/',
        '/frontend/jupiter/softaculous/index.php',
        '/3rdparty/softaculous/index.php'
    ],
    'cpanel_paths': [
        '/frontend/jupiter/',
        '/frontend/paper_lantern/',
        '/frontend/x3/',
        '/cpanel/',
        '/execute/',
        '/json-api/'
    ],
    'api_formats': ['json', 'serialize', 'xml'],
    'known_servers': [
        'server.a2hosting.com',
        'nl1-ss*.a2hosting.com',
        'sg*.a2hosting.com',
        'mi*.a2hosting.com',
        'server.clasit.org'
    ],
    'reseller_indicators': [
        'clasit.org',
        'hosting-provider.com',
        'myreseller.com'
    ]
}

# --- Enhanced Audit Logging System ---
class EnhancedAuditLogger:
    def __init__(self):
        self.logs_dir = LOGS_DIR
        self.setup_loggers()
        
    def setup_loggers(self):
        """Set up comprehensive logging system"""
        today = datetime.datetime.now().strftime('%Y-%m-%d')
        
        # Diagnostic logger for API troubleshooting
        self.diagnostic_logger = logging.getLogger('diagnostic')
        self.diagnostic_logger.setLevel(logging.DEBUG)
        diagnostic_handler = logging.FileHandler(self.logs_dir / f"diagnostic_{today}.log")
        diagnostic_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        diagnostic_handler.setFormatter(diagnostic_formatter)
        if not self.diagnostic_logger.handlers:
            self.diagnostic_logger.addHandler(diagnostic_handler)
        
        # API calls logger with full request/response details
        self.api_logger = logging.getLogger('api_detailed')
        self.api_logger.setLevel(logging.DEBUG)
        api_handler = logging.FileHandler(self.logs_dir / f"api_detailed_{today}.log")
        api_formatter = logging.Formatter('%(asctime)s - %(message)s')
        api_handler.setFormatter(api_formatter)
        if not self.api_logger.handlers:
            self.api_logger.addHandler(api_handler)
    
    def log_diagnostic(self, category, message, details=None):
        """Log diagnostic information for troubleshooting"""
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'category': category,
            'message': message,
            'details': details or {},
            'session_id': st.session_state.get('session_id', 'unknown')
        }
        self.diagnostic_logger.info(json.dumps(log_entry))
    
    def log_api_detailed(self, request_info, response_info, error_info=None):
        """Log detailed API request/response information"""
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'request': request_info,
            'response': response_info,
            'error': error_info,
            'session_id': st.session_state.get('session_id', 'unknown')
        }
        self.api_logger.debug(json.dumps(log_entry, indent=2))

# Global enhanced audit logger
enhanced_logger = EnhancedAuditLogger()

# --- Comprehensive Server Analysis ---
def analyze_server_configuration(host, port, user, password):
    """Comprehensive analysis of server configuration and capabilities"""
    st.write("🔍 **Starting comprehensive server analysis...**")
    
    analysis_results = {
        'server_type': 'unknown',
        'hosting_provider': 'unknown',
        'cpanel_version': 'unknown',
        'available_apis': [],
        'working_paths': [],
        'authentication_methods': [],
        'ssl_info': {},
        'response_formats': [],
        'errors': []
    }
    
    # 1. Basic connectivity test
    st.write("📡 **Testing basic connectivity...**")
    connectivity_result = test_basic_connectivity(host, port)
    analysis_results['connectivity'] = connectivity_result
    
    if not connectivity_result['success']:
        st.error(f"❌ Basic connectivity failed: {connectivity_result['error']}")
        return analysis_results
    
    st.success("✅ Basic connectivity successful")
    
    # 2. SSL/Certificate analysis
    st.write("🔒 **Analyzing SSL configuration...**")
    ssl_info = analyze_ssl_configuration(host, port)
    analysis_results['ssl_info'] = ssl_info
    
    # 3. Server identification
    st.write("🏢 **Identifying hosting provider and server type...**")
    server_info = identify_hosting_provider(host)
    analysis_results.update(server_info)
    
    # 4. cPanel detection and version
    st.write("🖥️ **Detecting cPanel version and theme...**")
    cpanel_info = detect_cpanel_configuration(host, port, user, password)
    analysis_results.update(cpanel_info)
    
    # 5. API endpoint discovery
    st.write("🔍 **Discovering available API endpoints...**")
    api_endpoints = discover_api_endpoints(host, port, user, password)
    analysis_results['available_apis'] = api_endpoints
    
    # 6. Authentication method testing
    st.write("🔐 **Testing authentication methods...**")
    auth_methods = test_authentication_methods(host, port, user, password)
    analysis_results['authentication_methods'] = auth_methods
    
    # 7. Softaculous detection
    st.write("⚙️ **Detecting Softaculous installation and configuration...**")
    softaculous_info = detect_softaculous_configuration(host, port, user, password)
    analysis_results['softaculous'] = softaculous_info
    
    # Log comprehensive analysis
    enhanced_logger.log_diagnostic('SERVER_ANALYSIS', 'Complete server analysis', analysis_results)
    
    return analysis_results

def test_basic_connectivity(host, port):
    """Test basic network connectivity to the server"""
    try:
        # Test socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        
        if result == 0:
            return {'success': True, 'method': 'socket'}
        else:
            return {'success': False, 'error': f'Socket connection failed (code: {result})'}
    
    except Exception as e:
        return {'success': False, 'error': str(e)}

def analyze_ssl_configuration(host, port):
    """Analyze SSL certificate and configuration"""
    ssl_info = {}
    
    try:
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, int(port)), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                ssl_info = {
                    'version': ssock.version(),
                    'cipher': ssock.cipher(),
                    'certificate': {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter')
                    }
                }
    
    except Exception as e:
        ssl_info = {'error': str(e), 'self_signed': True}
    
    return ssl_info

def identify_hosting_provider(host):
    """Identify hosting provider and server characteristics"""
    host_lower = host.lower()
    
    provider_info = {
        'hosting_provider': 'unknown',
        'server_type': 'unknown',
        'location': 'unknown',
        'is_reseller': False,
        'reseller_info': {}
    }
    
    # A2 Hosting detection
    if 'a2hosting.com' in host_lower:
        provider_info['hosting_provider'] = 'A2 Hosting'
        if 'nl1-ss' in host_lower:
            provider_info['location'] = 'Netherlands'
            provider_info['server_type'] = 'Shared'
        elif 'sg' in host_lower:
            provider_info['location'] = 'Singapore'
            provider_info['server_type'] = 'Shared'
        elif 'mi' in host_lower:
            provider_info['location'] = 'Michigan, USA'
            provider_info['server_type'] = 'Shared'
        elif 'server.a2hosting.com' in host_lower:
            provider_info['server_type'] = 'VPS/Dedicated'
    
    # Reseller detection
    elif 'clasit.org' in host_lower:
        provider_info['hosting_provider'] = 'A2 Hosting Reseller'
        provider_info['is_reseller'] = True
        provider_info['reseller_info'] = {
            'reseller_name': 'CLAS IT',
            'parent_provider': 'A2 Hosting'
        }
    
    # Generic reseller patterns
    elif any(indicator in host_lower for indicator in ['hosting', 'server', 'cpanel']):
        provider_info['hosting_provider'] = 'Possible Reseller'
        provider_info['is_reseller'] = True
    
    return provider_info

def detect_cpanel_configuration(host, port, user, password):
    """Detect cPanel version, theme, and configuration"""
    cpanel_info = {
        'version': 'unknown',
        'theme': 'unknown',
        'available_themes': [],
        'working_paths': []
    }
    
    # Test common cPanel paths
    test_paths = [
        '/cpanel',
        '/frontend/jupiter/',
        '/frontend/paper_lantern/',
        '/frontend/x3/',
        '/'
    ]
    
    for path in test_paths:
        try:
            url = f"https://{host}:{port}{path}"
            response = requests.get(
                url,
                auth=(user, password),
                verify=False,
                timeout=10,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                cpanel_info['working_paths'].append(path)
                
                # Extract cPanel version and theme from response
                content = response.text.lower()
                
                # Look for cPanel version
                version_patterns = [
                    r'cpanel[^\d]*(\d+\.\d+[\.\d]*)',
                    r'version[^\d]*(\d+\.\d+[\.\d]*)',
                    r'cpanel_magic_revision_(\d+)'
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, content)
                    if match:
                        cpanel_info['version'] = match.group(1)
                        break
                
                # Detect theme
                if 'jupiter' in content:
                    cpanel_info['theme'] = 'jupiter'
                elif 'paper_lantern' in content:
                    cpanel_info['theme'] = 'paper_lantern'
                elif 'x3' in content:
                    cpanel_info['theme'] = 'x3'
                
                # Look for available themes
                theme_patterns = ['jupiter', 'paper_lantern', 'x3', 'retro']
                for theme in theme_patterns:
                    if theme in content and theme not in cpanel_info['available_themes']:
                        cpanel_info['available_themes'].append(theme)
        
        except Exception as e:
            enhanced_logger.log_diagnostic('CPANEL_DETECTION', f'Path {path} failed', {'error': str(e)})
            continue
    
    return cpanel_info

def discover_api_endpoints(host, port, user, password):
    """Discover available API endpoints and their capabilities"""
    api_endpoints = []
    
    # Test various API endpoints
    endpoints_to_test = [
        # Softaculous endpoints
        {'path': '/frontend/jupiter/softaculous/index.live.php', 'type': 'softaculous', 'method': 'GET'},
        {'path': '/frontend/paper_lantern/softaculous/index.live.php', 'type': 'softaculous', 'method': 'GET'},
        {'path': '/softaculous/index.php', 'type': 'softaculous', 'method': 'GET'},
        
        # cPanel API endpoints
        {'path': '/execute/Fileman/list_files', 'type': 'cpanel_uapi', 'method': 'GET'},
        {'path': '/json-api/cpanel', 'type': 'cpanel_json', 'method': 'GET'},
        {'path': '/frontend/jupiter/filemanager/', 'type': 'file_manager', 'method': 'GET'},
        
        # WordPress specific
        {'path': '/wp-admin/', 'type': 'wordpress', 'method': 'GET'},
        {'path': '/xmlrpc.php', 'type': 'wordpress_xmlrpc', 'method': 'POST'}
    ]
    
    for endpoint in endpoints_to_test:
        try:
            url = f"https://{host}:{port}{endpoint['path']}"
            
            if endpoint['method'] == 'GET':
                response = requests.get(
                    url,
                    auth=(user, password),
                    verify=False,
                    timeout=10
                )
            else:
                response = requests.post(
                    url,
                    auth=(user, password),
                    verify=False,
                    timeout=10
                )
            
            endpoint_info = {
                'path': endpoint['path'],
                'type': endpoint['type'],
                'status_code': response.status_code,
                'content_type': response.headers.get('content-type', ''),
                'accessible': response.status_code in [200, 401, 403],  # 401/403 means exists but needs auth
                'response_size': len(response.content)
            }
            
            # Analyze response content
            if response.status_code == 200:
                content = response.text.lower()
                endpoint_info['contains_html'] = 'html' in content
                endpoint_info['contains_json'] = content.strip().startswith('{')
                endpoint_info['contains_xml'] = content.strip().startswith('<') and 'xml' in content
                endpoint_info['softaculous_detected'] = 'softaculous' in content
                endpoint_info['wordpress_detected'] = 'wordpress' in content or 'wp-' in content
            
            api_endpoints.append(endpoint_info)
            
        except Exception as e:
            api_endpoints.append({
                'path': endpoint['path'],
                'type': endpoint['type'],
                'error': str(e),
                'accessible': False
            })
    
    return api_endpoints

def test_authentication_methods(host, port, user, password):
    """Test different authentication methods"""
    auth_methods = []
    
    test_url = f"https://{host}:{port}/frontend/jupiter/"
    
    # 1. HTTP Basic Auth
    try:
        response = requests.get(
            test_url,
            auth=(user, password),
            verify=False,
            timeout=10
        )
        auth_methods.append({
            'method': 'HTTP Basic Auth',
            'status_code': response.status_code,
            'working': response.status_code in [200, 302],
            'headers': dict(response.headers)
        })
    except Exception as e:
        auth_methods.append({
            'method': 'HTTP Basic Auth',
            'error': str(e),
            'working': False
        })
    
    # 2. URL-embedded credentials
    try:
        url_with_creds = f"https://{user}:{password}@{host}:{port}/frontend/jupiter/"
        response = requests.get(
            url_with_creds,
            verify=False,
            timeout=10
        )
        auth_methods.append({
            'method': 'URL-embedded credentials',
            'status_code': response.status_code,
            'working': response.status_code in [200, 302],
            'headers': dict(response.headers)
        })
    except Exception as e:
        auth_methods.append({
            'method': 'URL-embedded credentials',
            'error': str(e),
            'working': False
        })
    
    # 3. Authorization header
    try:
        headers = {
            'Authorization': f'Basic {base64.b64encode(f"{user}:{password}".encode()).decode()}'
        }
        response = requests.get(
            test_url,
            headers=headers,
            verify=False,
            timeout=10
        )
        auth_methods.append({
            'method': 'Authorization header',
            'status_code': response.status_code,
            'working': response.status_code in [200, 302],
            'headers': dict(response.headers)
        })
    except Exception as e:
        auth_methods.append({
            'method': 'Authorization header',
            'error': str(e),
            'working': False
        })
    
    return auth_methods

def detect_softaculous_configuration(host, port, user, password):
    """Detect Softaculous installation and configuration"""
    softaculous_info = {
        'installed': False,
        'version': 'unknown',
        'accessible_paths': [],
        'supported_apis': [],
        'wordpress_support': False
    }
    
    # Test Softaculous paths
    softaculous_paths = A2_HOSTING_CONFIG['softaculous_paths']
    
    for path in softaculous_paths:
        try:
            # Test different API formats
            for api_format in ['json', 'serialize', 'xml']:
                url = f"https://{host}:{port}{path}"
                params = {'act': 'home', 'api': api_format}
                
                response = requests.get(
                    url,
                    params=params,
                    auth=(user, password),
                    verify=False,
                    timeout=15
                )
                
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '').lower()
                    
                    # Check if we got API data instead of HTML
                    if 'text/html' not in content_type or not response.text.strip().startswith('<!DOCTYPE'):
                        softaculous_info['installed'] = True
                        softaculous_info['accessible_paths'].append(path)
                        softaculous_info['supported_apis'].append(api_format)
                        
                        # Try to parse version and capabilities
                        try:
                            if api_format == 'json':
                                data = json.loads(response.text)
                                if 'version' in data:
                                    softaculous_info['version'] = data['version']
                                if 'wordpress' in str(data).lower():
                                    softaculous_info['wordpress_support'] = True
                            
                            elif api_format == 'serialize':
                                try:
                                    import phpserialize
                                    data = phpserialize.loads(response.content)
                                    if isinstance(data, dict):
                                        if b'version' in data or 'version' in data:
                                            softaculous_info['version'] = str(data.get('version', data.get(b'version', 'unknown')))
                                        if b'wordpress' in str(data).lower().encode() or 'wordpress' in str(data).lower():
                                            softaculous_info['wordpress_support'] = True
                                except ImportError:
                                    st.warning("⚠️ phpserialize library not available - some API formats may not work")
                        
                        except Exception as parse_error:
                            enhanced_logger.log_diagnostic('SOFTACULOUS_PARSE', f'Parse error for {api_format}', {'error': str(parse_error)})
                    
                    # Log the response for analysis
                    enhanced_logger.log_api_detailed(
                        {'url': url, 'params': params, 'auth_method': 'basic'},
                        {'status_code': response.status_code, 'content_type': content_type, 'size': len(response.content)},
                        None if response.status_code == 200 else 'Non-200 status'
                    )
        
        except Exception as e:
            enhanced_logger.log_diagnostic('SOFTACULOUS_TEST', f'Path {path} failed', {'error': str(e)})
            continue
    
    return softaculous_info

# --- Enhanced Softaculous API Functions ---
def make_enhanced_softaculous_request(act, post_data=None, additional_params=None):
    """
    Enhanced Softaculous API request with comprehensive diagnostics and fallbacks
    """
    start_time = datetime.datetime.now()
    
    if 'credentials' not in st.session_state:
        return None, "Not authenticated"
    
    creds = st.session_state.credentials
    
    # Rate limiting
    if creds.get('rate_limits', True):
        if 'last_api_call' in st.session_state:
            time_since_last = (datetime.datetime.now() - st.session_state.last_api_call).total_seconds()
            if time_since_last < 2:
                time.sleep(2 - time_since_last)
        st.session_state.last_api_call = datetime.datetime.now()
    
    # Get server analysis if available
    server_analysis = st.session_state.get('server_analysis', {})
    
    # Use discovered working paths if available
    if server_analysis.get('softaculous', {}).get('accessible_paths'):
        paths_to_try = server_analysis['softaculous']['accessible_paths']
    else:
        paths_to_try = A2_HOSTING_CONFIG['softaculous_paths']
    
    # Use discovered working API formats if available
    if server_analysis.get('softaculous', {}).get('supported_apis'):
        api_formats_to_try = server_analysis['softaculous']['supported_apis']
    else:
        api_formats_to_try = A2_HOSTING_CONFIG['api_formats']
    
    # Use discovered working auth methods if available
    working_auth_methods = [method for method in server_analysis.get('authentication_methods', []) if method.get('working')]
    
    for path_index, softaculous_path in enumerate(paths_to_try):
        for format_index, api_format in enumerate(api_formats_to_try):
            for auth_index, auth_method in enumerate(['basic', 'url', 'header']):
                
                # Prepare URL and authentication
                if auth_method == 'url':
                    base_url = f"https://{creds['user']}:{creds['pass']}@{creds['host']}:{creds['port']}{softaculous_path}"
                    auth = None
                    headers = {'User-Agent': 'A2-WordPress-Manager/2.0'}
                else:
                    base_url = f"https://{creds['host']}:{creds['port']}{softaculous_path}"
                    auth = (creds['user'], creds['pass'])
                    headers = {'User-Agent': 'A2-WordPress-Manager/2.0'}
                    
                    if auth_method == 'header':
                        headers['Authorization'] = f'Basic {base64.b64encode(f"{creds["user"]}:{creds["pass"]}".encode()).decode()}'
                        auth = None
                
                # Prepare parameters
                params = {
                    'act': act,
                    'api': api_format
                }
                
                if additional_params:
                    params.update(additional_params)
                
                # Add debug information
                if st.session_state.get('debug_mode', False):
                    st.write(f"🔍 **Attempt {path_index+1}.{format_index+1}.{auth_index+1}**: Path: `{softaculous_path}`, Format: `{api_format}`, Auth: `{auth_method}`")
                
                try:
                    # Make the request
                    if post_data:
                        response = requests.post(
                            base_url,
                            params=params,
                            data=post_data,
                            headers=headers,
                            auth=auth,
                            verify=False,
                            timeout=60
                        )
                    else:
                        response = requests.get(
                            base_url,
                            params=params,
                            headers=headers,
                            auth=auth,
                            verify=False,
                            timeout=60
                        )
                    
                    response_time = (datetime.datetime.now() - start_time).total_seconds()
                    
                    # Log detailed request/response
                    request_info = {
                        'url': base_url,
                        'params': params,
                        'auth_method': auth_method,
                        'headers': headers,
                        'post_data': bool(post_data)
                    }
                    
                    response_info = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'content_type': response.headers.get('content-type', ''),
                        'content_length': len(response.content),
                        'response_time': response_time
                    }
                    
                    if st.session_state.get('debug_mode', False):
                        st.write(f"📊 **Status**: {response.status_code}, **Time**: {response_time:.2f}s, **Size**: {len(response.content)} bytes")
                        st.write(f"📋 **Content-Type**: {response.headers.get('content-type', 'Unknown')}")
                    
                    if response.status_code == 200:
                        # Check if we got HTML (login page) instead of API data
                        content_type = response.headers.get('content-type', '').lower()
                        response_text = response.content.decode('utf-8', errors='ignore')
                        
                        # Detailed content analysis
                        is_html = ('text/html' in content_type or 
                                 response_text.strip().startswith('<!DOCTYPE') or
                                 response_text.strip().startswith('<html'))
                        
                        if is_html:
                            if st.session_state.get('debug_mode', False):
                                st.write(f"❌ **Got HTML instead of API data**")
                                # Show first 500 chars of HTML for analysis
                                st.code(response_text[:500] + "..." if len(response_text) > 500 else response_text)
                            
                            enhanced_logger.log_api_detailed(request_info, response_info, 'HTML_RESPONSE_INSTEAD_OF_API')
                            continue  # Try next combination
                        
                        # Try to parse based on API format
                        try:
                            if api_format == 'json':
                                # Try to find JSON in response
                                json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                                if json_match:
                                    result = json.loads(json_match.group())
                                else:
                                    result = json.loads(response_text)
                            
                            elif api_format == 'serialize':
                                try:
                                    import phpserialize
                                    result = phpserialize.loads(response.content)
                                except ImportError:
                                    if st.session_state.get('debug_mode', False):
                                        st.error("❌ **phpserialize library not available**")
                                    continue
                            
                            elif api_format == 'xml':
                                result = ET.fromstring(response_text)
                            
                            else:
                                result = response_text
                            
                            # Success!
                            if st.session_state.get('debug_mode', False):
                                st.success(f"✅ **SUCCESS!** Path: `{softaculous_path}`, Format: `{api_format}`, Auth: `{auth_method}`")
                                st.write(f"📋 **Result type**: {type(result)}")
                                if isinstance(result, dict):
                                    st.write(f"🔑 **Keys**: {list(result.keys())[:10]}...")  # Show first 10 keys
                            
                            enhanced_logger.log_api_detailed(request_info, response_info, None)
                            
                            # Store working configuration for future use
                            st.session_state.working_api_config = {
                                'path': softaculous_path,
                                'format': api_format,
                                'auth_method': auth_method
                            }
                            
                            return result, None
                        
                        except Exception as parse_error:
                            if st.session_state.get('debug_mode', False):
                                st.write(f"❌ **Parse Error**: {str(parse_error)}")
                                st.code(response_text[:300] + "..." if len(response_text) > 300 else response_text)
                            
                            enhanced_logger.log_api_detailed(request_info, response_info, f'PARSE_ERROR: {str(parse_error)}')
                            continue
                    
                    else:
                        if st.session_state.get('debug_mode', False):
                            st.write(f"❌ **HTTP {response.status_code}**")
                        
                        enhanced_logger.log_api_detailed(request_info, response_info, f'HTTP_{response.status_code}')
                        
                        # If it's a client error, don't try other auth methods for this path/format
                        if 400 <= response.status_code < 500:
                            break
                
                except Exception as e:
                    if st.session_state.get('debug_mode', False):
                        st.write(f"❌ **Connection Error**: {str(e)}")
                    
                    enhanced_logger.log_diagnostic('API_CONNECTION_ERROR', str(e), {
                        'path': softaculous_path,
                        'format': api_format,
                        'auth_method': auth_method
                    })
                    continue
    
    # If we get here, all combinations failed
    total_attempts = len(paths_to_try) * len(api_formats_to_try) * 3  # 3 auth methods
    error_message = f"All {total_attempts} API combinations failed. Server may have custom Softaculous configuration."
    
    enhanced_logger.log_diagnostic('API_EXHAUSTED', error_message, {
        'paths_tried': paths_to_try,
        'formats_tried': api_formats_to_try,
        'total_attempts': total_attempts
    })
    
    return None, error_message

def enhanced_wordpress_discovery():
    """Enhanced WordPress discovery with comprehensive fallback methods"""
    
    st.write("🔍 **Starting enhanced WordPress discovery...**")
    
    # Method 1: Enhanced Softaculous API
    st.write("📡 **Method 1: Enhanced Softaculous API**")
    installations = try_softaculous_discovery()
    if installations:
        st.success(f"✅ Found {len(installations)} WordPress installations via Softaculous API")
        return installations, None
    
    # Method 2: cPanel File Manager API
    st.write("📁 **Method 2: cPanel File Manager API**")
    installations = try_cpanel_file_discovery()
    if installations:
        st.success(f"✅ Found {len(installations)} WordPress installations via cPanel API")
        return installations, None
    
    # Method 3: Direct file system scanning (if accessible)
    st.write("🔍 **Method 3: Direct file system scanning**")
    installations = try_direct_file_scanning()
    if installations:
        st.success(f"✅ Found {len(installations)} WordPress installations via file scanning")
        return installations, None
    
    # Method 4: WordPress database detection
    st.write("💾 **Method 4: Database-based detection**")
    installations = try_database_detection()
    if installations:
        st.success(f"✅ Found {len(installations)} WordPress installations via database detection")
        return installations, None
    
    # Method 5: Manual discovery assistance
    st.write("🔧 **Method 5: Manual discovery assistance**")
    show_manual_discovery_assistant()
    
    return [], "Automated discovery methods exhausted. Please use manual discovery assistant."

def try_softaculous_discovery():
    """Try to discover WordPress installations via Softaculous API"""
    endpoints_to_try = [
        ('wordpress', {}),
        ('software', {'softwareid': '26'}),
        ('installations', {}),
        ('list', {}),
        ('home', {}),
        ('software', {'software': 'wordpress'}),
        ('list', {'type': 'wordpress'}),
        ('apps', {}),
    ]
    
    for act, extra_params in endpoints_to_try:
        if st.session_state.get('debug_mode', False):
            st.write(f"🔍 **Trying Softaculous endpoint**: `{act}` with params: `{extra_params}`")
        
        result, error = make_enhanced_softaculous_request(act, additional_params=extra_params)
        
        if not error and result:
            installations = extract_installations_from_result(result)
            if installations:
                return installations
            
            if st.session_state.get('debug_mode', False):
                st.write(f"📋 **Result structure**: {type(result)}")
                if isinstance(result, dict):
                    st.write(f"🔑 **Keys**: {list(result.keys())}")
                    # Show some sample data
                    for key, value in list(result.items())[:3]:
                        st.write(f"  - `{key}`: {type(value)} - {str(value)[:100]}...")
        
        elif st.session_state.get('debug_mode', False):
            st.write(f"❌ **Endpoint `{act}` failed**: {error}")
    
    return []

def try_cpanel_file_discovery():
    """Try to discover WordPress installations via cPanel File Manager API"""
    # This would require cPanel UAPI access
    # Implementation would depend on specific cPanel API availability
    return []

def try_direct_file_scanning():
    """Try to discover WordPress installations by scanning file system"""
    # This would require direct file system access
    # Implementation would depend on server permissions
    return []

def try_database_detection():
    """Try to discover WordPress installations by scanning databases"""
    # This would require database access
    # Implementation would depend on MySQL/database permissions
    return []

def show_manual_discovery_assistant():
    """Show comprehensive manual discovery assistance"""
    
    st.write("🛠️ **Manual WordPress Discovery Assistant**")
    
    with st.expander("📋 **Step-by-Step WordPress Discovery Guide**", expanded=True):
        st.markdown("""
        ### 🔍 **How to Find Your WordPress Installations Manually**
        
        #### **Method 1: cPanel File Manager**
        1. **Log into your cPanel** (same credentials as used here)
        2. **Open "File Manager"**
        3. **Navigate to `public_html`** (your main domain folder)
        4. **Look for these WordPress indicators**:
           - `wp-config.php` file
           - `wp-content/` directory
           - `wp-admin/` directory
           - `wp-includes/` directory
        
        #### **Method 2: Check Softaculous Directly**
        1. **In cPanel, find "Softaculous Apps Installer"**
        2. **Click on it**
        3. **Look for "Current Installations" or "My Apps"**
        4. **Note down all WordPress installations**
        
        #### **Method 3: Domain/Subdomain Check**
        1. **Visit your domains directly**:
           - `https://yourdomain.com/wp-admin/` 
           - `https://subdomain.yourdomain.com/wp-admin/`
           - `https://yourdomain.com/blog/wp-admin/`
           - `https://yourdomain.com/wordpress/wp-admin/`
        2. **If you see a WordPress login page, that's a WordPress site!**
        
        #### **Method 4: Database Check**
        1. **In cPanel, open "phpMyAdmin"**
        2. **Look for databases with names containing**: `wp_`, `wordpress`, or your domain name
        3. **Each WordPress database typically has tables like**: `wp_posts`, `wp_users`, `wp_options`
        """)
    
    # Manual entry form
    with st.expander("📝 **Manual WordPress Site Entry**", expanded=True):
        st.markdown("**Found WordPress sites? Enter them manually below:**")
        
        # Initialize manual sites in session state
        if 'manual_sites' not in st.session_state:
            st.session_state.manual_sites = []
        
        # Form for adding new site
        with st.form("add_manual_site"):
            st.subheader("➕ Add WordPress Site")
            
            col1, col2 = st.columns(2)
            
            with col1:
                domain = st.text_input(
                    "Domain", 
                    placeholder="example.com",
                    help="Main domain name (without http:// or www)"
                )
                path = st.text_input(
                    "Path", 
                    placeholder="/wordpress/ or /",
                    value="/",
                    help="Path where WordPress is installed (usually / for root)"
                )
            
            with col2:
                version = st.text_input(
                    "WordPress Version", 
                    placeholder="6.4.1",
                    help="WordPress version (check in wp-admin or leave blank)"
                )
                admin_url = st.text_input(
                    "Admin URL", 
                    placeholder="https://example.com/wp-admin/",
                    help="Full URL to WordPress admin (for verification)"
                )
            
            notes = st.text_area(
                "Notes", 
                placeholder="Any additional notes about this installation...",
                help="Optional notes for your reference"
            )
            
            if st.form_submit_button("➕ Add Site", type="primary"):
                if domain:
                    new_site = {
                        'insid': f"manual_{len(st.session_state.manual_sites)}",
                        'domain': domain.strip(),
                        'path': path.strip() or "/",
                        'version': version.strip() or "Unknown",
                        'user': st.session_state.credentials['user'],
                        'display_name': f"{domain.strip()}{path.strip() or '/'}",
                        'admin_url': admin_url.strip(),
                        'notes': notes.strip(),
                        'manual_entry': True,
                        'added_timestamp': datetime.datetime.now().isoformat()
                    }
                    
                    st.session_state.manual_sites.append(new_site)
                    st.success(f"✅ Added WordPress site: {new_site['display_name']}")
                    
                    # Log manual addition
                    enhanced_logger.log_diagnostic('MANUAL_SITE_ADDED', 'User manually added WordPress site', new_site)
                else:
                    st.error("❌ Please enter at least a domain name")
        
        # Show current manual sites
        if st.session_state.manual_sites:
            st.subheader("📋 Manually Added Sites")
            
            for i, site in enumerate(st.session_state.manual_sites):
                with st.container():
                    col1, col2, col3 = st.columns([3, 1, 1])
                    
                    with col1:
                        st.write(f"**{site['display_name']}** (v{site['version']})")
                        if site.get('admin_url'):
                            st.write(f"🔗 [Admin Panel]({site['admin_url']})")
                        if site.get('notes'):
                            st.write(f"📝 {site['notes']}")
                    
                    with col2:
                        if st.button(f"🧪 Test", key=f"test_{i}"):
                            test_wordpress_site(site)
                    
                    with col3:
                        if st.button(f"🗑️ Remove", key=f"remove_{i}"):
                            st.session_state.manual_sites.pop(i)
                            st.rerun()
            
            # Action buttons for manual sites
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("✅ Use These Sites", type="primary"):
                    st.session_state.installations = st.session_state.manual_sites.copy()
                    st.success(f"✅ Using {len(st.session_state.manual_sites)} manually added sites!")
                    
                    # Log bulk manual addition
                    enhanced_logger.log_diagnostic('MANUAL_SITES_ACTIVATED', 
                                                 f'User activated {len(st.session_state.manual_sites)} manual sites',
                                                 {'sites': st.session_state.manual_sites})
                    st.rerun()
            
            with col2:
                if st.button("🗑️ Clear All"):
                    st.session_state.manual_sites = []
                    st.rerun()

def test_wordpress_site(site):
    """Test if a manually entered WordPress site is accessible"""
    try:
        # Test wp-admin access
        admin_url = site.get('admin_url') or f"https://{site['domain']}{site['path']}wp-admin/"
        
        response = requests.get(admin_url, verify=False, timeout=10)
        
        if response.status_code == 200:
            if 'wp-login' in response.text.lower() or 'wordpress' in response.text.lower():
                st.success(f"✅ WordPress site confirmed at {admin_url}")
                return True
            else:
                st.warning(f"⚠️ Site accessible but doesn't look like WordPress: {admin_url}")
        else:
            st.error(f"❌ Site not accessible (HTTP {response.status_code}): {admin_url}")
        
        return False
        
    except Exception as e:
        st.error(f"❌ Error testing site: {str(e)}")
        return False

def extract_installations_from_result(result):
    """Enhanced extraction of WordPress installations from API responses"""
    installations = []
    
    if st.session_state.get('debug_mode', False):
        st.write(f"🔍 **Analyzing result structure**: {type(result)}")
    
    try:
        if isinstance(result, dict):
            # Try different possible keys where installations might be stored
            possible_keys = [
                'installations', 'data', 'result', 'software', 'wordpress', 
                'apps', 'sites', 'domains', 'list', 'items', 'records'
            ]
            
            for key in possible_keys:
                if key in result:
                    data = result[key]
                    if st.session_state.get('debug_mode', False):
                        st.write(f"🔑 **Found key `{key}`**: {type(data)}")
                    
                    if isinstance(data, dict):
                        for insid, install_data in data.items():
                            if isinstance(install_data, dict):
                                installation = create_installation_object(insid, install_data)
                                if installation and installation.get('domain'):
                                    installations.append(installation)
                                    if st.session_state.get('debug_mode', False):
                                        st.write(f"✅ **Extracted installation**: {installation.get('display_name')}")
                    
                    elif isinstance(data, list):
                        for i, install_data in enumerate(data):
                            if isinstance(install_data, dict):
                                installation = create_installation_object(f"list_{i}", install_data)
                                if installation and installation.get('domain'):
                                    installations.append(installation)
                                    if st.session_state.get('debug_mode', False):
                                        st.write(f"✅ **Extracted installation**: {installation.get('display_name')}")
        
        elif isinstance(result, list):
            for i, item in enumerate(result):
                if isinstance(item, dict):
                    installation = create_installation_object(f"item_{i}", item)
                    if installation and installation.get('domain'):
                        installations.append(installation)
                        if st.session_state.get('debug_mode', False):
                            st.write(f"✅ **Extracted installation**: {installation.get('display_name')}")
    
    except Exception as e:
        if st.session_state.get('debug_mode', False):
            st.write(f"❌ **Error extracting installations**: {str(e)}")
        enhanced_logger.log_diagnostic('EXTRACTION_ERROR', str(e), {'result_type': type(result)})
    
    return installations

def create_installation_object(insid, install_data):
    """Create standardized installation object with enhanced field mapping"""
    
    # Map various possible field names to standard fields
    field_mappings = {
        'domain': ['softurl', 'domain', 'site_url', 'url', 'host', 'hostname'],
        'path': ['softpath', 'path', 'directory', 'softdirectory', 'folder'],
        'version': ['ver', 'version', 'wp_version', 'wordpress_version'],
        'user': ['cuser', 'user', 'owner', 'username'],
        'display_name': ['display_name', 'name', 'title', 'site_name']
    }
    
    installation = {'insid': str(insid)}
    
    for field, possible_keys in field_mappings.items():
        value = None
        for key in possible_keys:
            if key in install_data:
                value = install_data[key]
                break
        
        if value:
            installation[field] = str(value).strip()
    
    # Generate display name if not found
    if not installation.get('display_name') and installation.get('domain'):
        path = installation.get('path', '/')
        installation['display_name'] = f"{installation['domain']}{path if path != '/' else ''}"
    
    # Validate that we have minimum required fields
    if not installation.get('domain'):
        return None
    
    # Set defaults
    installation.setdefault('path', '/')
    installation.setdefault('version', 'Unknown')
    installation.setdefault('user', st.session_state.credentials.get('user', 'Unknown'))
    
    return installation

# --- Enhanced Login Screen ---
def show_enhanced_login_screen():
    """Enhanced login screen with comprehensive server analysis"""
    st.title("🔐 Enhanced A2 Hosting WordPress Manager")
    st.markdown("### Connect to your A2 Hosting cPanel account with advanced diagnostics")
    
    # Add enhanced information
    st.info("💡 **Enhanced Version**: This version includes comprehensive server analysis and advanced troubleshooting capabilities")
    
    with st.expander("🔍 What's New in Enhanced Version"):
        st.markdown("""
        ### 🚀 Enhanced Features:
        
        - **🔍 Comprehensive Server Analysis**: Automatic detection of hosting configuration
        - **🧪 Multi-Path API Testing**: Tests multiple Softaculous paths and formats
        - **🔐 Authentication Method Testing**: Tests different authentication approaches
        - **📊 Detailed Diagnostics**: Complete API request/response logging
        - **🛠️ Advanced Troubleshooting**: Step-by-step problem identification
        - **📝 Manual Entry Assistant**: Guided manual WordPress site discovery
        - **💾 Enhanced Logging**: Detailed logs for support purposes
        """)
    
    with st.form("enhanced_login_form"):
        st.subheader("📋 cPanel Credentials")
        
        col1, col2 = st.columns(2)
        
        with col1:
            host = st.text_input(
                "cPanel Host", 
                placeholder="server.clasit.org",
                help="Your cPanel server hostname"
            )
            
            user = st.text_input(
                "cPanel Username", 
                placeholder="your_username",
                help="Your cPanel username"
            )
        
        with col2:
            port = st.selectbox(
                "Port", 
                ["2083", "2082"], 
                index=0,
                help="Usually 2083 for secure connections"
            )
            
            password = st.text_input(
                "cPanel Password", 
                type="password",
                help="Your cPanel password"
            )
        
        # Enhanced options
        st.subheader("🔧 Enhanced Options")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            run_server_analysis = st.checkbox(
                "Run server analysis", 
                value=True,
                help="Analyze server configuration and capabilities"
            )
        
        with col2:
            enable_debug_mode = st.checkbox(
                "Enable debug mode", 
                value=True,
                help="Show detailed API request/response information"
            )
        
        with col3:
            respect_rate_limits = st.checkbox(
                "Respect rate limits", 
                value=True,
                help="Add delays between API calls"
            )
        
        submit = st.form_submit_button("🔍 Connect & Analyze", type="primary")
        
        if submit:
            if not all([host, user, password]):
                st.error("❌ Please fill in all cPanel credentials")
                return
            
            # Store credentials and settings
            st.session_state.credentials = {
                'host': host,
                'port': port,
                'user': user,
                'pass': password,
                'rate_limits': respect_rate_limits
            }
            
            st.session_state.debug_mode = enable_debug_mode
            
            # Run server analysis if requested
            if run_server_analysis:
                with st.spinner("🔍 Running comprehensive server analysis..."):
                    analysis_results = analyze_server_configuration(host, port, user, password)
                    st.session_state.server_analysis = analysis_results
                    
                    # Show analysis results
                    show_server_analysis_results(analysis_results)
            
            # Test basic authentication
            with st.spinner("🔐 Testing authentication..."):
                auth_success = test_basic_authentication(host, port, user, password)
                
                if auth_success:
                    st.success("✅ Authentication successful! Proceeding to WordPress discovery...")
                    enhanced_logger.log_diagnostic('AUTH_SUCCESS', 'Enhanced login successful', {
                        'host': host, 'port': port, 'analysis_run': run_server_analysis
                    })
                    st.rerun()
                else:
                    st.error("❌ Authentication failed. Please check your credentials.")
                    return

def show_server_analysis_results(analysis_results):
    """Display comprehensive server analysis results"""
    
    st.subheader("📊 Server Analysis Results")
    
    # Basic info
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Hosting Provider", analysis_results.get('hosting_provider', 'Unknown'))
    
    with col2:
        st.metric("Server Type", analysis_results.get('server_type', 'Unknown'))
    
    with col3:
        st.metric("cPanel Version", analysis_results.get('cpanel_version', 'Unknown'))
    
    # Detailed results in expandable sections
    with st.expander("🔒 SSL/Certificate Information"):
        ssl_info = analysis_results.get('ssl_info', {})
        if ssl_info.get('error'):
            st.warning(f"SSL Issue: {ssl_info['error']}")
        else:
            st.json(ssl_info)
    
    with st.expander("🔐 Authentication Methods"):
        auth_methods = analysis_results.get('authentication_methods', [])
        for method in auth_methods:
            if method.get('working'):
                st.success(f"✅ {method['method']} - Working")
            else:
                st.error(f"❌ {method['method']} - Failed")
    
    with st.expander("🔍 Available API Endpoints"):
        api_endpoints = analysis_results.get('available_apis', [])
        for endpoint in api_endpoints:
            status = "✅" if endpoint.get('accessible') else "❌"
            st.write(f"{status} {endpoint['path']} ({endpoint['type']}) - Status: {endpoint.get('status_code', 'Error')}")
    
    with st.expander("⚙️ Softaculous Configuration"):
        softaculous_info = analysis_results.get('softaculous', {})
        if softaculous_info.get('installed'):
            st.success("✅ Softaculous is installed and accessible")
            st.write(f"**Version**: {softaculous_info.get('version', 'Unknown')}")
            st.write(f"**Accessible Paths**: {len(softaculous_info.get('accessible_paths', []))}")
            st.write(f"**Supported APIs**: {', '.join(softaculous_info.get('supported_apis', []))}")
            st.write(f"**WordPress Support**: {'✅ Yes' if softaculous_info.get('wordpress_support') else '❌ Unknown'}")
        else:
            st.error("❌ Softaculous not detected or not accessible")

def test_basic_authentication(host, port, user, password):
    """Test basic authentication to cPanel"""
    try:
        url = f"https://{host}:{port}/frontend/jupiter/"
        response = requests.get(
            url,
            auth=(user, password),
            verify=False,
            timeout=15
        )
        
        return response.status_code in [200, 302]
    
    except Exception as e:
        enhanced_logger.log_diagnostic('AUTH_TEST_ERROR', str(e), {
            'host': host, 'port': port
        })
        return False

# --- Enhanced Main Application ---
def show_enhanced_main_app():
    """Enhanced main application with comprehensive diagnostics"""
    
    # Enhanced sidebar with detailed info
    with st.sidebar:
        st.markdown("### 🔐 Session Info")
        creds = st.session_state.credentials
        st.write(f"**Host:** {creds['host']}")
        st.write(f"**User:** {creds['user']}")
        st.write(f"**Port:** {creds['port']}")
        
        # Show server analysis summary if available
        if 'server_analysis' in st.session_state:
            analysis = st.session_state.server_analysis
            st.markdown("### 📊 Server Info")
            st.write(f"**Provider:** {analysis.get('hosting_provider', 'Unknown')}")
            st.write(f"**Type:** {analysis.get('server_type', 'Unknown')}")
            
            if analysis.get('softaculous', {}).get('installed'):
                st.success("✅ Softaculous Available")
            else:
                st.error("❌ Softaculous Issues")
        
        # Debug controls
        st.markdown("### 🔧 Debug Controls")
        st.session_state.debug_mode = st.checkbox("Debug Mode", value=st.session_state.get('debug_mode', False))
        
        if st.button("🔍 Re-run Server Analysis"):
            with st.spinner("Running server analysis..."):
                analysis_results = analyze_server_configuration(
                    creds['host'], creds['port'], creds['user'], creds['pass']
                )
                st.session_state.server_analysis = analysis_results
                st.rerun()
        
        # Working configuration display
        if 'working_api_config' in st.session_state:
            st.markdown("### ✅ Working API Config")
            config = st.session_state.working_api_config
            st.code(f"""
Path: {config['path']}
Format: {config['format']}
Auth: {config['auth_method']}
            """)
        
        st.markdown("---")
        if st.button("🚪 Logout"):
            # Clear all session state
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    
    # Initialize installations if not present
    if 'installations' not in st.session_state:
        st.session_state.installations = []
    
    # WordPress discovery
    if not st.session_state.installations:
        st.header("🔍 WordPress Discovery")
        
        with st.spinner("🔍 Discovering WordPress installations..."):
            installations, error = enhanced_wordpress_discovery()
            
            if installations:
                st.session_state.installations = installations
                st.success(f"✅ Found {len(installations)} WordPress installations!")
                
                # Show installations
                for installation in installations:
                    st.write(f"• {installation['display_name']} (v{installation['version']})")
            
            elif error:
                st.error(f"❌ WordPress discovery failed: {error}")
                st.info("💡 Please use the manual discovery assistant above to add your WordPress sites.")
            
            else:
                st.info("ℹ️ No WordPress installations found automatically. Please use manual discovery.")
    
    # Main application continues here...
    if st.session_state.installations:
        st.header("🎉 WordPress Sites Ready!")
        st.write(f"Found {len(st.session_state.installations)} WordPress installations")
        
        # Show sites
        for installation in st.session_state.installations:
            with st.expander(f"📝 {installation['display_name']}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Domain:** {installation['domain']}")
                    st.write(f"**Path:** {installation['path']}")
                with col2:
                    st.write(f"**Version:** {installation['version']}")
                    st.write(f"**User:** {installation['user']}")
                
                if installation.get('admin_url'):
                    st.write(f"🔗 [Admin Panel]({installation['admin_url']})")

# --- Main Application Entry Point ---
def main():
    """Enhanced main application entry point"""
    
    st.set_page_config(
        page_title="Enhanced A2 Hosting WordPress Manager", 
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Initialize session state
    if 'session_id' not in st.session_state:
        st.session_state.session_id = hashlib.md5(
            f"{datetime.datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
    
    # Always show header
    st.title("🔧 Enhanced A2 Hosting WordPress Manager")
    st.markdown("### Advanced WordPress Management with Comprehensive Diagnostics")
    
    # Instructions
    with st.expander("📖 Enhanced Instructions & Features"):
        st.markdown("""
        # 🎉 Enhanced A2 Hosting WordPress Manager
        
        ## 🚀 What's New:
        - **🔍 Comprehensive Server Analysis**: Automatic detection of your hosting configuration
        - **🧪 Multi-Path Testing**: Tests multiple Softaculous API paths and formats
        - **🔐 Authentication Testing**: Tries different authentication methods
        - **📊 Detailed Diagnostics**: Complete logging of all API attempts
        - **🛠️ Advanced Troubleshooting**: Step-by-step problem identification
        - **📝 Manual Discovery**: Guided process for manual WordPress site entry
        
        ## 🎯 Perfect for:
        - **A2 Hosting customers** (direct and reseller accounts)
        - **Troubleshooting API issues** with comprehensive diagnostics
        - **Server configuration analysis** and optimization
        - **Manual WordPress site management** when automation fails
        
        ## 🔧 How to Use:
        1. **Enter your cPanel credentials** (same as cPanel login)
        2. **Enable server analysis** for comprehensive diagnostics
        3. **Review analysis results** to understand your server configuration
        4. **Let the tool discover WordPress sites** or add them manually
        5. **Manage your WordPress installations** with confidence
        """)
    
    st.markdown("---")
    
    # Main application logic
    if 'credentials' not in st.session_state:
        show_enhanced_login_screen()
    else:
        show_enhanced_main_app()

if __name__ == "__main__":
    main()
