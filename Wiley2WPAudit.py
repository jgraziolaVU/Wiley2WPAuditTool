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
import re
from urllib.parse import urlparse
import warnings

# Suppress SSL warnings for self-signed certificates (common with hosting providers)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
LOCAL_BACKUP_DIR = Path("./backups")
DOWNLOADS_DIR = Path("./downloads")
LOGS_DIR = Path("./logs")

# Ensure directories exist
LOCAL_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Enhanced A2 Hosting configuration
A2_HOSTING_CONFIG = {
    'default_ports': {'secure': '2083', 'non_secure': '2082'},
    'softaculous_paths': [
        '/frontend/jupiter/softaculous/index.live.php',
        '/frontend/paper_lantern/softaculous/index.live.php', 
        '/frontend/x3/softaculous/index.live.php',
        '/softaculous/index.php',
        '/cpanel/softaculous/index.php',
        '/frontend/jupiter/softaculous/',
        '/frontend/jupiter/softaculous/index.php',
        '/3rdparty/softaculous/index.php',
        '/softaculous/',
        '/cgi-bin/softaculous/index.php'
    ],
    'api_formats': ['json', 'serialize'],
    'auth_methods': ['basic', 'url', 'header'],
    'request_timeout': 30,
    'max_retries': 3
}

class SimpleLogger:
    """Simplified logging class that doesn't require external dependencies"""
    
    def __init__(self):
        self.log_file = LOGS_DIR / f"wordpress_manager_{datetime.datetime.now().strftime('%Y%m%d')}.log"
        
    def log(self, level, message, details=None):
        """Simple logging function"""
        timestamp = datetime.datetime.now().isoformat()
        log_entry = f"{timestamp} - {level} - {message}"
        if details:
            log_entry += f" - {json.dumps(details)}"
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry + "\n")
        except Exception:
            pass  # Silent fail for logging
        
        # Also show in debug mode
        if st.session_state.get('debug_mode', False):
            if level == 'ERROR':
                st.error(f"🔍 **Debug Log**: {message}")
            elif level == 'INFO':
                st.info(f"🔍 **Debug Log**: {message}")
            else:
                st.write(f"🔍 **Debug Log**: {message}")

# Global logger
logger = SimpleLogger()

def safe_request(method, url, **kwargs):
    """Make a safe HTTP request with proper error handling"""
    # Set safe defaults
    kwargs.setdefault('verify', False)  # Disable SSL verification for self-signed certs
    kwargs.setdefault('timeout', A2_HOSTING_CONFIG['request_timeout'])
    kwargs.setdefault('allow_redirects', True)
    
    # Add headers if not present
    headers = kwargs.get('headers', {})
    headers.setdefault('User-Agent', 'A2-WordPress-Manager/2.0')
    kwargs['headers'] = headers
    
    try:
        if method.upper() == 'GET':
            response = requests.get(url, **kwargs)
        elif method.upper() == 'POST':
            response = requests.post(url, **kwargs)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
        
        logger.log('INFO', f"HTTP {method} {url} -> {response.status_code}", {
            'status_code': response.status_code,
            'content_length': len(response.content),
            'content_type': response.headers.get('content-type', '')
        })
        
        return response
        
    except requests.exceptions.Timeout:
        logger.log('ERROR', f"Request timeout for {url}")
        raise Exception(f"Request timeout ({A2_HOSTING_CONFIG['request_timeout']}s)")
    
    except requests.exceptions.ConnectionError as e:
        logger.log('ERROR', f"Connection error for {url}: {str(e)}")
        raise Exception(f"Connection failed: {str(e)}")
    
    except Exception as e:
        logger.log('ERROR', f"Request error for {url}: {str(e)}")
        raise

def test_server_connectivity(host, port):
    """Test basic connectivity to the server"""
    try:
        # Test socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        
        if result == 0:
            logger.log('INFO', f"Basic connectivity to {host}:{port} successful")
            return True, "Connection successful"
        else:
            error_msg = f"Cannot connect to {host}:{port} (error code: {result})"
            logger.log('ERROR', error_msg)
            return False, error_msg
    
    except Exception as e:
        error_msg = f"Connectivity test failed: {str(e)}"
        logger.log('ERROR', error_msg)
        return False, error_msg

def test_cpanel_authentication(host, port, user, password):
    """Test cPanel authentication"""
    test_urls = [
        f"https://{host}:{port}/frontend/jupiter/",
        f"https://{host}:{port}/cpanel/",
        f"https://{host}:{port}/"
    ]
    
    for url in test_urls:
        try:
            response = safe_request('GET', url, auth=(user, password))
            
            if response.status_code in [200, 302]:
                # Check if we got a login page or actual cPanel content
                content = response.text.lower()
                if 'cpanel' in content or 'control panel' in content:
                    logger.log('INFO', f"cPanel authentication successful at {url}")
                    return True, f"Authentication successful at {url}"
            
        except Exception as e:
            logger.log('ERROR', f"Auth test failed for {url}: {str(e)}")
            continue
    
    return False, "Authentication failed for all cPanel URLs"

def analyze_softaculous_response(response):
    """Analyze Softaculous response to determine the issue"""
    content = response.text.lower()
    content_type = response.headers.get('content-type', '').lower()
    
    analysis = {
        'is_html': 'text/html' in content_type or content.strip().startswith('<!doctype'),
        'is_login_page': 'login' in content and ('username' in content or 'password' in content),
        'is_cpanel_page': 'cpanel' in content,
        'has_softaculous': 'softaculous' in content,
        'has_error': 'error' in content or 'internal server error' in content,
        'has_json': content.strip().startswith('{') or 'application/json' in content_type,
        'status_code': response.status_code,
        'content_length': len(response.content)
    }
    
    if analysis['is_html'] and analysis['is_login_page']:
        return analysis, "Got login page - authentication may have failed"
    elif analysis['is_html'] and analysis['is_cpanel_page']:
        return analysis, "Got cPanel page instead of Softaculous API"
    elif analysis['has_error']:
        return analysis, "Server returned an error page"
    elif analysis['status_code'] != 200:
        return analysis, f"HTTP error {analysis['status_code']}"
    elif not analysis['has_json'] and not analysis['has_softaculous']:
        return analysis, "Response doesn't appear to be Softaculous API data"
    else:
        return analysis, "Response looks promising"

def make_softaculous_request(act, post_data=None, additional_params=None):
    """Enhanced Softaculous API request with comprehensive testing"""
    
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
    
    # Use cached working config if available
    if 'working_softaculous_config' in st.session_state:
        config = st.session_state.working_softaculous_config
        return make_single_softaculous_request(
            creds, act, config['path'], config['format'], config['auth_method'], 
            post_data, additional_params
        )
    
    # Test all combinations to find one that works
    paths = A2_HOSTING_CONFIG['softaculous_paths']
    formats = A2_HOSTING_CONFIG['api_formats']
    auth_methods = A2_HOSTING_CONFIG['auth_methods']
    
    total_combinations = len(paths) * len(formats) * len(auth_methods)
    
    if st.session_state.get('debug_mode', False):
        st.write(f"🔍 **Testing {total_combinations} Softaculous API combinations...**")
    
    attempt = 0
    for path in paths:
        for api_format in formats:
            for auth_method in auth_methods:
                attempt += 1
                
                if st.session_state.get('debug_mode', False):
                    st.write(f"🔍 **Attempt {attempt}/{total_combinations}**: `{path}` + `{api_format}` + `{auth_method}`")
                
                result, error = make_single_softaculous_request(
                    creds, act, path, api_format, auth_method, post_data, additional_params
                )
                
                if result is not None:
                    # Success! Cache this configuration
                    st.session_state.working_softaculous_config = {
                        'path': path,
                        'format': api_format,
                        'auth_method': auth_method
                    }
                    
                    if st.session_state.get('debug_mode', False):
                        st.success(f"✅ **Found working configuration!** Path: `{path}`, Format: `{api_format}`, Auth: `{auth_method}`")
                    
                    logger.log('INFO', f"Working Softaculous config found", {
                        'path': path, 'format': api_format, 'auth': auth_method
                    })
                    
                    return result, None
                
                # Show error for debug mode
                if st.session_state.get('debug_mode', False):
                    st.write(f"❌ **Failed**: {error}")
    
    # All combinations failed
    error_msg = f"All {total_combinations} Softaculous API combinations failed"
    logger.log('ERROR', error_msg)
    return None, error_msg

def make_single_softaculous_request(creds, act, path, api_format, auth_method, post_data, additional_params):
    """Make a single Softaculous API request with specific configuration"""
    
    try:
        # Build URL based on auth method
        if auth_method == 'url':
            base_url = f"https://{creds['user']}:{creds['pass']}@{creds['host']}:{creds['port']}{path}"
            auth = None
        else:
            base_url = f"https://{creds['host']}:{creds['port']}{path}"
            auth = (creds['user'], creds['pass'])
        
        # Prepare parameters
        params = {'act': act, 'api': api_format}
        if additional_params:
            params.update(additional_params)
        
        # Prepare headers
        headers = {'User-Agent': 'A2-WordPress-Manager/2.0'}
        if auth_method == 'header':
            headers['Authorization'] = f'Basic {base64.b64encode(f"{creds["user"]}:{creds["pass"]}".encode()).decode()}'
            auth = None
        
        # Make request
        if post_data:
            response = safe_request('POST', base_url, params=params, data=post_data, headers=headers, auth=auth)
        else:
            response = safe_request('GET', base_url, params=params, headers=headers, auth=auth)
        
        # Analyze response
        analysis, analysis_message = analyze_softaculous_response(response)
        
        if st.session_state.get('debug_mode', False):
            st.write(f"📊 **Response Analysis**: {analysis_message}")
            st.write(f"📋 **Details**: Status {analysis['status_code']}, {analysis['content_length']} bytes")
        
        # Try to parse if response looks good
        if response.status_code == 200 and not analysis['is_html']:
            try:
                if api_format == 'json':
                    # Look for JSON in response
                    content = response.text.strip()
                    if content.startswith('{') or content.startswith('['):
                        result = json.loads(content)
                        return result, None
                
                elif api_format == 'serialize':
                    # Try to import and use phpserialize
                    try:
                        import phpserialize
                        result = phpserialize.loads(response.content)
                        return result, None
                    except ImportError:
                        return None, "phpserialize library not available"
                
                # If we can't parse, return raw content for analysis
                return {'raw_content': response.text[:1000]}, None
                
            except Exception as parse_error:
                return None, f"Parse error: {str(parse_error)}"
        
        return None, analysis_message
        
    except Exception as e:
        error_msg = f"Request failed: {str(e)}"
        logger.log('ERROR', error_msg, {'path': path, 'format': api_format, 'auth': auth_method})
        return None, error_msg

def discover_wordpress_installations():
    """Discover WordPress installations using various Softaculous endpoints"""
    
    if st.session_state.get('debug_mode', False):
        st.write("🔍 **Starting WordPress installation discovery...**")
    
    # Try different Softaculous actions that might return WordPress installations
    endpoints_to_try = [
        ('wordpress', {}),
        ('software', {'softwareid': '26'}),  # WordPress is typically ID 26
        ('installations', {}),
        ('list', {}),
        ('home', {}),
        ('apps', {}),
        ('myapps', {}),
        ('list', {'software': 'wordpress'}),
        ('software', {'software': 'wordpress'}),
    ]
    
    for act, params in endpoints_to_try:
        if st.session_state.get('debug_mode', False):
            st.write(f"🔍 **Trying endpoint**: `{act}` with params: `{params}`")
        
        result, error = make_softaculous_request(act, additional_params=params)
        
        if result and not error:
            installations = extract_wordpress_installations(result)
            if installations:
                logger.log('INFO', f"Found {len(installations)} WordPress installations via {act}")
                return installations, None
            
            if st.session_state.get('debug_mode', False):
                st.write(f"📋 **Endpoint `{act}` returned data but no installations found**")
                if isinstance(result, dict):
                    st.write(f"🔑 **Keys found**: {list(result.keys())[:10]}")
        
        elif st.session_state.get('debug_mode', False):
            st.write(f"❌ **Endpoint `{act}` failed**: {error}")
    
    return [], "No WordPress installations found via Softaculous API"

def extract_wordpress_installations(result):
    """Extract WordPress installations from Softaculous API response"""
    
    installations = []
    
    if not isinstance(result, dict):
        return installations
    
    # Try different keys where installations might be stored
    possible_keys = [
        'installations', 'data', 'result', 'software', 'wordpress', 
        'apps', 'sites', 'list', 'items', 'records', 'myapps'
    ]
    
    for key in possible_keys:
        if key in result:
            data = result[key]
            
            if isinstance(data, dict):
                # Data is a dictionary of installations
                for install_id, install_data in data.items():
                    if isinstance(install_data, dict):
                        installation = parse_installation_data(install_id, install_data)
                        if installation:
                            installations.append(installation)
            
            elif isinstance(data, list):
                # Data is a list of installations
                for i, install_data in enumerate(data):
                    if isinstance(install_data, dict):
                        installation = parse_installation_data(f"item_{i}", install_data)
                        if installation:
                            installations.append(installation)
    
    return installations

def parse_installation_data(install_id, data):
    """Parse individual installation data into standardized format"""
    
    # Field mapping for different possible field names
    field_map = {
        'domain': ['softurl', 'domain', 'url', 'site_url', 'host'],
        'path': ['softpath', 'path', 'directory', 'folder', 'dir'],
        'version': ['ver', 'version', 'wp_version'],
        'user': ['cuser', 'user', 'username', 'owner']
    }
    
    installation = {'insid': str(install_id)}
    
    # Extract fields using mapping
    for field, possible_keys in field_map.items():
        for key in possible_keys:
            if key in data and data[key]:
                installation[field] = str(data[key]).strip()
                break
    
    # Must have at least a domain to be valid
    if not installation.get('domain'):
        return None
    
    # Set defaults
    installation.setdefault('path', '/')
    installation.setdefault('version', 'Unknown')
    installation.setdefault('user', st.session_state.credentials.get('user', 'Unknown'))
    
    # Create display name
    domain = installation['domain']
    path = installation['path']
    installation['display_name'] = f"{domain}{path if path != '/' else ''}"
    
    return installation

def show_manual_entry_form():
    """Show form for manually entering WordPress sites"""
    
    st.subheader("📝 Manual WordPress Site Entry")
    st.markdown("**Can't find your WordPress sites automatically? Add them manually:**")
    
    with st.form("manual_wordpress_entry"):
        col1, col2 = st.columns(2)
        
        with col1:
            domain = st.text_input("Domain", placeholder="example.com")
            path = st.text_input("Path", value="/", placeholder="/wordpress/")
        
        with col2:
            version = st.text_input("WordPress Version", placeholder="6.4")
            notes = st.text_input("Notes", placeholder="Optional notes")
        
        if st.form_submit_button("➕ Add WordPress Site"):
            if domain:
                if 'manual_installations' not in st.session_state:
                    st.session_state.manual_installations = []
                
                installation = {
                    'insid': f"manual_{len(st.session_state.manual_installations)}",
                    'domain': domain.strip(),
                    'path': path.strip() or "/",
                    'version': version.strip() or "Unknown",
                    'user': st.session_state.credentials['user'],
                    'display_name': f"{domain.strip()}{path.strip() if path.strip() != '/' else ''}",
                    'notes': notes.strip(),
                    'manual_entry': True
                }
                
                st.session_state.manual_installations.append(installation)
                st.success(f"✅ Added: {installation['display_name']}")
                logger.log('INFO', f"Manual WordPress site added: {installation['display_name']}")
            else:
                st.error("❌ Please enter a domain name")
    
    # Show manually added sites
    if st.session_state.get('manual_installations'):
        st.subheader("📋 Manually Added Sites")
        
        for i, site in enumerate(st.session_state.manual_installations):
            col1, col2, col3 = st.columns([3, 1, 1])
            
            with col1:
                st.write(f"**{site['display_name']}** (v{site['version']})")
                if site.get('notes'):
                    st.write(f"📝 {site['notes']}")
            
            with col2:
                test_url = f"https://{site['domain']}{site['path']}wp-admin/"
                st.markdown(f"[🔗 Test]({test_url})")
            
            with col3:
                if st.button("🗑️", key=f"remove_{i}"):
                    st.session_state.manual_installations.pop(i)
                    st.rerun()
        
        if st.button("✅ Use These Sites"):
            st.session_state.installations = st.session_state.manual_installations.copy()
            st.success(f"✅ Using {len(st.session_state.manual_installations)} manually added sites!")
            st.rerun()

def show_comprehensive_troubleshooting():
    """Show comprehensive troubleshooting guide"""
    
    with st.expander("🛠️ Comprehensive Troubleshooting Guide", expanded=True):
        st.markdown("""
        ## 🔍 **Step-by-Step WordPress Discovery**
        
        ### **Method 1: Check cPanel Directly**
        1. **Log into your cPanel** (same credentials as here)
        2. **Find "Softaculous Apps Installer"**
        3. **Look for "Current Installations" or "My Installations"**
        4. **Note all WordPress sites listed**
        
        ### **Method 2: File Manager Check**
        1. **Open cPanel File Manager**
        2. **Go to `public_html` folder**
        3. **Look for these WordPress files**:
           - `wp-config.php`
           - `wp-content/` folder
           - `wp-admin/` folder
        4. **Check subfolders** for additional WordPress installations
        
        ### **Method 3: Direct URL Testing**
        Test these URLs in your browser:
        - `https://yourdomain.com/wp-admin/`
        - `https://yourdomain.com/blog/wp-admin/`
        - `https://yourdomain.com/wordpress/wp-admin/`
        - `https://subdomain.yourdomain.com/wp-admin/`
        
        If you see a WordPress login page, that's a WordPress site!
        
        ### **Method 4: Database Check**
        1. **Open phpMyAdmin in cPanel**
        2. **Look for databases with WordPress tables**:
           - Tables starting with `wp_`
           - `wp_posts`, `wp_users`, `wp_options` tables
        
        ### **Why Automatic Discovery Might Fail:**
        - **Reseller Account**: Custom Softaculous configuration
        - **Old cPanel Version**: Different API structure
        - **No Softaculous**: WordPress installed manually
        - **Permissions**: Limited API access
        - **Custom Setup**: Non-standard installation paths
        """)

def show_login_screen():
    """Enhanced login screen with better error handling"""
    
    st.title("🔐 A2 Hosting WordPress Manager")
    st.markdown("### Enhanced WordPress Management for A2 Hosting & Resellers")
    
    # Quick info about the tool
    st.info("💡 **Enhanced Version**: Includes comprehensive diagnostics and manual entry options for maximum compatibility")
    
    with st.form("login_form"):
        st.subheader("📋 cPanel Login Credentials")
        
        col1, col2 = st.columns(2)
        
        with col1:
            host = st.text_input(
                "cPanel Host", 
                placeholder="server.clasit.org",
                help="Your cPanel server hostname (from hosting welcome email)"
            )
            user = st.text_input(
                "Username", 
                placeholder="your_username",
                help="Your cPanel username"
            )
        
        with col2:
            port = st.selectbox("Port", ["2083", "2082"], index=0)
            password = st.text_input("Password", type="password")
        
        # Options
        st.subheader("🔧 Options")
        col1, col2 = st.columns(2)
        
        with col1:
            debug_mode = st.checkbox("Enable debug mode", value=False, help="Show detailed diagnostic information")
        
        with col2:
            rate_limits = st.checkbox("Respect rate limits", value=True, help="Add delays between API calls")
        
        if st.form_submit_button("🔍 Connect & Discover WordPress Sites", type="primary"):
            if not all([host, user, password]):
                st.error("❌ Please fill in all credentials")
                return
            
            # Store credentials
            st.session_state.credentials = {
                'host': host, 'port': port, 'user': user, 'pass': password, 'rate_limits': rate_limits
            }
            st.session_state.debug_mode = debug_mode
            
            # Test connectivity
            with st.spinner("🔍 Testing server connectivity..."):
                connectivity_ok, connectivity_msg = test_server_connectivity(host, port)
                
                if not connectivity_ok:
                    st.error(f"❌ **Connectivity Failed**: {connectivity_msg}")
                    st.markdown("""
                    **Possible issues:**
                    - Incorrect hostname or port
                    - Firewall blocking connection
                    - Server is down
                    
                    **Solutions:**
                    - Double-check hostname in your hosting welcome email
                    - Try port 2082 instead of 2083
                    - Contact your hosting provider
                    """)
                    return
                
                st.success("✅ Server connectivity OK")
            
            # Test authentication
            with st.spinner("🔐 Testing cPanel authentication..."):
                auth_ok, auth_msg = test_cpanel_authentication(host, port, user, password)
                
                if not auth_ok:
                    st.error(f"❌ **Authentication Failed**: {auth_msg}")
                    st.markdown("""
                    **Possible issues:**
                    - Incorrect username or password
                    - Account suspended
                    - Two-factor authentication enabled
                    
                    **Solutions:**
                    - Verify credentials in your hosting control panel
                    - Reset cPanel password if needed
                    - Disable 2FA temporarily for API access
                    """)
                    return
                
                st.success("✅ cPanel authentication OK")
            
            # Success - proceed to main app
            logger.log('INFO', f"Successful login for {user}@{host}:{port}")
            st.success("🎉 Login successful! Proceeding to WordPress discovery...")
            st.rerun()

def show_main_app():
    """Main application interface"""
    
    # Sidebar with session info and controls
    with st.sidebar:
        st.markdown("### 🔐 Session Info")
        creds = st.session_state.credentials
        st.write(f"**Host:** {creds['host']}")
        st.write(f"**User:** {creds['user']}")
        
        st.markdown("### 🔧 Controls")
        st.session_state.debug_mode = st.checkbox("Debug Mode", value=st.session_state.get('debug_mode', False))
        
        if 'working_softaculous_config' in st.session_state:
            st.markdown("### ✅ Working API Config")
            config = st.session_state.working_softaculous_config
            st.code(f"Path: {config['path']}\nFormat: {config['format']}\nAuth: {config['auth_method']}")
        
        st.markdown("---")
        if st.button("🚪 Logout"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    
    # Main content
    st.header("🔍 WordPress Site Discovery")
    
    # Initialize installations
    if 'installations' not in st.session_state:
        st.session_state.installations = []
    
    # Discover WordPress installations if not already done
    if not st.session_state.installations:
        
        # Automatic discovery
        st.subheader("🤖 Automatic Discovery")
        
        if st.button("🔍 Discover WordPress Sites", type="primary"):
            with st.spinner("🔍 Discovering WordPress installations..."):
                installations, error = discover_wordpress_installations()
                
                if installations:
                    st.session_state.installations = installations
                    st.success(f"✅ Found {len(installations)} WordPress installations!")
                    
                    # Show discovered sites
                    for installation in installations:
                        st.write(f"• **{installation['display_name']}** (v{installation['version']})")
                    
                    st.rerun()
                
                else:
                    st.warning(f"⚠️ Automatic discovery failed: {error}")
                    st.info("💡 Don't worry! You can add WordPress sites manually below.")
        
        st.markdown("---")
        
        # Manual entry form
        show_manual_entry_form()
        
        st.markdown("---")
        
        # Troubleshooting guide
        show_comprehensive_troubleshooting()
    
    else:
        # Show discovered/manual sites
        st.subheader(f"📋 WordPress Sites ({len(st.session_state.installations)})")
        
        for installation in st.session_state.installations:
            with st.expander(f"🌐 {installation['display_name']}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Domain:** {installation['domain']}")
                    st.write(f"**Path:** {installation['path']}")
                    st.write(f"**Version:** {installation['version']}")
                
                with col2:
                    st.write(f"**User:** {installation['user']}")
                    if installation.get('manual_entry'):
                        st.write("📝 **Manually Added**")
                    
                    # Test URL
                    test_url = f"https://{installation['domain']}{installation['path']}wp-admin/"
                    st.markdown(f"[🔗 Open WordPress Admin]({test_url})")
        
        # Management options
        st.subheader("🛠️ Management Options")
        st.info("🚧 **WordPress management features** (plugin updates, backups, etc.) will be available once we resolve the Softaculous API connectivity.")
        
        # Export options
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📊 Export Site List (CSV)"):
                csv_data = create_csv_export(st.session_state.installations)
                st.download_button(
                    label="📥 Download CSV",
                    data=csv_data,
                    file_name=f"wordpress_sites_{datetime.datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("🗑️ Clear All Sites"):
                st.session_state.installations = []
                if 'manual_installations' in st.session_state:
                    del st.session_state.manual_installations
                st.rerun()

def create_csv_export(installations):
    """Create CSV export of WordPress installations"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['Domain', 'Path', 'Display Name', 'Version', 'User', 'Admin URL', 'Type'])
    
    # Data
    for installation in installations:
        admin_url = f"https://{installation['domain']}{installation['path']}wp-admin/"
        install_type = "Manual Entry" if installation.get('manual_entry') else "Auto Discovered"
        
        writer.writerow([
            installation['domain'],
            installation['path'],
            installation['display_name'],
            installation['version'],
            installation['user'],
            admin_url,
            install_type
        ])
    
    return output.getvalue()

def main():
    """Main application entry point"""
    
    st.set_page_config(
        page_title="A2 Hosting WordPress Manager",
        page_icon="🔧",
        layout="wide"
    )
    
    # Initialize session state
    if 'session_id' not in st.session_state:
        st.session_state.session_id = hashlib.md5(
            f"{datetime.datetime.now().isoformat()}".encode()
        ).hexdigest()[:8]
    
    # Header
    st.title("🔧 A2 Hosting WordPress Manager")
    st.markdown("### Production-Ready WordPress Management Tool")
    
    # Instructions
    with st.expander("📖 Quick Start Guide"):
        st.markdown("""
        ## 🚀 How to Use This Tool
        
        ### **Step 1: Login**
        - Enter your **cPanel credentials** (same as cPanel login)
        - Use your **hosting server hostname** (from welcome email)
        - Enable **debug mode** for detailed information
        
        ### **Step 2: Discover WordPress Sites**
        - Try **automatic discovery** first
        - If that fails, use **manual entry**
        - Follow the **troubleshooting guide** if needed
        
        ### **Step 3: Manage Your Sites**
        - View all discovered WordPress installations
        - Export site lists for documentation
        - Access WordPress admin panels directly
        
        ## ✨ **Key Features**
        - **Smart Discovery**: Tests multiple API methods
        - **Manual Entry**: Add sites when automation fails  
        - **Debug Mode**: Detailed diagnostic information
        - **Export Options**: CSV export for documentation
        - **Production Ready**: Proper error handling and logging
        """)
    
    st.markdown("---")
    
    # Main application flow
    if 'credentials' not in st.session_state:
        show_login_screen()
    else:
        show_main_app()

if __name__ == "__main__":
    main()
