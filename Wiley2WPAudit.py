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

# --- Configuration ---
LOCAL_BACKUP_DIR = Path("./backups")
DOWNLOADS_DIR = Path("./downloads")
LOGS_DIR = Path("./logs")

# Ensure directories exist
LOCAL_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# A2 Hosting specific configuration
A2_HOSTING_CONFIG = {
    'default_ports': {
        'secure': '2083',
        'non_secure': '2082'
    },
    'softaculous_path': '/frontend/jupiter/softaculous/index.live.php',
    'cpanel_themes': ['jupiter', 'paper_lantern'],
    'known_servers': [
        'server.a2hosting.com',
        'nl1-ss*.a2hosting.com',
        'sg*.a2hosting.com',
        'mi*.a2hosting.com'
    ],
    'rate_limits': {
        'api_calls_per_minute': 30,
        'bulk_operations_delay': 2
    }
}

# --- Audit Logging System ---
class AuditLogger:
    def __init__(self):
        self.logs_dir = LOGS_DIR
        self.setup_loggers()
        
    def setup_loggers(self):
        """Set up different loggers for different event types"""
        today = datetime.datetime.now().strftime('%Y-%m-%d')
        
        # Main audit logger
        self.audit_logger = logging.getLogger('audit')
        self.audit_logger.setLevel(logging.INFO)
        audit_handler = logging.FileHandler(self.logs_dir / f"audit_{today}.log")
        audit_formatter = logging.Formatter('%(message)s')
        audit_handler.setFormatter(audit_formatter)
        if not self.audit_logger.handlers:
            self.audit_logger.addHandler(audit_handler)
        
        # Security events logger
        self.security_logger = logging.getLogger('security')
        self.security_logger.setLevel(logging.INFO)
        security_handler = logging.FileHandler(self.logs_dir / "security_events.log")
        security_formatter = logging.Formatter('%(message)s')
        security_handler.setFormatter(security_formatter)
        if not self.security_logger.handlers:
            self.security_logger.addHandler(security_handler)
        
        # Bulk operations logger
        self.bulk_logger = logging.getLogger('bulk_operations')
        self.bulk_logger.setLevel(logging.INFO)
        bulk_handler = logging.FileHandler(self.logs_dir / "bulk_operations.log")
        bulk_formatter = logging.Formatter('%(message)s')
        bulk_handler.setFormatter(bulk_formatter)
        if not self.bulk_logger.handlers:
            self.bulk_logger.addHandler(bulk_handler)
        
        # API calls logger
        self.api_logger = logging.getLogger('api_calls')
        self.api_logger.setLevel(logging.INFO)
        api_handler = logging.FileHandler(self.logs_dir / "api_calls.log")
        api_formatter = logging.Formatter('%(message)s')
        api_handler.setFormatter(api_formatter)
        if not self.api_logger.handlers:
            self.api_logger.addHandler(api_handler)
    
    def get_client_ip(self):
        """Get client IP address"""
        try:
            if hasattr(st, 'context') and hasattr(st.context, 'headers'):
                return st.context.headers.get('X-Forwarded-For', '127.0.0.1')
            return '127.0.0.1'
        except:
            return '127.0.0.1'
    
    def get_session_id(self):
        """Generate session ID"""
        if 'session_id' not in st.session_state:
            st.session_state.session_id = hashlib.md5(
                f"{datetime.datetime.now().isoformat()}{self.get_client_ip()}".encode()
            ).hexdigest()[:16]
        return st.session_state.session_id
    
    def get_username(self):
        """Get current username"""
        if 'credentials' in st.session_state:
            return st.session_state.credentials.get('user', 'unknown')
        return 'anonymous'
    
    def log_auth_event(self, event_type, result, details=None):
        """Log authentication events"""
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'event_type': 'AUTHENTICATION',
            'action': event_type,
            'username': self.get_username(),
            'ip_address': self.get_client_ip(),
            'session_id': self.get_session_id(),
            'result': result,
            'details': details or {},
            'risk_level': 'HIGH' if result == 'FAILURE' else 'LOW'
        }
        
        self.audit_logger.info(json.dumps(log_entry))
        if result == 'FAILURE':
            self.security_logger.info(json.dumps(log_entry))
    
    def log_site_access(self, site_name, action, result, details=None):
        """Log site access events"""
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'event_type': 'SITE_ACCESS',
            'username': self.get_username(),
            'ip_address': self.get_client_ip(),
            'session_id': self.get_session_id(),
            'site_name': site_name,
            'action': action,
            'result': result,
            'details': details or {},
            'risk_level': 'MEDIUM' if 'UPDATE' in action else 'LOW'
        }
        
        self.audit_logger.info(json.dumps(log_entry))
        if result == 'FAILURE':
            self.security_logger.info(json.dumps(log_entry))
    
    def log_bulk_operation(self, operation_type, site_count, results, details=None):
        """Log bulk operations"""
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'event_type': 'BULK_OPERATION',
            'username': self.get_username(),
            'ip_address': self.get_client_ip(),
            'session_id': self.get_session_id(),
            'operation': operation_type,
            'sites_affected': site_count,
            'success_count': len(results.get('success', [])),
            'failure_count': len(results.get('errors', [])),
            'details': details or {},
            'risk_level': 'HIGH'
        }
        
        self.audit_logger.info(json.dumps(log_entry))
        self.bulk_logger.info(json.dumps(log_entry))
        
        if len(results.get('errors', [])) > site_count * 0.5:
            self.security_logger.info(json.dumps({**log_entry, 'alert': 'HIGH_FAILURE_RATE'}))
    
    def log_api_call(self, endpoint, action, result, response_time=None, details=None):
        """Log API calls"""
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'event_type': 'API_CALL',
            'username': self.get_username(),
            'ip_address': self.get_client_ip(),
            'session_id': self.get_session_id(),
            'endpoint': endpoint,
            'action': action,
            'result': result,
            'response_time': response_time,
            'details': details or {},
            'risk_level': 'MEDIUM' if result == 'FAILURE' else 'LOW'
        }
        
        self.api_logger.info(json.dumps(log_entry))
        if result == 'FAILURE':
            self.security_logger.info(json.dumps(log_entry))
    
    def log_file_operation(self, operation_type, file_path, result, details=None):
        """Log file operations"""
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'event_type': 'FILE_OPERATION',
            'username': self.get_username(),
            'ip_address': self.get_client_ip(),
            'session_id': self.get_session_id(),
            'operation': operation_type,
            'file_path': str(file_path),
            'result': result,
            'details': details or {},
            'risk_level': 'LOW'
        }
        
        self.audit_logger.info(json.dumps(log_entry))
    
    def log_export_operation(self, export_type, record_count, result, details=None):
        """Log export operations"""
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'event_type': 'EXPORT_OPERATION',
            'username': self.get_username(),
            'ip_address': self.get_client_ip(),
            'session_id': self.get_session_id(),
            'export_type': export_type,
            'record_count': record_count,
            'result': result,
            'details': details or {},
            'risk_level': 'MEDIUM'
        }
        
        self.audit_logger.info(json.dumps(log_entry))

# Global audit logger instance
audit_logger = AuditLogger()

# --- A2 Hosting Specific Functions ---
def detect_a2_hosting_server(host):
    """Detect if this is an A2 Hosting server (including reseller accounts)"""
    a2_indicators = [
        'a2hosting.com',
        'server.a2hosting.com',
        'nl1-ss',
        'sg',
        'mi',
        'clasit.org',  # CLAS IT reseller
    ]
    
    for indicator in a2_indicators:
        if indicator in host.lower():
            return True, get_a2_server_info(host)
    
    return False, None

def get_a2_server_info(host):
    """Get information about A2 Hosting server location and type"""
    server_info = {
        'provider': 'A2 Hosting',
        'location': 'Unknown',
        'server_type': 'Shared/VPS'
    }
    
    if 'nl1-ss' in host.lower():
        server_info['location'] = 'Netherlands (Amsterdam)'
        server_info['server_type'] = 'Shared'
    elif 'sg' in host.lower():
        server_info['location'] = 'Singapore'
        server_info['server_type'] = 'Shared'
    elif 'mi' in host.lower():
        server_info['location'] = 'Michigan (USA)'
        server_info['server_type'] = 'Shared'
    elif 'server.a2hosting.com' in host.lower():
        server_info['location'] = 'USA (Primary)'
        server_info['server_type'] = 'VPS/Dedicated'
    elif 'clasit.org' in host.lower():
        server_info['location'] = 'USA (A2 Hosting Reseller - CLAS IT)'
        server_info['server_type'] = 'Reseller Account'
        server_info['reseller'] = 'CLAS IT'
    
    return server_info

def validate_a2_credentials(host, user, password, port):
    """Validate A2 Hosting credentials (including reseller accounts)"""
    errors = []
    
    # A2 Hosting (including resellers) host validation
    a2_domains = ['.a2hosting.com', 'server.a2hosting.com', 'clasit.org']
    is_a2_host = any(domain in host.lower() for domain in a2_domains)
    
    if not is_a2_host:
        errors.append("Host should be an A2 Hosting server (*.a2hosting.com) or A2 reseller (e.g., clasit.org)")
    
    # A2 typically has specific username formats
    if len(user) < 3:
        errors.append("A2 Hosting usernames are typically at least 3 characters")
    
    # A2 password requirements
    if len(password) < 6:
        errors.append("A2 Hosting passwords should be at least 6 characters")
    
    return errors

def test_a2_cpanel_connection(host, port, user, password):
    """Test A2 Hosting cPanel connection with specific error handling"""
    try:
        base_url = f"https://{user}:{password}@{host}:{port}/frontend/jupiter/softaculous/index.live.php"
        params = {'act': 'home', 'api': 'json'}
        
        response = requests.get(
            base_url, 
            params=params, 
            verify=False,  # A2 may use self-signed certs
            timeout=30,    # A2 servers can be slow
            headers={'User-Agent': 'A2-WordPress-Manager/1.0'}
        )
        
        if response.status_code == 200:
            return True
        elif response.status_code == 401:
            audit_logger.log_auth_event('A2_LOGIN', 'FAILURE', 
                                      details={'error': 'Invalid credentials'})
            return False
        elif response.status_code == 403:
            audit_logger.log_auth_event('A2_LOGIN', 'FAILURE', 
                                      details={'error': 'IP blocked or access denied'})
            return False
        else:
            audit_logger.log_auth_event('A2_LOGIN', 'FAILURE', 
                                      details={'error': f'HTTP {response.status_code}'})
            return False
            
    except requests.exceptions.ConnectTimeout:
        audit_logger.log_auth_event('A2_LOGIN', 'FAILURE', 
                                  details={'error': 'Connection timeout - A2 server may be slow'})
        return False
    except requests.exceptions.SSLError:
        audit_logger.log_auth_event('A2_LOGIN', 'FAILURE', 
                                  details={'error': 'SSL certificate error'})
        return False
    except Exception as e:
        audit_logger.log_auth_event('A2_LOGIN', 'FAILURE', 
                                  details={'error': str(e)})
        return False

def handle_a2_hosting_errors(error_message):
    """Handle A2 Hosting specific error messages"""
    a2_error_solutions = {
        'timeout': {
            'message': 'A2 Hosting server timeout',
            'solution': 'A2 servers can be slow during peak hours. Try again in a few minutes.',
            'action': 'Reduce batch sizes or schedule operations during off-peak hours'
        },
        'ssl': {
            'message': 'SSL certificate error',
            'solution': 'A2 Hosting uses self-signed certificates on some servers.',
            'action': 'This is normal and handled automatically by the tool'
        },
        '401': {
            'message': 'Authentication failed',
            'solution': 'Check your cPanel credentials in the A2 Hosting client area.',
            'action': 'Verify username and password, or reset cPanel password'
        },
        '403': {
            'message': 'Access denied',
            'solution': 'A2 Hosting firewall may be blocking the request.',
            'action': 'Contact A2 support to whitelist your IP address'
        },
        'rate_limit': {
            'message': 'Too many requests',
            'solution': 'A2 Hosting is throttling API calls.',
            'action': 'Enable rate limiting and reduce operation frequency'
        }
    }
    
    error_lower = error_message.lower()
    
    for error_type, info in a2_error_solutions.items():
        if error_type in error_lower:
            st.error(f"🚨 **{info['message']}**")
            st.info(f"💡 **Solution:** {info['solution']}")
            st.success(f"🔧 **Action:** {info['action']}")
            return True
    
    return False

# --- Softaculous API Functions ---
def make_softaculous_request(act, post_data=None, additional_params=None):
    """Make authenticated request to Softaculous API optimized for A2 Hosting"""
    start_time = datetime.datetime.now()
    
    # Get credentials from session state
    if 'credentials' not in st.session_state:
        audit_logger.log_api_call('softaculous', act, 'FAILURE', 
                                details={'error': 'No credentials available'})
        return None, "Not authenticated"
    
    creds = st.session_state.credentials
    
    # A2 Hosting specific rate limiting
    if creds.get('rate_limits', True):
        if 'last_api_call' in st.session_state:
            time_since_last = (datetime.datetime.now() - st.session_state.last_api_call).total_seconds()
            if time_since_last < 2:  # Wait at least 2 seconds between calls
                time.sleep(2 - time_since_last)
        
        st.session_state.last_api_call = datetime.datetime.now()
    
    softaculous_path = "/frontend/jupiter/softaculous/index.live.php"
    
    base_url = f"https://{creds['user']}:{creds['pass']}@{creds['host']}:{creds['port']}{softaculous_path}"
    
    params = {
        'act': act,
        'api': 'serialize'
    }
    
    if additional_params:
        params.update(additional_params)
    
    # A2 Hosting specific headers
    headers = {
        'User-Agent': 'A2-WordPress-Manager/1.0',
        'Accept': 'application/json, text/plain, */*',
        'Cache-Control': 'no-cache'
    }
    
    try:
        # Show debug info in dev mode
        if st.session_state.get('debug_mode', False):
            st.write(f"🔍 **Debug**: Making request to {act}")
            st.write(f"📍 **URL**: {base_url}")
            st.write(f"🔧 **Params**: {params}")
        
        if post_data:
            response = requests.post(
                base_url, 
                params=params, 
                data=post_data,
                headers=headers,
                verify=False,  # A2 may use self-signed certs
                timeout=60     # A2 operations can be slow
            )
        else:
            response = requests.get(
                base_url, 
                params=params,
                headers=headers,
                verify=False,
                timeout=60
            )
        
        response_time = (datetime.datetime.now() - start_time).total_seconds()
        
        if st.session_state.get('debug_mode', False):
            st.write(f"📊 **Response Status**: {response.status_code}")
            st.write(f"⏱️ **Response Time**: {response_time:.2f}s")
        
        if response.status_code == 200:
            # Parse serialized PHP response
            import phpserialize
            try:
                result = phpserialize.loads(response.content)
                
                if st.session_state.get('debug_mode', False):
                    st.write(f"✅ **Parsed Result**: {type(result)}")
                    if isinstance(result, dict):
                        st.write(f"📋 **Keys**: {list(result.keys())}")
                
                audit_logger.log_api_call('a2_softaculous', act, 'SUCCESS', 
                                        response_time=response_time,
                                        details={'params': params, 'response_size': len(response.content)})
                return result, None
            except Exception as parse_error:
                if st.session_state.get('debug_mode', False):
                    st.write(f"❌ **Parse Error**: {str(parse_error)}")
                    st.write(f"📄 **Raw Response**: {response.content[:500]}...")
                
                audit_logger.log_api_call('a2_softaculous', act, 'FAILURE', 
                                        response_time=response_time,
                                        details={'error': f'Parse error: {str(parse_error)}'})
                return None, f"Failed to parse A2 Softaculous response: {str(parse_error)}"
        else:
            audit_logger.log_api_call('a2_softaculous', act, 'FAILURE', 
                                    response_time=response_time,
                                    details={'status_code': response.status_code, 'error': response.text})
            return None, f"A2 Hosting API Error - HTTP {response.status_code}: {response.text}"
    
    except requests.exceptions.Timeout:
        response_time = (datetime.datetime.now() - start_time).total_seconds()
        audit_logger.log_api_call('a2_softaculous', act, 'FAILURE', 
                                response_time=response_time,
                                details={'error': 'Request timeout - A2 server slow'})
        return None, "Request timeout - A2 Hosting server may be experiencing high load"
    
    except Exception as e:
        response_time = (datetime.datetime.now() - start_time).total_seconds()
        audit_logger.log_api_call('a2_softaculous', act, 'FAILURE', 
                                response_time=response_time,
                                details={'error': str(e)})
        return None, f"A2 Hosting connection error: {str(e)}"

def list_wordpress_installations():
    """List all WordPress installations with enhanced debugging"""
    # Try different API endpoints that might work
    endpoints_to_try = [
        ('wordpress', {}),
        ('software', {'softwareid': '26'}),  # WordPress is usually ID 26
        ('list', {'software': 'wordpress'}),
        ('installations', {'type': 'wordpress'}),
    ]
    
    for act, extra_params in endpoints_to_try:
        if st.session_state.get('debug_mode', False):
            st.write(f"🔍 **Trying endpoint**: {act} with params: {extra_params}")
        
        result, error = make_softaculous_request(act, additional_params=extra_params)
        
        if not error and result:
            # Try to find installations in different possible locations
            installations = []
            
            # Check different possible response structures
            possible_keys = ['installations', 'data', 'result', 'software', 'wordpress']
            
            for key in possible_keys:
                if key in result:
                    data = result[key]
                    if isinstance(data, dict):
                        for insid, install_data in data.items():
                            if isinstance(install_data, dict):
                                installations.append({
                                    'insid': insid,
                                    'domain': install_data.get('softurl', install_data.get('domain', '')),
                                    'path': install_data.get('softpath', install_data.get('path', '')),
                                    'version': install_data.get('ver', install_data.get('version', '')),
                                    'user': install_data.get('cuser', install_data.get('user', '')),
                                    'display_name': f"{install_data.get('softdomain', install_data.get('domain', ''))}/{install_data.get('softdirectory', install_data.get('directory', ''))}"
                                })
                    break
            
            if installations:
                if st.session_state.get('debug_mode', False):
                    st.write(f"✅ **Found {len(installations)} installations** using endpoint: {act}")
                return installations, None
        
        if st.session_state.get('debug_mode', False):
            st.write(f"❌ **Endpoint {act} failed**: {error}")
    
    return [], "No WordPress installations found. This could mean: 1) No WordPress sites exist, 2) Softaculous API structure is different, or 3) API permissions issue."

def get_plugins_for_installation(insid):
    """Get all plugins for a specific WordPress installation"""
    post_data = {
        'insid': insid,
        'type': 'plugins',
        'list': '1'
    }
    
    result, error = make_softaculous_request('wordpress', post_data)
    if error:
        audit_logger.log_site_access(f"Site_{insid}", 'PLUGIN_LIST', 'FAILURE', 
                                   details={'error': error})
        return None, error
    
    plugins = []
    if result and 'plugins' in result:
        for plugin_path, plugin_data in result['plugins'].items():
            plugins.append({
                'name': plugin_data.get('Name', 'Unknown'),
                'slug': plugin_path,
                'version': plugin_data.get('Version', ''),
                'active': plugin_data.get('active', False),
                'update_available': plugin_data.get('update_available', False),
                'new_version': plugin_data.get('new_version', ''),
                'description': plugin_data.get('Description', '')
            })
    
    audit_logger.log_site_access(f"Site_{insid}", 'PLUGIN_LIST', 'SUCCESS', 
                               details={'plugin_count': len(plugins)})
    return plugins, None

def update_plugin(insid, plugin_slug=None):
    """Update a specific plugin or all plugins"""
    post_data = {
        'insid': insid,
        'type': 'plugins'
    }
    
    if plugin_slug:
        post_data['slug'] = plugin_slug
        post_data['update'] = '1'
        action = f'PLUGIN_UPDATE_{plugin_slug}'
    else:
        post_data['bulk_update'] = '1'
        action = 'PLUGIN_BULK_UPDATE'
    
    result, error = make_softaculous_request('wordpress', post_data)
    
    if error:
        audit_logger.log_site_access(f"Site_{insid}", action, 'FAILURE', 
                                   details={'error': error})
    else:
        audit_logger.log_site_access(f"Site_{insid}", action, 'SUCCESS', 
                                   details={'plugin_slug': plugin_slug})
    
    return result, error

def activate_plugin(insid, plugin_slug):
    """Activate a plugin"""
    post_data = {
        'insid': insid,
        'type': 'plugins',
        'slug': plugin_slug,
        'activate': '1'
    }
    
    result, error = make_softaculous_request('wordpress', post_data)
    
    if error:
        audit_logger.log_site_access(f"Site_{insid}", f'PLUGIN_ACTIVATE_{plugin_slug}', 'FAILURE', 
                                   details={'error': error})
    else:
        audit_logger.log_site_access(f"Site_{insid}", f'PLUGIN_ACTIVATE_{plugin_slug}', 'SUCCESS')
    
    return result, error

def deactivate_plugin(insid, plugin_slug):
    """Deactivate a plugin"""
    post_data = {
        'insid': insid,
        'type': 'plugins',
        'slug': plugin_slug,
        'deactivate': '1'
    }
    
    result, error = make_softaculous_request('wordpress', post_data)
    
    if error:
        audit_logger.log_site_access(f"Site_{insid}", f'PLUGIN_DEACTIVATE_{plugin_slug}', 'FAILURE', 
                                   details={'error': error})
    else:
        audit_logger.log_site_access(f"Site_{insid}", f'PLUGIN_DEACTIVATE_{plugin_slug}', 'SUCCESS')
    
    return result, error

def create_backup(insid):
    """Create a backup for a WordPress installation"""
    post_data = {
        'backupins': '1',
        'backup_dir': '1',
        'backup_datadir': '1',
        'backup_db': '1'
    }
    
    result, error = make_softaculous_request('backup', post_data, {'insid': insid})
    
    if error:
        audit_logger.log_site_access(f"Site_{insid}", 'BACKUP_CREATE', 'FAILURE', 
                                   details={'error': error})
    else:
        audit_logger.log_site_access(f"Site_{insid}", 'BACKUP_CREATE', 'SUCCESS')
    
    return result, error

def list_backups():
    """List all backups"""
    result, error = make_softaculous_request('backups')
    return result, error

def download_backup_file(backup_filename):
    """Download a backup file to local machine"""
    try:
        # Get the backup file content via Softaculous API
        params = {'download': backup_filename}
        result, error = make_softaculous_request('backups', additional_params=params)
        
        if error:
            audit_logger.log_file_operation('BACKUP_DOWNLOAD', backup_filename, 'FAILURE', 
                                          details={'error': error})
            return None, error
        
        # Save to local backup directory
        local_file_path = LOCAL_BACKUP_DIR / backup_filename
        
        # If result contains binary data, save it
        if result and isinstance(result, bytes):
            with open(local_file_path, 'wb') as f:
                f.write(result)
            
            audit_logger.log_file_operation('BACKUP_DOWNLOAD', local_file_path, 'SUCCESS', 
                                          details={'file_size': len(result)})
            return local_file_path, None
        else:
            audit_logger.log_file_operation('BACKUP_DOWNLOAD', backup_filename, 'FAILURE', 
                                          details={'error': 'No backup data received'})
            return None, "No backup data received"
            
    except Exception as e:
        audit_logger.log_file_operation('BACKUP_DOWNLOAD', backup_filename, 'FAILURE', 
                                      details={'error': str(e)})
        return None, str(e)

def delete_backup(backup_filename):
    """Delete a backup file"""
    params = {'remove': backup_filename}
    result, error = make_softaculous_request('backups', additional_params=params)
    return result, error

def upgrade_wordpress_installation(insid):
    """Upgrade WordPress installation"""
    post_data = {'softsubmit': '1'}
    result, error = make_softaculous_request('upgrade', post_data, {'insid': insid})
    return result, error

def create_compressed_archive(backup_files, archive_name, compression_type):
    """Create a compressed archive from multiple backup files"""
    try:
        archive_path = DOWNLOADS_DIR / f"{archive_name}.{compression_type}"
        
        if compression_type == 'zip':
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for backup_file in backup_files:
                    file_path = LOCAL_BACKUP_DIR / backup_file
                    if file_path.exists():
                        zipf.write(file_path, backup_file)
                        audit_logger.log_file_operation('ARCHIVE_ADD', backup_file, 'SUCCESS')
        
        elif compression_type == 'tar.gz':
            with tarfile.open(archive_path, 'w:gz') as tar:
                for backup_file in backup_files:
                    file_path = LOCAL_BACKUP_DIR / backup_file
                    if file_path.exists():
                        tar.add(file_path, arcname=backup_file)
                        audit_logger.log_file_operation('ARCHIVE_ADD', backup_file, 'SUCCESS')
        
        audit_logger.log_file_operation('ARCHIVE_CREATE', archive_path.name, 'SUCCESS',
                                      details={'file_count': len(backup_files), 'compression': compression_type})
        return archive_path, None
    
    except Exception as e:
        audit_logger.log_file_operation('ARCHIVE_CREATE', f"{archive_name}.{compression_type}", 'FAILURE',
                                      details={'error': str(e)})
        return None, str(e)

def bulk_download_backups(backup_list, progress_callback=None):
    """Download multiple backups from server"""
    results = {'success': [], 'errors': []}
    
    for i, backup_filename in enumerate(backup_list):
        if progress_callback:
            progress_callback(i, len(backup_list), backup_filename)
        
        local_file, error = download_backup_file(backup_filename)
        if error:
            results['errors'].append(f"{backup_filename}: {error}")
        else:
            results['success'].append(backup_filename)
    
    return results

def get_backup_file_info(backup_filename):
    """Get information about a backup file"""
    try:
        file_path = LOCAL_BACKUP_DIR / backup_filename
        if file_path.exists():
            stat = file_path.stat()
            return {
                'name': backup_filename,
                'size': stat.st_size,
                'modified': datetime.datetime.fromtimestamp(stat.st_mtime),
                'path': file_path
            }
        return None
    except Exception:
        return None

def export_sites_to_csv(installations):
    """Export WordPress installations to CSV format"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'Installation ID', 'Domain', 'Display Name', 'Path', 
        'WordPress Version', 'User', 'Full URL'
    ])
    
    # Write data rows
    for installation in installations:
        writer.writerow([
            installation.get('insid', ''),
            installation.get('domain', ''),
            installation.get('display_name', ''),
            installation.get('path', ''),
            installation.get('version', ''),
            installation.get('user', ''),
            f"https://{installation.get('domain', '')}{installation.get('path', '')}"
        ])
    
    return output.getvalue()

def export_sites_to_json(installations):
    """Export WordPress installations to JSON format"""
    export_data = {
        'export_timestamp': datetime.datetime.now().isoformat(),
        'total_installations': len(installations),
        'installations': installations
    }
    return json.dumps(export_data, indent=2)

def create_detailed_site_report(installations):
    """Create a detailed markdown report of all installations"""
    report = []
    report.append("# WordPress Installations Report")
    report.append(f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"**Total Sites:** {len(installations)}")
    report.append("")
    
    for i, installation in enumerate(installations, 1):
        report.append(f"## {i}. {installation.get('display_name', 'Unknown')}")
        report.append(f"- **Installation ID:** {installation.get('insid', 'N/A')}")
        report.append(f"- **Domain:** {installation.get('domain', 'N/A')}")
        report.append(f"- **Path:** {installation.get('path', 'N/A')}")
        report.append(f"- **WordPress Version:** {installation.get('version', 'N/A')}")
        report.append(f"- **User:** {installation.get('user', 'N/A')}")
        report.append(f"- **Full URL:** https://{installation.get('domain', '')}{installation.get('path', '')}")
        report.append("")
    
    return "\n".join(report)

# --- A2 Hosting UI Functions ---
def show_a2_hosting_dashboard():
    """A2 Hosting specific dashboard with server info"""
    if 'credentials' in st.session_state:
        creds = st.session_state.credentials
        
        # Server information
        is_a2, server_info = detect_a2_hosting_server(creds['host'])
        
        if is_a2:
            st.sidebar.markdown("### 🏢 A2 Hosting Info")
            st.sidebar.success(f"**Server Location:** {server_info['location']}")
            st.sidebar.info(f"**Server Type:** {server_info['server_type']}")
            
            # A2 Hosting quick links
            st.sidebar.markdown("### 🔗 A2 Hosting Links")
            st.sidebar.markdown("[📧 A2 Support](mailto:support@a2hosting.com)")
            st.sidebar.markdown("[🎫 Submit Ticket](https://my.a2hosting.com/submitticket.php)")
            st.sidebar.markdown("[📚 A2 Knowledge Base](https://www.a2hosting.com/kb)")
            st.sidebar.markdown("[💻 cPanel Direct](https://my.a2hosting.com/clientarea.php)")
        
        # Debug mode toggle
        st.sidebar.markdown("### 🔧 Debug Options")
        st.session_state.debug_mode = st.sidebar.checkbox("Enable Debug Mode", value=False)
        
        if st.session_state.debug_mode:
            st.sidebar.warning("Debug mode enabled - API calls will show detailed information")

def check_a2_hosting_limits():
    """Check if we're approaching A2 Hosting limits"""
    if 'api_call_count' not in st.session_state:
        st.session_state.api_call_count = 0
    
    # A2 Hosting recommended limits
    if st.session_state.api_call_count > 50:
        st.warning("⚠️ You've made many API calls. A2 Hosting may throttle requests.")
        st.info("💡 Consider taking a break or reducing batch sizes.")
    
    elif st.session_state.api_call_count > 30:
        st.info("ℹ️ Approaching A2 Hosting recommended API limits.")

def show_a2_hosting_info():
    """Display A2 Hosting specific information and tips"""
    with st.expander("🏢 A2 Hosting WordPress Management", expanded=False):
        st.markdown("""
        ### 🚀 A2 Hosting WordPress Management
        
        **What makes A2 Hosting special:**
        - **Turbo Servers**: Up to 20x faster page loads
        - **Developer Friendly**: SSH access, staging sites, Git integration
        - **Pre-installed Software**: Softaculous with 1-click WordPress installs
        - **Multiple Server Locations**: USA, Netherlands, Singapore
        
        **A2 Hosting Server Types:**
        - **Shared Hosting**: `nl1-ss##.a2hosting.com`, `sg##.a2hosting.com`
        - **VPS/Dedicated**: `server.a2hosting.com`
        - **Turbo Servers**: Enhanced performance with caching
        
        **Important A2 Hosting Notes:**
        - ⚡ **Turbo Plan**: Some features may work differently on Turbo servers
        - 🔒 **Security**: A2 has additional security layers that may affect API calls
        - 🌍 **Server Location**: Performance varies by server location
        - 📞 **Support**: A2 Hosting has excellent 24/7 support
        
        **Troubleshooting A2 Issues:**
        - **Slow responses**: A2 servers can be slow during peak hours
        - **API limits**: A2 may throttle API calls - use rate limiting
        - **SSL issues**: Some A2 servers use self-signed certificates
        - **Firewall**: A2's firewall may block certain operations
        """)

def show_a2_hosting_login_screen():
    """Enhanced login screen with A2 Hosting (including reseller) support"""
    st.title("🔐 A2 Hosting WordPress Manager")
    st.markdown("### Connect to your A2 Hosting cPanel account")
    
    # Add A2 Hosting branding/info
    st.info("💡 **A2 Hosting Users**: Use your cPanel credentials (works with direct A2 accounts and reseller accounts)")
    
    with st.form("a2_login_form"):
        st.subheader("📋 A2 Hosting cPanel Credentials")
        
        # Helpful hints for A2 users
        with st.expander("🤔 Where do I find these credentials?"):
            st.markdown("""
            **Your A2 Hosting credentials:**
            
            1. **cPanel Host**: Found in your A2 Hosting welcome email
               - **Direct A2**: `server.a2hosting.com` or `nl1-ss##.a2hosting.com`
               - **Reseller Accounts**: Custom domains like `server.clasit.org`
               - Check your hosting account dashboard for the exact server name
            
            2. **cPanel Username**: Usually your domain name or chosen username
               - Found in your A2 Hosting welcome email
               - Same username you use to log into cPanel
            
            3. **cPanel Password**: Your cPanel password
               - Same password you use to log into cPanel
               - Can be reset through A2 Hosting client area
            
            4. **Port**: Usually 2083 (secure) or 2082 (non-secure)
               - A2 Hosting typically uses 2083 for secure connections
            
            **Need help?** Contact A2 Hosting support at support@a2hosting.com
            """)
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Smart host detection
            host = st.text_input(
                "cPanel Host", 
                placeholder="server.clasit.org or server.a2hosting.com",
                help="Your A2 Hosting server name (found in welcome email)"
            )
            
            # Host validation for A2 Hosting (including resellers)
            if host:
                is_a2, server_info = detect_a2_hosting_server(host)
                if is_a2:
                    if 'reseller' in server_info:
                        st.success(f"✅ A2 Hosting Reseller detected: {server_info['reseller']} ({server_info['location']})")
                    else:
                        st.success(f"✅ A2 Hosting server detected: {server_info['location']}")
                else:
                    st.warning("⚠️ This doesn't look like an A2 Hosting server or reseller")
            
            user = st.text_input(
                "cPanel Username", 
                placeholder="your_username",
                help="Your cPanel username (same as cPanel login)"
            )
        
        with col2:
            # A2 Hosting typically uses 2083
            port = st.selectbox(
                "Port", 
                ["2083", "2082"], 
                index=0,
                help="A2 Hosting typically uses 2083 (secure)"
            )
            
            password = st.text_input(
                "cPanel Password", 
                type="password",
                help="Your cPanel password (same as cPanel login)"
            )
        
        # A2 Hosting specific options
        st.subheader("🔧 A2 Hosting Options")
        
        col1, col2 = st.columns(2)
        with col1:
            respect_rate_limits = st.checkbox(
                "Respect A2 rate limits", 
                value=True,
                help="Adds delays between operations to avoid overwhelming A2 servers"
            )
        
        with col2:
            use_secure_connection = st.checkbox(
                "Use secure connection (SSL)", 
                value=True,
                help="Recommended for A2 Hosting (uses port 2083)"
            )
        
        # Override port if secure connection is selected
        if use_secure_connection:
            port = "2083"
        
        submit = st.form_submit_button("🚀 Connect to A2 Hosting", type="primary")
        
        if submit:
            if not all([host, user, password]):
                st.error("❌ Please fill in all A2 Hosting cPanel credentials")
                return
            
            # Validate A2 Hosting format (including resellers)
            validation_errors = validate_a2_credentials(host, user, password, port)
            if validation_errors:
                for error in validation_errors:
                    st.error(f"❌ {error}")
                return
            
            with st.spinner("🔄 Connecting to A2 Hosting cPanel..."):
                if test_a2_cpanel_connection(host, port, user, password):
                    # Store credentials with A2 specific settings
                    st.session_state.credentials = {
                        'host': host,
                        'port': port,
                        'user': user,
                        'pass': password,
                        'provider': 'A2 Hosting',
                        'rate_limits': respect_rate_limits,
                        'secure_connection': use_secure_connection
                    }
                    
                    # Log successful A2 login
                    audit_logger.log_auth_event('A2_LOGIN', 'SUCCESS', 
                                              details={'host': host, 'port': port, 'secure': use_secure_connection})
                    
                    st.success("✅ Successfully connected to A2 Hosting!")
                    st.balloons()  # Celebration for successful connection
                    st.rerun()
                else:
                    st.error("❌ Failed to connect to A2 Hosting cPanel")
                    st.markdown("""
                    **Troubleshooting A2 Hosting Connection:**
                    
                    1. **Double-check credentials**: Verify in your A2 Hosting client area
                    2. **Server name**: Make sure you're using the correct server name
                    3. **Reseller accounts**: Use your reseller's custom domain (e.g., server.clasit.org)
                    4. **Port**: Try port 2082 if 2083 doesn't work
                    5. **Password**: Try resetting your cPanel password
                    6. **IP restrictions**: A2 may block certain IPs
                    
                    **Still having issues?** Contact A2 Hosting support or your reseller
                    """)

def show_main_app():
    """Show the main application interface"""
    # A2 Hosting dashboard
    show_a2_hosting_dashboard()
    
    # Check for A2 limits
    check_a2_hosting_limits()
    
    # Add logout button in sidebar
    with st.sidebar:
        st.markdown("---")
        st.write("### 🔐 Session Info")
        st.write(f"**Host:** {st.session_state.credentials['host']}")
        st.write(f"**User:** {st.session_state.credentials['user']}")
        
        if st.button("🚪 Logout"):
            # Log logout event
            audit_logger.log_auth_event('LOGOUT', 'SUCCESS')
            
            for key in ['credentials', 'installations', 'selected_installation', 'plugins']:
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()

def run_bulk_audit(domains, audit_options):
    """Run bulk audit on selected domains"""
    total_sites = len(domains)
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    results = {
        'success': [],
        'errors': []
    }
    
    # Log start of bulk operation
    audit_logger.log_bulk_operation('BULK_AUDIT_START', total_sites, 
                                   {'success': [], 'errors': []}, 
                                   details={'audit_options': audit_options})
    
    for i, domain in enumerate(domains):
        status_text.text(f"Processing {domain['display_name']} ({i+1}/{total_sites})")
        
        # Update plugins
        if "Update all plugins" in audit_options:
            st.write(f"🔄 Updating plugins for {domain['display_name']}...")
            result, error = update_plugin(domain['insid'])
            if error:
                st.error(f"Plugin update failed for {domain['display_name']}: {error}")
                results['errors'].append(f"Plugin update failed for {domain['display_name']}: {error}")
            else:
                st.success(f"✅ Plugins updated for {domain['display_name']}")
                results['success'].append(f"Plugins updated for {domain['display_name']}")
        
        # Upgrade WordPress core
        if "Upgrade WordPress core" in audit_options:
            st.write(f"⚙️ Upgrading WordPress core for {domain['display_name']}...")
            result, error = upgrade_wordpress_installation(domain['insid'])
            if error:
                st.error(f"Core upgrade failed for {domain['display_name']}: {error}")
                results['errors'].append(f"Core upgrade failed for {domain['display_name']}: {error}")
            else:
                st.success(f"✅ WordPress core upgraded for {domain['display_name']}")
                results['success'].append(f"WordPress core upgraded for {domain['display_name']}")
        
        # Create backups
        if "Create backups" in audit_options:
            st.write(f"💾 Creating backup for {domain['display_name']}...")
            result, error = create_backup(domain['insid'])
            if error:
                st.error(f"Backup failed for {domain['display_name']}: {error}")
                results['errors'].append(f"Backup failed for {domain['display_name']}: {error}")
            else:
                st.success(f"✅ Backup created for {domain['display_name']}")
                results['success'].append(f"Backup created for {domain['display_name']}")
        
        progress_bar.progress((i + 1) / total_sites)
    
    # Log completion of bulk operation
    audit_logger.log_bulk_operation('BULK_AUDIT_COMPLETE', total_sites, results, 
                                   details={'audit_options': audit_options})
    
    # Show final results
    status_text.text("Bulk audit complete!")
    
    with st.expander("📊 Bulk Audit Results Summary"):
        st.write(f"**✅ Successful Operations:** {len(results['success'])}")
        for success in results['success']:
            st.write(f"• {success}")
        
        if results['errors']:
            st.write(f"**❌ Failed Operations:** {len(results['errors'])}")
            for error in results['errors']:
                st.write(f"• {error}")
    
    st.success("🎉 Bulk audit process completed!")

def run_bulk_plugin_update(domains):
    """Run plugin updates on all selected domains"""
    total_sites = len(domains)
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    success_count = 0
    error_count = 0
    results = {'success': [], 'errors': []}
    
    # Log start of bulk operation
    audit_logger.log_bulk_operation('BULK_PLUGIN_UPDATE_START', total_sites, results)
    
    for i, domain in enumerate(domains):
        status_text.text(f"Updating plugins for {domain['display_name']} ({i+1}/{total_sites})")
        
        result, error = update_plugin(domain['insid'])
        if error:
            st.error(f"❌ Plugin update failed for {domain['display_name']}: {error}")
            error_count += 1
            results['errors'].append(f"{domain['display_name']}: {error}")
        else:
            st.success(f"✅ Plugins updated for {domain['display_name']}")
            success_count += 1
            results['success'].append(domain['display_name'])
        
        progress_bar.progress((i + 1) / total_sites)
    
    # Log completion of bulk operation
    audit_logger.log_bulk_operation('BULK_PLUGIN_UPDATE_COMPLETE', total_sites, results)
    
    status_text.text("Plugin updates complete!")
    st.success(f"🎉 Plugin updates completed! ✅ {success_count} successful, ❌ {error_count} failed")

# --- Main Streamlit Application ---
st.set_page_config(page_title="A2 Hosting WordPress Manager", layout="wide")

# Always show the title and instructions at the top
st.title("🔧 A2 Hosting WordPress Manager")
st.markdown("### Enhanced WordPress Management for A2 Hosting (Including Resellers)")

# Instructions Section - Always visible at the top
with st.expander("📖 Instructions - A2 Hosting WordPress Management Guide! 🧙‍♂️", expanded=False):
    st.markdown("""
    # 🎉 Welcome to A2 Hosting WordPress Management!
    
    **Perfect for A2 Hosting customers!** This tool is specifically optimized for A2 Hosting's cPanel and Softaculous integration.
    
    ## 🚀 What This Tool Does
    
    - **🔌 Manage plugins** across all your WordPress sites
    - **🔄 Update everything** with bulk operations
    - **💾 Create and download backups** with compression
    - **⚙️ Upgrade WordPress cores** across multiple sites
    - **📊 Export site inventories** for reporting
    - **🔒 Complete audit logging** for security compliance
    
    ## 🏢 A2 Hosting Benefits
    
    - **Turbo Servers**: Enhanced performance
    - **Multiple Locations**: Netherlands, Singapore, USA
    - **Excellent Support**: 24/7 technical support
    - **Developer Tools**: SSH, Git, staging sites
    
    ## 🔧 Troubleshooting
    
    **If you don't see WordPress sites:**
    1. Make sure you have WordPress sites installed via Softaculous
    2. Check that your cPanel user has permission to manage WordPress
    3. Enable Debug Mode in the sidebar to see detailed API information
    4. Contact A2 Hosting support if issues persist
    
    **Need help?** Contact A2 Hosting support at support@a2hosting.com
    """)

# Show A2 Hosting information
show_a2_hosting_info()

st.markdown("---")

# Check if user is authenticated
if 'credentials' not in st.session_state:
    show_a2_hosting_login_screen()
else:
    show_main_app()

    # Initialize session state
    if 'installations' not in st.session_state:
        st.session_state.installations = []
    if 'selected_installation' not in st.session_state:
        st.session_state.selected_installation = None
    if 'plugins' not in st.session_state:
        st.session_state.plugins = []
    if 'available_backups' not in st.session_state:
        st.session_state.available_backups = {}

    # Load WordPress installations
    if not st.session_state.installations:
        with st.spinner("Loading WordPress installations from A2 Hosting..."):
            installations, error = list_wordpress_installations()
            if error:
                audit_logger.log_auth_event('SITE_DISCOVERY', 'FAILURE', 
                                          details={'error': error})
                st.error(f"Failed to load installations: {error}")
                
                # Show troubleshooting info
                st.markdown("""
                **Troubleshooting WordPress Discovery:**
                
                1. **No WordPress sites found**: Make sure you have WordPress sites installed via Softaculous in cPanel
                2. **API permissions**: Your cPanel user may not have permission to access Softaculous
                3. **Server configuration**: A2 Hosting may have a different Softaculous setup
                4. **Debug mode**: Enable Debug Mode in the sidebar to see detailed API information
                
                **Next steps:**
                - Check your cPanel for WordPress installations
                - Contact A2 Hosting support if you know you have WordPress sites
                - Try logging out and back in with correct credentials
                """)
                
                if not handle_a2_hosting_errors(error):
                    st.error("Please check your A2 Hosting credentials and try again.")
                st.stop()
            else:
                st.session_state.installations = installations
                audit_logger.log_auth_event('SITE_DISCOVERY', 'SUCCESS', 
                                          details={'site_count': len(installations)})

    # Rest of the application continues only if we have installations
    if st.session_state.installations:
        # Domain selection
        st.header("🌐 Select WordPress Installations")
        
        # Export options before domain selection
        st.subheader("📊 Export Site Information")
        st.markdown("Export your WordPress installations data for record-keeping or analysis.")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            # CSV Export
            csv_data = export_sites_to_csv(st.session_state.installations)
            if st.download_button(
                label="📊 Export CSV",
                data=csv_data,
                file_name=f"a2_wordpress_sites_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                help="Download site list as CSV file"
            ):
                audit_logger.log_export_operation('CSV', len(st.session_state.installations), 'SUCCESS')
        
        with col2:
            # JSON Export
            json_data = export_sites_to_json(st.session_state.installations)
            if st.download_button(
                label="📋 Export JSON",
                data=json_data,
                file_name=f"a2_wordpress_sites_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                help="Download site list as JSON file"
            ):
                audit_logger.log_export_operation('JSON', len(st.session_state.installations), 'SUCCESS')
        
        with col3:
            # Markdown Report
            report_data = create_detailed_site_report(st.session_state.installations)
            if st.download_button(
                label="📝 Export Report",
                data=report_data,
                file_name=f"a2_wordpress_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown",
                help="Download detailed markdown report"
            ):
                audit_logger.log_export_operation('MARKDOWN', len(st.session_state.installations), 'SUCCESS')
        
        with col4:
            # Display count
            st.metric("Total Sites", len(st.session_state.installations))
        
        st.markdown("---")
        
        # Create a multiselect for domain selection
        domain_options = [f"{domain['display_name']} (v{domain['version']})" for domain in st.session_state.installations]
        selected_indices = st.multiselect(
            "Select domains to manage:",
            range(len(st.session_state.installations)),
            format_func=lambda x: domain_options[x],
            default=[],
            help="Select one or more WordPress sites to manage"
        )
        
        selected_domains = [st.session_state.installations[i] for i in selected_indices]
        
        if selected_domains:
            st.success(f"✅ Selected {len(selected_domains)} domains for management")
            
            # Display selected domains
            with st.expander("📋 Selected Domains"):
                for domain in selected_domains:
                    st.write(f"• {domain['display_name']} (v{domain['version']}) - User: {domain['user']}")
        else:
            st.warning("⚠️ Please select at least one domain to continue")
            st.stop()
        
        # Continue with the rest of the application...
        st.success("🎉 WordPress sites loaded successfully! You can now manage your sites.")
        st.info("💡 The rest of the site management features will be available once you select domains above.")
    
    else:
        st.info("ℹ️ No WordPress installations found. Please install WordPress via Softaculous in cPanel first.")

    st.markdown("---")
    st.caption("🏢 **Optimized for A2 Hosting** - Works with direct A2 accounts and reseller accounts")
    st.caption("✨ **Enhanced with Comprehensive Audit Logging**")
    st.caption("🔐 **Security & Compliance Ready**")
    st.caption("📋 **Complete Activity Tracking & Monitoring**")
    st.caption("🔗 Uses A2 Hosting's Softaculous WordPress Manager API")
    st.caption("💾 **Audit logs stored in ./logs/ directory**")
    st.caption("📞 **A2 Hosting Support:** support@a2hosting.com")
