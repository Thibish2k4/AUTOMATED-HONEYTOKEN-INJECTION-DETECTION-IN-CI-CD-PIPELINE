# windows_honeytoken_generator.py
import secrets
import string
import json
import hashlib
import winreg
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class WindowsHoneytokenConfig:
    token_type: str
    format_template: str
    length: int
    expiry_hours: int
    metadata: Dict
    fingerprint_resistance: bool = True
    adaptive_structure: bool = True

class WindowsHoneytokenGenerator:
    """Windows-optimized honeytoken generator with advanced features from research papers"""
    
    def __init__(self):
        self.token_templates = {
            'api_key': 'sk-{random_string}',
            'database_url': 'Server={host};Database=HoneyDB;Integrated Security=true;',
            'jwt_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.{payload}.{signature}',
            'aws_access_key': 'AKIA{random_string}',
            'azure_token': 'azure_{random_string}',
            'docker_token': 'dckr_pat_{random_string}',
            'github_token': 'ghp_{random_string}',
            'sql_connection': 'Data Source={host};Initial Catalog=HoneyDB;User ID={username};Password={password}',
            'registry_key': 'HKEY_CURRENT_USER\\SOFTWARE\\{company}\\{product}\\{key_name}',
            'powershell_var': '$honey_{var_name} = "{value}"'
        }
        
        # Fingerprinting resistance data (from Msaad et al.)
        self.fingerprint_countermeasures = {
            'randomize_id_length': True,
            'vary_file_sizes': True,
            'dynamic_templates': True,
            'obfuscated_metadata': True
        }
    
    def generate_honeytoken(self, config: WindowsHoneytokenConfig) -> Dict:
        """Generate Windows-optimized honeytoken with fingerprinting resistance"""
        token_id = self._generate_adaptive_id(config)
        token_value = self._create_adaptive_token_value(config)
        
        # Apply fingerprinting resistance (Msaad et al., 2023)
        if config.fingerprint_resistance:
            token_value = self._apply_fingerprint_resistance(token_value, config)
        
        honeytoken = {
            'id': token_id,
            'type': config.token_type,
            'value': token_value,
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(hours=config.expiry_hours)).isoformat(),
            'metadata': self._generate_adaptive_metadata(config),
            'triggered': False,
            'trigger_count': 0,
            'windows_specific': {
                'registry_location': self._get_registry_location(config),
                'service_integration': self._get_service_integration(config),
                'event_log_source': f"HoneyToken_{config.token_type}"
            },
            'fingerprint_resistance': {
                'applied': config.fingerprint_resistance,
                'randomized_length': self._get_randomized_length(config),
                'obfuscation_level': self._calculate_obfuscation_level(config)
            }
        }
        
        return honeytoken
    
    def generate_batch(self, configs: List[WindowsHoneytokenConfig]) -> List[Dict]:
        """Generate multiple honeytokens in batch (Flora et al. scaling support)"""
        batch_results = []
        
        for config in configs:
            try:
                token = self.generate_honeytoken(config)
                batch_results.append(token)
            except Exception as e:
                # Add error token for debugging
                batch_results.append({
                    'id': f'error_{secrets.token_hex(4)}',
                    'type': config.token_type if hasattr(config, 'token_type') else 'unknown',
                    'error': str(e),
                    'created_at': datetime.utcnow().isoformat()
                })
        
        return batch_results
    
    def _generate_adaptive_id(self, config: WindowsHoneytokenConfig) -> str:
        """Generate adaptive ID with dynamic length (Msaad et al. improvement)"""
        base_data = f"{datetime.utcnow().isoformat()}{secrets.randbits(128)}"
        
        # Randomize ID length to prevent fingerprinting
        if config.fingerprint_resistance:
            id_length = secrets.randbelow(8) + 12  # Random length between 12-20
        else:
            id_length = 16
        
        return hashlib.sha256(base_data.encode()).hexdigest()[:id_length]
    
    def _create_adaptive_token_value(self, config: WindowsHoneytokenConfig) -> str:
        """Create adaptive token with context awareness (Reti et al. enhancement)"""
        base_template = self.token_templates.get(config.token_type, config.format_template)
        
        # Context-aware replacements for Windows environment
        replacements = {
            'random_string': self._generate_adaptive_random_string(config),
            'host': self._generate_windows_hostname(),
            'username': self._generate_windows_username(),
            'password': self._generate_windows_password(config),
            'company': 'HoneyCorpLtd',
            'product': f'Honey{config.token_type.title()}Tool',
            'key_name': f'Config_{secrets.token_hex(4)}',
            'var_name': config.token_type.lower(),
            'value': secrets.token_hex(16),
            'payload': self._generate_adaptive_jwt_payload(config),
            'signature': self._generate_adaptive_signature(config)
        }
        
        result = base_template
        for key, value in replacements.items():
            result = result.replace(f'{{{key}}}', str(value))
        
        return result
    
    def _apply_fingerprint_resistance(self, token_value: str, config: WindowsHoneytokenConfig) -> str:
        """Apply fingerprinting resistance measures (Msaad et al., 2023)"""
        if not config.fingerprint_resistance:
            return token_value
        
        # Add random padding to vary token sizes
        if self.fingerprint_countermeasures['vary_file_sizes']:
            padding_length = secrets.randbelow(20) + 5
            padding = secrets.token_hex(padding_length // 2)
            token_value = f"{token_value}#{padding}"
        
        # Randomize case for certain token types
        if config.token_type in ['api_key', 'github_token']:
            token_parts = token_value.split('_')
            if len(token_parts) > 1:
                # Randomly capitalize parts
                token_parts = [part.upper() if secrets.randbelow(2) else part.lower() 
                              for part in token_parts]
                token_value = '_'.join(token_parts)
        
        return token_value
    
    def _generate_adaptive_metadata(self, config: WindowsHoneytokenConfig) -> Dict:
        """Generate adaptive metadata that changes based on context"""
        base_metadata = config.metadata.copy()
        
        # Add Windows-specific metadata
        base_metadata.update({
            'windows_version': self._get_windows_version(),
            'deployment_strategy': 'windows_optimized',
            'resistance_features': list(self.fingerprint_countermeasures.keys()),
            'adaptive_features': ['context_aware_generation', 'dynamic_obfuscation'],
            'research_implementations': [
                'msaad_fingerprint_resistance',
                'reti_context_awareness',
                'flora_scaling_support'
            ]
        })
        
        # Obfuscate metadata if fingerprint resistance is enabled
        if config.fingerprint_resistance and self.fingerprint_countermeasures['obfuscated_metadata']:
            obfuscated_keys = {}
            for key, value in base_metadata.items():
                if isinstance(value, str) and len(value) > 5:
                    # Add random prefix/suffix to string values
                    prefix = secrets.token_hex(2)
                    suffix = secrets.token_hex(2)
                    obfuscated_keys[f"{prefix}_{key}_{suffix}"] = value
                else:
                    obfuscated_keys[key] = value
            return obfuscated_keys
        
        return base_metadata
    
    def _generate_adaptive_random_string(self, config: WindowsHoneytokenConfig) -> str:
        """Generate adaptive random string based on token type and context"""
        base_length = config.length
        
        # Adjust length based on token type and fingerprinting resistance
        if config.fingerprint_resistance:
            length_variation = secrets.randbelow(8) - 4  # ±4 characters
            actual_length = max(8, base_length + length_variation)
        else:
            actual_length = base_length
        
        # Use different character sets based on token type
        if config.token_type in ['api_key', 'github_token']:
            chars = string.ascii_letters + string.digits
        elif config.token_type in ['sql_connection', 'database_url']:
            chars = string.ascii_letters + string.digits + '_-'
        else:
            chars = string.ascii_letters + string.digits
        
        return ''.join(secrets.choice(chars) for _ in range(actual_length))
    
    def _generate_windows_hostname(self) -> str:
        """Generate realistic Windows hostname"""
        prefixes = ['WIN-SRV', 'HONEY-DB', 'APP-SVR', 'WEB-HOST', 'DEV-BOX']
        suffix = secrets.token_hex(4).upper()
        return f"{secrets.choice(prefixes)}-{suffix}"
    
    def _generate_windows_username(self) -> str:
        """Generate realistic Windows username"""
        usernames = ['sa', 'admin', 'service_account', 'db_user', 'app_service']
        return secrets.choice(usernames)
    
    def _generate_windows_password(self, config: WindowsHoneytokenConfig) -> str:
        """Generate Windows-compliant password"""
        # Windows password complexity requirements
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password_length = 12 if not config.fingerprint_resistance else secrets.randbelow(8) + 10
        return ''.join(secrets.choice(chars) for _ in range(password_length))
    
    def _get_windows_version(self) -> str:
        """Get Windows version information"""
        try:
            import platform
            return f"{platform.system()} {platform.release()}"
        except:
            return "Windows 10"
    
    def _get_registry_location(self, config: WindowsHoneytokenConfig) -> str:
        """Get appropriate Windows Registry location for token"""
        base_paths = [
            r"HKEY_CURRENT_USER\SOFTWARE\HoneytokenTool",
            r"HKEY_LOCAL_MACHINE\SOFTWARE\HoneytokenTool",
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\HoneyApp"
        ]
        
        token_path = f"{secrets.choice(base_paths)}\\{config.token_type}_{config.metadata.get('stage', 'default')}"
        return token_path
    
    def _get_service_integration(self, config: WindowsHoneytokenConfig) -> Dict:
        """Get Windows service integration details"""
        return {
            'service_name': f"HoneyService_{config.token_type}",
            'display_name': f"Honey {config.token_type.title()} Service",
            'description': f"Honeytoken monitoring service for {config.token_type}",
            'startup_type': "Automatic"
        }
    
    def _generate_adaptive_jwt_payload(self, config: WindowsHoneytokenConfig) -> str:
        """Generate adaptive JWT payload"""
        import base64
        
        payload_data = {
            "sub": f"honey_user_{secrets.token_hex(4)}",
            "iat": int(datetime.utcnow().timestamp()),
            "exp": int((datetime.utcnow() + timedelta(hours=config.expiry_hours)).timestamp()),
            "iss": "HoneyTokenIssuer",
            "aud": "windows-cicd-pipeline",
            "stage": config.metadata.get('stage', 'unknown')
        }
        
        # Add random claims for fingerprinting resistance
        if config.fingerprint_resistance:
            random_claims = {
                f"claim_{i}": secrets.token_hex(8) 
                for i in range(secrets.randbelow(3) + 1)
            }
            payload_data.update(random_claims)
        
        payload_json = json.dumps(payload_data)
        return base64.b64encode(payload_json.encode()).decode().rstrip('=')
    
    def _generate_adaptive_signature(self, config: WindowsHoneytokenConfig) -> str:
        """Generate adaptive signature for tokens"""
        base_length = 43
        
        if config.fingerprint_resistance:
            # Vary signature length to prevent fingerprinting
            length_variation = secrets.randbelow(6) - 3
            signature_length = max(20, base_length + length_variation)
        else:
            signature_length = base_length
        
        chars = string.ascii_letters + string.digits + '-_'
        return ''.join(secrets.choice(chars) for _ in range(signature_length))
    
    def _get_randomized_length(self, config: WindowsHoneytokenConfig) -> int:
        """Get randomized length for fingerprint resistance"""
        if config.fingerprint_resistance:
            return config.length + secrets.randbelow(10) - 5
        return config.length
    
    def _calculate_obfuscation_level(self, config: WindowsHoneytokenConfig) -> str:
        """Calculate obfuscation level based on configuration"""
        if not config.fingerprint_resistance:
            return "none"
        
        obfuscation_features = sum([
            self.fingerprint_countermeasures['randomize_id_length'],
            self.fingerprint_countermeasures['vary_file_sizes'],
            self.fingerprint_countermeasures['dynamic_templates'],
            self.fingerprint_countermeasures['obfuscated_metadata']
        ])
        
        if obfuscation_features >= 3:
            return "high"
        elif obfuscation_features >= 2:
            return "medium"
        else:
            return "low"
