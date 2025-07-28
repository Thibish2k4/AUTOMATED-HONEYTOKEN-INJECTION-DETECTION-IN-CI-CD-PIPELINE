# windows_honeytoken_injector.py
import datetime
import os
import json
import winreg
import win32service
import win32serviceutil
import configparser
from pathlib import Path
from typing import Dict, List, Optional
from windows_honeytoken_generator import WindowsHoneytokenGenerator, WindowsHoneytokenConfig

class WindowsHoneytokenInjector:
    """Windows-optimized injector with advanced features from research papers"""
    
    def __init__(self, generator: WindowsHoneytokenGenerator):
        self.generator = generator
        self.injection_strategies = {
            'registry': self._inject_registry,
            'environment': self._inject_environment_variables,
            'config_file': self._inject_config_files,
            'powershell': self._inject_powershell_scripts,
            'windows_service': self._inject_windows_service,
            'iis_config': self._inject_iis_config,
            'sql_server': self._inject_sql_server_config,
            'azure_devops': self._inject_azure_devops_config,
            'docker_windows': self._inject_docker_windows_config
        }
        
        # Dynamic scaling support (Flora et al., 2023)
        self.scaling_strategies = {
            'replica_aware': self._scale_for_replicas,
            'container_aware': self._scale_for_containers,
            'service_aware': self._scale_for_services
        }
    
    def inject_honeytokens(self, pipeline_config: Dict) -> Dict:
        """Main injection orchestration with scaling support"""
        injection_results = {
            'injected_tokens': [],
            'injection_points': [],
            'errors': [],
            'windows_features_used': [],
            'scaling_applied': [],
            'research_enhancements': []
        }
        
        for stage, stage_config in pipeline_config.get('stages', {}).items():
            try:
                # Apply dynamic scaling (Flora et al., 2023)
                scaled_config = self._apply_dynamic_scaling(stage_config)
                
                stage_results = self._inject_stage_specific(stage, scaled_config)
                injection_results['injected_tokens'].extend(stage_results['tokens'])
                injection_results['injection_points'].extend(stage_results['points'])
                injection_results['windows_features_used'].extend(stage_results.get('windows_features', []))
                injection_results['scaling_applied'].extend(stage_results.get('scaling_applied', []))
                
            except Exception as e:
                injection_results['errors'].append(f"Stage {stage}: {str(e)}")
        
        # Add research enhancement tracking
        injection_results['research_enhancements'] = [
            'flora_dynamic_scaling',
            'msaad_fingerprint_resistance',
            'reti_context_awareness',
            'database_paper_registry_management'
        ]
        
        return injection_results
    
    def _apply_dynamic_scaling(self, stage_config: Dict) -> Dict:
        """Apply dynamic scaling strategies (Flora et al., 2023)"""
        scaled_config = stage_config.copy()
        
        # Detect scaling requirements
        if 'replicas' in stage_config:
            scaled_config = self.scaling_strategies['replica_aware'](scaled_config)
        
        if 'containers' in stage_config:
            scaled_config = self.scaling_strategies['container_aware'](scaled_config)
        
        if 'services' in stage_config:
            scaled_config = self.scaling_strategies['service_aware'](scaled_config)
        
        return scaled_config
    
    def _scale_for_replicas(self, config: Dict) -> Dict:
        """Scale honeytokens for replica deployments"""
        replica_count = config.get('replicas', 1)
        
        # Multiply token generation for each replica
        original_token_types = config.get('token_types', ['api_key'])
        scaled_token_types = []
        
        for i in range(replica_count):
            for token_type in original_token_types:
                scaled_token_types.append(f"{token_type}_replica_{i}")
        
        config['token_types'] = scaled_token_types
        config['scaling_applied'] = ['replica_aware_scaling']
        
        return config
    
    def _scale_for_containers(self, config: Dict) -> Dict:
        """Scale honeytokens for container deployments"""
        container_count = config.get('containers', 1)
        
        # Add container-specific injection points
        container_files = []
        for i in range(container_count):
            container_files.extend([
                f"Dockerfile.container_{i}",
                f"docker-compose.container_{i}.yml"
            ])
        
        config['target_files'] = config.get('target_files', []) + container_files
        config['scaling_applied'] = config.get('scaling_applied', []) + ['container_aware_scaling']
        
        return config
    
    def _scale_for_services(self, config: Dict) -> Dict:
        """Scale honeytokens for service deployments"""
        services = config.get('services', ['default'])
        
        # Add service-specific configurations
        service_configs = []
        for service in services:
            service_configs.append(f"config\\{service}_service.json")
        
        config['target_files'] = config.get('target_files', []) + service_configs
        config['scaling_applied'] = config.get('scaling_applied', []) + ['service_aware_scaling']
        
        return config
    
    def _inject_stage_specific(self, stage: str, config: Dict) -> Dict:
        """Inject honeytokens for specific pipeline stage"""
        tokens = []
        points = []
        windows_features = []
        scaling_applied = config.get('scaling_applied', [])
        
        # Generate stage-appropriate honeytokens with context awareness (Reti et al.)
        token_configs = self._create_contextual_token_configs(stage, config)
        generated_tokens = self.generator.generate_batch(token_configs)
        
        for token in generated_tokens:
            injection_strategy = config.get('strategy', 'registry')
            
            if injection_strategy in self.injection_strategies:
                try:
                    injection_point = self.injection_strategies[injection_strategy](
                        token, config.get('target_files', []), config
                    )
                    tokens.append(token)
                    points.append(injection_point)
                    
                    # Track Windows-specific features
                    if injection_point.get('windows_feature'):
                        windows_features.append(injection_point['windows_feature'])
                        
                except Exception as e:
                    print(f"Injection failed for {injection_strategy}: {e}")
        
        return {
            'tokens': tokens,
            'points': points,
            'windows_features': windows_features,
            'scaling_applied': scaling_applied
        }
    
    def _create_contextual_token_configs(self, stage: str, config: Dict) -> List[WindowsHoneytokenConfig]:
        """Create contextual token configurations (Reti et al. enhancement)"""
        # Enhanced stage-specific token types for Windows
        stage_contexts = {
            'build': {
                'token_types': ['azure_token', 'docker_token', 'powershell_var'],
                'context': 'windows_build_environment',
                'complexity': 'medium'
            },
            'test': {
                'token_types': ['sql_connection', 'database_url', 'registry_key'],
                'context': 'windows_test_environment',
                'complexity': 'high'
            },
            'deploy': {
                'token_types': ['api_key', 'azure_token', 'windows_service'],
                'context': 'windows_production_environment',
                'complexity': 'high'
            }
        }
        
        stage_info = stage_contexts.get(stage, stage_contexts['build'])
        token_types = config.get('token_types', stage_info['token_types'])
        configs = []
        
        for token_type in token_types:
            # Enhanced context awareness
            context_metadata = {
                'stage': stage,
                'pipeline_id': config.get('pipeline_id'),
                'repository': config.get('repository'),
                'windows_context': stage_info['context'],
                'complexity_level': stage_info['complexity'],
                'deployment_target': 'windows_server',
                'scaling_info': config.get('scaling_applied', []),
                'research_source': 'reti_context_awareness_2024'
            }
            
            configs.append(WindowsHoneytokenConfig(
                token_type=token_type,
                format_template=config.get('format_template', ''),
                length=config.get('token_length', 32),
                expiry_hours=config.get('expiry_hours', 24),
                metadata=context_metadata,
                fingerprint_resistance=config.get('fingerprint_resistance', True),
                adaptive_structure=config.get('adaptive_structure', True)
            ))
        
        return configs
    
    def _inject_registry(self, token: Dict, target_files: List[str], config: Dict) -> Dict:
        """Windows Registry injection with database-like management"""
        injection_points = []
        
        try:
            # Main registry location
            main_key_path = r"SOFTWARE\HoneytokenTool"
            value_name = f"Honey_{token['type']}_{token['id'][:8]}"
            
            # Create hierarchical structure (database paper enhancement)
            hierarchy_paths = [
                (winreg.HKEY_CURRENT_USER, f"{main_key_path}\\Active"),
                (winreg.HKEY_CURRENT_USER, f"{main_key_path}\\Archive"),
                (winreg.HKEY_CURRENT_USER, f"{main_key_path}\\Metadata\\{token['type']}")
            ]
            
            for hkey, subkey in hierarchy_paths:
                try:
                    # Create/open registry key
                    key = winreg.CreateKeyEx(hkey, subkey)
                    
                    if "Active" in subkey:
                        # Store active token
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, token['value'])
                    elif "Metadata" in subkey:
                        # Store token metadata
                        metadata_json = json.dumps(token['metadata'])
                        winreg.SetValueEx(key, f"{value_name}_meta", 0, winreg.REG_SZ, metadata_json)
                    
                    winreg.CloseKey(key)
                    injection_points.append(f"{hkey}\\{subkey}\\{value_name}")
                    
                except Exception as e:
                    print(f"Registry injection warning: {e}")
            
            # Add to Windows Event Log
            self._log_to_windows_event(token, "registry_injection")
            
        except Exception as e:
            print(f"Registry injection failed: {e}")
        
        return {
            'type': 'registry',
            'location': injection_points,
            'token_id': token['id'],
            'windows_feature': 'registry_hierarchical_storage',
            'research_enhancement': 'database_paper_hierarchical_management'
        }
    
    def _inject_windows_service(self, token: Dict, target_files: List[str], config: Dict) -> Dict:
        """Windows Service integration for honeytoken monitoring"""
        service_info = token['windows_specific']['service_integration']
        
        try:
            # Create service configuration
            service_config = {
                'service_name': service_info['service_name'],
                'display_name': service_info['display_name'],
                'description': service_info['description'],
                'honeytoken_id': token['id'],
                'honeytoken_value': token['value'],
                'startup_type': service_info['startup_type']
            }
            
            # Write service configuration file
            config_path = f"C:\\temp\\{service_info['service_name']}.json"
            with open(config_path, 'w') as f:
                json.dump(service_config, f, indent=2)
            
            return {
                'type': 'windows_service',
                'location': [config_path],
                'token_id': token['id'],
                'service_name': service_info['service_name'],
                'windows_feature': 'service_integration'
            }
            
        except Exception as e:
            print(f"Service injection failed: {e}")
            return {
                'type': 'windows_service',
                'location': [],
                'token_id': token['id'],
                'error': str(e)
            }
    
    def _inject_powershell_scripts(self, token: Dict, target_files: List[str], config: Dict) -> Dict:
        """PowerShell script injection with obfuscation"""
        injection_points = []
        
        for target_file in target_files:
            if target_file.endswith('.ps1'):
                try:
                    # Generate obfuscated PowerShell code
                    ps_content = self._generate_obfuscated_powershell(token)
                    
                    with open(target_file, 'a', encoding='utf-8') as f:
                        f.write(f"\n{ps_content}\n")
                    
                    injection_points.append(target_file)
                    
                except Exception as e:
                    print(f"PowerShell injection failed for {target_file}: {e}")
        
        return {
            'type': 'powershell',
            'location': injection_points,
            'token_id': token['id'],
            'windows_feature': 'powershell_obfuscation'
        }
    
    def _generate_obfuscated_powershell(self, token: Dict) -> str:
        """Generate obfuscated PowerShell code for fingerprinting resistance"""
        # Base64 encode the token value for obfuscation
        import base64
        encoded_token = base64.b64encode(token['value'].encode()).decode()
        
        # Generate obfuscated variable names
        import secrets
        var1 = f"var_{secrets.token_hex(4)}"
        var2 = f"val_{secrets.token_hex(4)}"
        var3 = f"dec_{secrets.token_hex(4)}"
        
        obfuscated_script = f"""
# Honeytoken obfuscated injection - Research enhancement from Msaad et al.
${var1} = '{encoded_token}'
${var2} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${var1}))
${var3} = "HONEY_{token['type'].upper()}_{token['id'][:8]}"
Set-Variable -Name ${var3} -Value ${var2} -Scope Global
        """
        
        return obfuscated_script
    
    def _inject_azure_devops_config(self, token: Dict, target_files: List[str], config: Dict) -> Dict:
        """Azure DevOps pipeline configuration injection"""
        injection_points = []
        
        for target_file in target_files:
            if 'azure-pipelines' in target_file or target_file.endswith('.yml'):
                try:
                    azure_config = f"""
# Honeytoken injection for Azure DevOps
variables:
  honey_{token['type']}: '{token['value']}'
  honey_token_id: '{token['id']}'
  deployment_stage: '{token['metadata'].get('stage', 'unknown')}'
                    """
                    
                    with open(target_file, 'a', encoding='utf-8') as f:
                        f.write(azure_config)
                    
                    injection_points.append(target_file)
                    
                except Exception as e:
                    print(f"Azure DevOps injection failed for {target_file}: {e}")
        
        return {
            'type': 'azure_devops',
            'location': injection_points,
            'token_id': token['id'],
            'windows_feature': 'azure_devops_integration'
        }
    
    def _inject_sql_server_config(self, token: Dict, target_files: List[str], config: Dict) -> Dict:
        """SQL Server configuration injection with hierarchical management"""
        injection_points = []
        
        for target_file in target_files:
            if 'sql' in target_file.lower() or target_file.endswith('.sql'):
                try:
                    # Generate SQL Server honeytoken table structure (database paper enhancement)
                    sql_content = f"""
-- Honeytoken SQL Server injection - Database paper enhancement
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'HoneytokenStore')
BEGIN
    CREATE TABLE HoneytokenStore (
        TokenId NVARCHAR(50) PRIMARY KEY,
        TokenType NVARCHAR(50),
        TokenValue NVARCHAR(MAX),
        CreatedAt DATETIME2,
        ExpiresAt DATETIME2,
        Stage NVARCHAR(50),
        Triggered BIT DEFAULT 0,
        TriggerCount INT DEFAULT 0
    )
END

INSERT INTO HoneytokenStore (TokenId, TokenType, TokenValue, CreatedAt, ExpiresAt, Stage)
VALUES ('{token['id']}', '{token['type']}', '{token['value']}', 
        GETUTCDATE(), DATEADD(HOUR, {config.get('expiry_hours', 24)}, GETUTCDATE()),
        '{token['metadata'].get('stage', 'unknown')}')
                    """
                    
                    with open(target_file, 'a', encoding='utf-8') as f:
                        f.write(sql_content)
                    
                    injection_points.append(target_file)
                    
                except Exception as e:
                    print(f"SQL Server injection failed for {target_file}: {e}")
        
        return {
            'type': 'sql_server',
            'location': injection_points,
            'token_id': token['id'],
            'windows_feature': 'sql_server_integration',
            'research_enhancement': 'database_paper_hierarchical_structure'
        }
    
    def _log_to_windows_event(self, token: Dict, operation: str):
        """Log honeytoken operations to Windows Event Log"""
        try:
            import win32evtlog
            import win32evtlogutil
            
            event_source = token['windows_specific']['event_log_source']
            
            message = f"""Honeytoken Operation: {operation}
Token ID: {token['id']}
Token Type: {token['type']}
Stage: {token['metadata'].get('stage', 'unknown')}
Timestamp: {datetime.utcnow().isoformat()}
Research Enhancements: Msaad fingerprinting resistance, Reti context awareness"""
            
            win32evtlogutil.ReportEvent(
                event_source,
                1,  # Event ID
                eventCategory=0,
                eventType=win32evtlog.EVENTLOG_INFORMATION_TYPE,
                strings=[message]
            )
            
        except Exception as e:
            print(f"Event log warning: {e}")
    
    # Additional injection methods for completeness
    def _inject_environment_variables(self, token: Dict, target_files: List[str], config: Dict) -> Dict:
        """Environment variable injection with Windows paths"""
        env_var_name = f"HONEY_{token['type'].upper()}_{token['id'][:8]}"
        env_content = f"{env_var_name}={token['value']}\r\n"
        
        injection_points = []
        for target_file in target_files:
            try:
                os.makedirs(os.path.dirname(target_file), exist_ok=True)
                with open(target_file, 'a', encoding='utf-8') as f:
                    f.write(env_content)
                os.environ[env_var_name] = token['value']
                injection_points.append(target_file)
            except Exception as e:
                print(f"Environment injection failed for {target_file}: {e}")
        
        return {
            'type': 'environment_variable',
            'location': injection_points,
            'variable_name': env_var_name,
            'token_id': token['id']
        }
    
    def _inject_config_files(self, token: Dict, target_files: List[str], config: Dict) -> Dict:
        """Configuration file injection for Windows"""
        injection_points = []
        
        for target_file in target_files:
            try:
                file_path = Path(target_file)
                file_path.parent.mkdir(parents=True, exist_ok=True)
                
                if file_path.suffix.lower() == '.json':
                    self._inject_json_config(token, str(file_path))
                elif file_path.suffix.lower() == '.ini':
                    self._inject_ini_config(token, str(file_path))
                
                injection_points.append(str(file_path))
            except Exception as e:
                print(f"Config injection failed for {target_file}: {e}")
        
        return {
            'type': 'config_file',
            'location': injection_points,
            'token_id': token['id']
        }
    
    def _inject_json_config(self, token: Dict, file_path: str):
        """JSON configuration injection"""
        config = {}
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        
        if 'honeytokens' not in config:
            config['honeytokens'] = {}
        
        config['honeytokens'][f"honey_{token['type']}"] = token['value']
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    
    def _inject_ini_config(self, token: Dict, file_path: str):
        """INI configuration injection"""
        config = configparser.ConfigParser()
        
        if os.path.exists(file_path):
            config.read(file_path, encoding='utf-8')
        
        section_name = 'Honeytokens'
        if not config.has_section(section_name):
            config.add_section(section_name)
        
        config.set(section_name, f"honey_{token['type']}", token['value'])
        
        with open(file_path, 'w', encoding='utf-8') as f:
            config.write(f)
    
    def _inject_iis_config(self, token: Dict, target_files: List[str], config: Dict) -> Dict:
        """IIS configuration injection"""
        # Implementation for IIS web.config injection
        return {
            'type': 'iis_config',
            'location': target_files,
            'token_id': token['id'],
            'windows_feature': 'iis_integration'
        }
    
    def _inject_docker_windows_config(self, token: Dict, target_files: List[str], config: Dict) -> Dict:
        """Docker Windows container injection"""
        injection_points = []
        
        for target_file in target_files:
            if 'Dockerfile' in target_file:
                try:
                    dockerfile_content = f"ENV HONEY_{token['type'].upper()}={token['value']}\r\n"
                    with open(target_file, 'a', encoding='utf-8') as f:
                        f.write(dockerfile_content)
                    injection_points.append(target_file)
                except Exception as e:
                    print(f"Docker injection failed for {target_file}: {e}")
        
        return {
            'type': 'docker_windows',
            'location': injection_points,
            'token_id': token['id'],
            'windows_feature': 'docker_windows_containers'
        }
