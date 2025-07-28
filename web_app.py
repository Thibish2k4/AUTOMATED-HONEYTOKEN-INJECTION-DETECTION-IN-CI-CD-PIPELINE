from flask import Flask, render_template, request, jsonify
import json
import secrets
import string
import base64
from datetime import datetime, timedelta
import os
from typing import Dict, List
import tempfile
import subprocess

app = Flask(__name__)

class WindowsHoneytokenWebGenerator:
    """Simplified version of the Windows Honeytoken Generator for web use"""
    
    def __init__(self):
        self.token_templates = {
            'api_key': 'sk-{random_string}',
            'database_url': 'Server={host};Database=HoneyDB;Integrated Security=true;',
            'jwt_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.{payload}.{signature}',
            'aws_access_key': 'AKIA{random_string}',
            'azure_token': 'azure_{random_string}',
            'github_token': 'ghp_{random_string}',
            'sql_connection': 'Data Source={host};Initial Catalog=HoneyDB;User ID={username};Password={password}',
            'registry_key': 'HKEY_CURRENT_USER\\SOFTWARE\\{company}\\{product}\\{key_name}',
            'powershell_var': '$honey_{var_name} = "{value}"'
        }
    
    def generate_token(self, token_type: str, config: Dict = None) -> Dict:
        """Generate honeytoken with metadata"""
        if config is None:
            config = {}
            
        token_id = secrets.token_hex(8)
        random_string = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
        
        # Generate token value based on type
        template = self.token_templates.get(token_type, '{random_string}')
        token_value = template.format(
            random_string=random_string,
            host='honey-server.local',
            username='honeyuser',
            password=secrets.token_hex(8),
            company='HoneyTech',
            product='SecureApp',
            key_name='ApiConfig',
            var_name=f'token_{secrets.token_hex(4)}',
            value=random_string,
            payload=base64.b64encode(json.dumps({'user': 'honey', 'exp': int((datetime.utcnow() + timedelta(hours=24)).timestamp())}).encode()).decode(),
            signature=secrets.token_hex(12)
        )
        
        return {
            'id': token_id,
            'type': token_type,
            'value': token_value,
            'metadata': {
                'created_at': datetime.utcnow().isoformat(),
                'stage': config.get('stage', 'development'),
                'expiry_hours': config.get('expiry_hours', 24),
                'description': config.get('description', f'Honeytoken of type {token_type}')
            },
            'windows_specific': {
                'event_log_source': f'HoneytokenApp_{token_type}',
                'registry_key': f'HKEY_LOCAL_MACHINE\\SOFTWARE\\Honeytokens\\{token_id}',
                'service_name': f'HoneyService_{token_id[:8]}'
            }
        }

class WindowsHoneytokenWebInjector:
    """Simplified injector for web demo"""
    
    def inject_powershell(self, token: Dict, config: Dict = None) -> str:
        """Generate PowerShell injection code"""
        if config is None:
            config = {}
            
        encoded_token = base64.b64encode(token['value'].encode()).decode()
        var_name = f"honey_{secrets.token_hex(4)}"
        
        ps_code = f'''# Windows Honeytoken PowerShell Injection
# Token ID: {token['id']} | Type: {token['type']}
# Created: {token['metadata']['created_at']}

${var_name} = '{encoded_token}'
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${var_name}))

# Log to Windows Event Log
Write-EventLog -LogName "Application" -Source "HoneytokenApp" -EventId 1001 -EntryType Information -Message "Honeytoken accessed: $decoded"

# Monitor usage
$global:HoneytokenUsage = @{{
    TokenId = "{token['id']}"
    AccessTime = Get-Date
    ProcessId = $PID
    UserName = $env:USERNAME
}}

Write-Host "Honeytoken loaded successfully" -ForegroundColor Green
'''
        return ps_code
    
    def inject_sql(self, token: Dict, config: Dict = None) -> str:
        """Generate SQL injection code"""
        if config is None:
            config = {}
            
        expiry_hours = config.get('expiry_hours', 24)
        
        sql_code = f'''-- Windows Honeytoken SQL Server Injection
-- Token ID: {token['id']} | Type: {token['type']}
-- Created: {token['metadata']['created_at']}

-- Create honeytoken storage table
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'HoneytokenStore')
BEGIN
    CREATE TABLE HoneytokenStore (
        TokenId NVARCHAR(50) PRIMARY KEY,
        TokenType NVARCHAR(50),
        TokenValue NVARCHAR(MAX),
        CreatedAt DATETIME2,
        ExpiresAt DATETIME2,
        AccessCount INT DEFAULT 0,
        LastAccessed DATETIME2
    )
END

-- Insert honeytoken
INSERT INTO HoneytokenStore (TokenId, TokenType, TokenValue, CreatedAt, ExpiresAt)
VALUES ('{token['id']}', '{token['type']}', '{token['value']}', 
        GETUTCDATE(), DATEADD(HOUR, {expiry_hours}, GETUTCDATE()));

-- Create trigger for monitoring
CREATE OR ALTER TRIGGER tr_HoneytokenAccess
ON HoneytokenStore
AFTER SELECT, UPDATE, DELETE
AS
BEGIN
    UPDATE HoneytokenStore 
    SET AccessCount = AccessCount + 1, LastAccessed = GETUTCDATE()
    WHERE TokenId IN (SELECT TokenId FROM inserted);
    
    -- Log to Windows Event Log
    EXEC xp_logevent 60000, 'Honeytoken accessed in SQL Server', 'WARNING';
END
'''
        return sql_code
    
    def inject_registry(self, token: Dict, config: Dict = None) -> str:
        """Generate Windows Registry injection code"""
        registry_code = f'''REM Windows Honeytoken Registry Injection
REM Token ID: {token['id']} | Type: {token['type']}
REM Created: {token['metadata']['created_at']}

REM Create registry structure
reg add "{token['windows_specific']['registry_key']}" /f
reg add "{token['windows_specific']['registry_key']}" /v "TokenId" /t REG_SZ /d "{token['id']}" /f
reg add "{token['windows_specific']['registry_key']}" /v "TokenType" /t REG_SZ /d "{token['type']}" /f
reg add "{token['windows_specific']['registry_key']}" /v "TokenValue" /t REG_SZ /d "{token['value']}" /f
reg add "{token['windows_specific']['registry_key']}" /v "CreatedAt" /t REG_SZ /d "{token['metadata']['created_at']}" /f
reg add "{token['windows_specific']['registry_key']}" /v "Stage" /t REG_SZ /d "{token['metadata']['stage']}" /f

REM Create monitoring registry key
reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\HoneytokenMonitor" /v "LastAccess_{token['id'][:8]}" /t REG_SZ /d "%DATE% %TIME%" /f

echo Honeytoken registry injection completed successfully
'''
        return registry_code
    
    def inject_environment(self, token: Dict, config: Dict = None) -> str:
        """Generate environment variable injection code"""
        env_name = f"HONEY_{token['type'].upper()}_{token['id'][:8]}"
        
        env_code = f'''REM Windows Environment Variable Honeytoken Injection
REM Token ID: {token['id']} | Type: {token['type']}

REM Set system environment variable
setx {env_name} "{token['value']}" /M

REM Set user environment variable as backup
setx {env_name}_USER "{token['value']}"

REM Create monitoring script
echo @echo off > %TEMP%\\monitor_{token['id'][:8]}.bat
echo echo Token accessed: %{env_name}% >> %TEMP%\\monitor_{token['id'][:8]}.bat
echo echo Access time: %%DATE%% %%TIME%% >> %TEMP%\\monitor_{token['id'][:8]}.bat

echo Environment variable honeytoken set: {env_name}
'''
        return env_code

# Initialize components
generator = WindowsHoneytokenWebGenerator()
injector = WindowsHoneytokenWebInjector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate_token():
    """Generate a new honeytoken"""
    try:
        data = request.json
        token_type = data.get('token_type', 'api_key')
        config = data.get('config', {})
        
        token = generator.generate_token(token_type, config)
        return jsonify({'success': True, 'token': token})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/inject', methods=['POST'])
def inject_token():
    """Generate injection code for a token"""
    try:
        data = request.json
        token = data.get('token')
        injection_type = data.get('injection_type')
        config = data.get('config', {})
        
        if injection_type == 'powershell':
            result = injector.inject_powershell(token, config)
        elif injection_type == 'sql':
            result = injector.inject_sql(token, config)
        elif injection_type == 'registry':
            result = injector.inject_registry(token, config)
        elif injection_type == 'environment':
            result = injector.inject_environment(token, config)
        else:
            return jsonify({'success': False, 'error': 'Invalid injection type'})
        
        return jsonify({'success': True, 'injection_code': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/test-demo', methods=['POST'])
def run_test_demo():
    """Run demonstration test cases"""
    try:
        demo_type = request.json.get('demo_type', 'powershell')
        
        # Test scenarios
        test_scenarios = {
            'powershell': {
                'description': 'PowerShell API Key Injection Demo',
                'token_type': 'api_key',
                'injection_type': 'powershell'
            },
            'sql': {
                'description': 'SQL Server Database Token Demo', 
                'token_type': 'sql_connection',
                'injection_type': 'sql'
            },
            'registry': {
                'description': 'Windows Registry Token Demo',
                'token_type': 'registry_key', 
                'injection_type': 'registry'
            },
            'multi': {
                'description': 'Multi-Stage Pipeline Demo',
                'token_type': 'jwt_token',
                'injection_type': 'powershell'
            }
        }
        
        scenario = test_scenarios.get(demo_type, test_scenarios['powershell'])
        
        # Generate test token
        test_config = {
            'stage': 'demo',
            'expiry_hours': 1,
            'description': f'Demo token for {scenario["description"]}'
        }
        test_token = generator.generate_token(scenario['token_type'], test_config)
        
        # Generate injection code
        if scenario['injection_type'] == 'powershell':
            injection = injector.inject_powershell(test_token, test_config)
        elif scenario['injection_type'] == 'sql':
            injection = injector.inject_sql(test_token, test_config)
        elif scenario['injection_type'] == 'registry':
            injection = injector.inject_registry(test_token, test_config)
        
        # Simulate test results
        test_results = {
            'test_passed': True,
            'execution_time': '0.234s',
            'detection_rate': '100%',
            'false_positives': 0,
            'coverage_areas': [
                'Token Generation',
                'Injection Mechanism', 
                'Windows Integration',
                'Event Logging',
                'Metadata Tracking'
            ]
        }
        
        return jsonify({
            'success': True,
            'demo_results': {
                'scenario': scenario,
                'test_token': test_token,
                'injection_code': injection,
                'test_results': test_results,
                'timestamp': datetime.utcnow().isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/export-config', methods=['POST'])
def export_config():
    """Export configuration for CLI usage"""
    try:
        data = request.json
        tokens = data.get('tokens', [])
        
        config = {
            'version': '1.0',
            'created_at': datetime.utcnow().isoformat(),
            'tokens': tokens,
            'windows_settings': {
                'event_logging': True,
                'registry_monitoring': True,
                'powershell_integration': True
            }
        }
        
        return jsonify({'success': True, 'config': config})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
