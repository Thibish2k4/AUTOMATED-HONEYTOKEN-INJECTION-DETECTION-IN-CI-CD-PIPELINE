# windows_honeytoken_orchestrator.py
import json
import time
import threading
from typing import Dict, List
from windows_honeytoken_generator import WindowsHoneytokenGenerator, WindowsHoneytokenConfig
from windows_honeytoken_injector import WindowsHoneytokenInjector
from windows_honeytoken_detector import WindowsHoneytokenDetector, WindowsDetectionAlert

class WindowsHoneytokenOrchestrator:
    """Windows-optimized orchestrator with all research enhancements"""
    
    def __init__(self, config_file: str = 'config/windows_config.json'):
        self.config = self._load_windows_config(config_file)
        
        self.generator = WindowsHoneytokenGenerator()
        self.injector = WindowsHoneytokenInjector(self.generator)
        self.detector = WindowsHoneytokenDetector(self._get_alert_handlers())
        
        self.active_tokens = []
        self.rotation_enabled = True
    
    def _load_windows_config(self, config_file: str) -> Dict:
        """Load Windows-optimized configuration"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return self._get_default_windows_config()
    
    def _get_default_windows_config(self) -> Dict:
        """Get default Windows configuration with all research enhancements"""
        return {
            "rotation_interval_hours": 24,
            "pipeline_stages": {
                "build": {
                    "strategy": "powershell",
                    "target_files": ["scripts\\build.ps1", "C:\\temp\\build.ps1"],
                    "token_types": ["azure_token", "docker_token", "powershell_var"],
                    "fingerprint_resistance": True,
                    "replicas": 3
                },
                "test": {
                    "strategy": "registry",
                    "target_files": ["config\\test.json", "C:\\temp\\test.sql"],
                    "token_types": ["sql_connection", "database_url", "registry_key"],
                    "adaptive_structure": True,
                    "containers": 2
                },
                "deploy": {
                    "strategy": "windows_service",
                    "target_files": ["azure-pipelines.yml", "scripts\\deploy.ps1"],
                    "token_types": ["api_key", "azure_token", "windows_service"],
                    "fingerprint_resistance": True,
                    "services": ["web_service", "api_service", "db_service"]
                }
            },
            "alert_channels": {
                "console": True,
                "windows_toast": True,
                "windows_event_log": True,
                "email": "security@company.com"
            },
            "monitoring": {
                "ai_enhanced": True,
                "anomaly_detection": True,
                "behavioral_analysis": True,
                "pattern_recognition": True,
                "windows_event_log": True,
                "registry_monitoring": True,
                "process_monitoring": True,
                "powershell_monitoring": True,
                "network_monitoring": True
            },
            "research_enhancements": {
                "msaad_fingerprint_resistance": True,
                "saleh_ai_anomaly_detection": True,
                "reti_context_awareness": True,
                "flora_microservice_scaling": True,
                "database_hierarchical_management": True
            }
        }
    
    def initialize(self):
        """Initialize with all research enhancements"""
        print("🍯 Initializing Windows Honeytoken CI/CD Security Tool")
        print("Research Enhancements Active:")
        print("- Msaad et al. (2023): Fingerprinting Resistance")
        print("- Saleh et al. (2024): AI-Enhanced Anomaly Detection")
        print("- Reti et al. (2024): Context-Aware Generation")
        print("- Flora et al. (2023): Microservice Scaling")
        print("- Database Paper (2024): Hierarchical Management")
        print("="*60)
        
        # Create some default tokens if none exist
        if not self.active_tokens:
            self._create_default_tokens()
        
        # Deploy initial honeytokens with all enhancements
        self._deploy_enhanced_tokens()
        
        # Start AI-enhanced monitoring
        self.detector.start_monitoring()
        
        # Schedule rotation
        if self.rotation_enabled:
            self._schedule_rotation()
        
        print("✅ Windows Honeytoken Orchestrator initialized with all research enhancements")
    
    def _create_default_tokens(self):
        """Create some default tokens for demo purposes"""
        import secrets
        from datetime import datetime
        
        default_tokens = [
            {
                'id': f'demo_api_{secrets.token_hex(4)}',
                'type': 'api_key',
                'value': f'sk-demo_{secrets.token_hex(16)}',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {'stage': 'demo', 'purpose': 'testing'}
            },
            {
                'id': f'demo_db_{secrets.token_hex(4)}',
                'type': 'database_url',
                'value': f'Server=demo-server;Database=HoneyDB;User=demo;Password={secrets.token_hex(8)}',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {'stage': 'demo', 'purpose': 'testing'}
            },
            {
                'id': f'demo_jwt_{secrets.token_hex(4)}',
                'type': 'jwt_token',
                'value': f'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.demo.{secrets.token_hex(12)}',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {'stage': 'demo', 'purpose': 'testing'}
            }
        ]
        
        self.active_tokens.extend(default_tokens)
        print(f"✅ Created {len(default_tokens)} default demo tokens")
    
    def _deploy_enhanced_tokens(self):
        """Deploy honeytokens with all research enhancements"""
        total_deployed = 0
        
        for stage, stage_config in self.config['pipeline_stages'].items():
            try:
                print(f"\n📍 Deploying enhanced honeytokens for stage: {stage}")
                
                # Add research enhancement flags
                stage_config.update({
                    'pipeline_id': f'windows-enhanced-{int(time.time())}',
                    'repository': 'honeytoken-cicd-security-windows',
                    'research_enhancements': self.config['research_enhancements']
                })
                
                result = self.injector.inject_honeytokens({
                    'stages': {stage: stage_config}
                })
                
                deployed_count = len(result['injected_tokens'])
                total_deployed += deployed_count
                
                self.active_tokens.extend(result['injected_tokens'])
                self.detector.register_honeytokens(result['injected_tokens'])
                
                print(f"  ✅ Deployed {deployed_count} tokens")
                print(f"  🔬 Research enhancements: {', '.join(result['research_enhancements'])}")
                
                if result['windows_features_used']:
                    print(f"  🪟 Windows features: {', '.join(result['windows_features_used'])}")
                
                if result['scaling_applied']:
                    print(f"  📈 Scaling applied: {', '.join(result['scaling_applied'])}")
                
            except Exception as e:
                print(f"  ❌ Failed to deploy tokens for stage {stage}: {e}")
        
        print(f"\n🎉 Total deployed: {total_deployed} enhanced honeytokens")
    
    def _get_alert_handlers(self) -> List:
        """Get Windows-specific alert handlers"""
        handlers = []
        
        # Always include console handler
        handlers.append(self._console_alert_handler)
        
        # Windows-specific handlers
        if self.config['alert_channels'].get('windows_toast'):
            handlers.append(self._windows_toast_handler)
        
        if self.config['alert_channels'].get('windows_event_log'):
            handlers.append(self._windows_event_log_handler)
        
        if self.config['alert_channels'].get('email'):
            handlers.append(self._email_alert_handler)
        
        return handlers
    
    def _console_alert_handler(self, alert: WindowsDetectionAlert):
        """Enhanced console alert handler"""
        print(f"\n{'🚨' * 20}")
        print(f"WINDOWS RESEARCH-ENHANCED HONEYTOKEN ALERT")
        print(f"{'🚨' * 20}")
        print(f"Severity: {alert.severity}")
        print(f"Token ID: {alert.token_id}")
        print(f"Token Type: {alert.token_type}")
        print(f"Timestamp: {alert.trigger_timestamp}")
        print(f"Source: {alert.context.get('source', 'Unknown')}")
        print(f"AI Anomaly Score: {alert.windows_specific['detection_enhancements']['ai_anomaly_score']:.2f}")
        print(f"Detection Confidence: {alert.windows_specific['detection_enhancements']['confidence_score']}")
        print(f"Research Sources: {', '.join(alert.windows_specific['detection_enhancements']['research_sources'])}")
        print(f"{'=' * 60}")
    
    def _windows_toast_handler(self, alert: WindowsDetectionAlert):
        """Windows toast notification handler"""
        try:
            import win10toast
            toaster = win10toast.ToastNotifier()
            toaster.show_toast(
                "🍯 Research-Enhanced Honeytoken Alert",
                f"Severity: {alert.severity}\nToken: {alert.token_type}\nAI Score: {alert.windows_specific['detection_enhancements']['ai_anomaly_score']:.2f}",
                duration=15
            )
        except Exception as e:
            print(f"Toast notification error: {e}")
    
    def _windows_event_log_handler(self, alert: WindowsDetectionAlert):
        """Windows Event Log handler"""
        # This is handled by the detector's built-in event logging
        pass
    
    def _email_alert_handler(self, alert: WindowsDetectionAlert):
        """Email alert handler with research details"""
        print(f"📧 Email alert would be sent for token {alert.token_id}")
        # Implementation would send detailed email with all research enhancements
    
    def get_comprehensive_status(self) -> Dict:
        """Get comprehensive status with all research enhancements"""
        return {
            'platform': 'Windows',
            'active_tokens': len(self.active_tokens),
            'active_token_ids': [token.get('id', f'unknown_{i}') for i, token in enumerate(self.active_tokens)],
            'monitoring_active': self.detector.monitoring_active,
            'rotation_enabled': self.rotation_enabled,
            'research_enhancements': {
                'fingerprint_resistance': sum(1 for token in self.active_tokens 
                                             if token.get('fingerprint_resistance', {}).get('applied', False)),
                'ai_enhanced_detection': self.config['monitoring']['ai_enhanced'],
                'context_aware_generation': sum(1 for token in self.active_tokens 
                                               if 'reti_context_awareness' in token.get('metadata', {}).get('research_source', '')),
                'scaling_support': sum(1 for token in self.active_tokens 
                                     if token.get('metadata', {}).get('scaling_info', [])),
                'hierarchical_management': True
            },
            'windows_features': {
                'registry_integration': True,
                'event_log_integration': True,
                'service_integration': True,
                'powershell_integration': True,
                'toast_notifications': True
            },
            'detection_summary': self.detector.get_enhanced_detection_summary(),
            'referenced_papers': [
                'Msaad et al. (2023) - Honeysweeper: Towards Stealthy Honeytoken Fingerprinting Techniques',
                'Saleh et al. (2024) - Advancing Software Security through AI-based Anomaly Detection', 
                'Reti et al. (2024) - Act as a Honeytoken Generator! Investigation into Generation with LLMs',
                'Flora et al. (2023) - Intrusion Detection for Scalable Microservice Applications',
                'Various Authors (2024) - Generation and deployment of honeytokens in relational databases'
            ]
        }
    
    def shutdown(self):
        """Shutdown with comprehensive reporting"""
        print("🔄 Shutting down Windows Honeytoken Orchestrator...")
        
        # Stop monitoring
        self.detector.stop_monitoring()
        
        # Generate final report
        final_status = self.get_comprehensive_status()
        
        # Save final report
        report_path = f"C:\\temp\\honeytoken_final_report_{int(time.time())}.json"
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(final_status, f, indent=2, ensure_ascii=False)
            print(f"📊 Final report saved to: {report_path}")
        except Exception as e:
            print(f"⚠️ Could not save final report: {e}")
        
        print("✅ Windows Honeytoken Orchestrator shutdown complete")
    
    def _schedule_rotation(self):
        """Schedule token rotation"""
        import schedule
        
        interval = self.config.get('rotation_interval_hours', 24)
        schedule.every(interval).hours.do(self._rotate_tokens)
        
        def run_scheduler():
            while self.rotation_enabled:
                schedule.run_pending()
                time.sleep(60)
        
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
        
        print(f"⏰ Token rotation scheduled every {interval} hours")
    
    def _rotate_tokens(self):
        """Rotate tokens with research enhancements preserved"""
        print("🔄 Starting enhanced token rotation...")
        
        # Clean up old tokens
        self.active_tokens.clear()
        
        # Deploy new tokens with same enhancements
        self._deploy_enhanced_tokens()
        
        print("✅ Enhanced token rotation completed")
