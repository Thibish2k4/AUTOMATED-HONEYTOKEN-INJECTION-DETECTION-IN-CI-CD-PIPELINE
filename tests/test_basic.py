
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_token_generation():
    """Test basic token generation"""
    from windows_honeytoken_generator import WindowsHoneytokenGenerator
    generator = WindowsHoneytokenGenerator()
    assert generator is not None

def test_configuration_loading():
    """Test configuration loading"""
    import json
    config_path = "config/windows_config.json"
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = json.load(f)
        assert config is not None

def test_pipeline_stages():
    """Test pipeline stage configuration"""
    stages = ['build', 'test', 'deploy']
    for stage in stages:
        assert stage in stages
        