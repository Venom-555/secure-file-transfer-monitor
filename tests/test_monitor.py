"""
Unit tests for the monitoring system
"""

import unittest
import tempfile
import os
from pathlib import Path
from src.integrity_checker import IntegrityChecker
from src.config import Config

class TestFileTransferMonitor(unittest.TestCase):
    """Test cases for the monitoring system"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = Path(self.test_dir) / "test.txt"
        self.test_file.write_text("Test content for integrity checking")
        
        self.integrity = IntegrityChecker()
    
    def test_hash_calculation(self):
        """Test SHA256 hash calculation"""
        hash_value = self.integrity.calculate_hash(self.test_file)
        self.assertIsNotNone(hash_value)
        self.assertEqual(len(hash_value), 64)  # SHA256 hex length
    
    def test_integrity_check(self):
        """Test file integrity checking"""
        # First check should register the file
        result1 = self.integrity.check_file(self.test_file)
        self.assertEqual(result1["status"], "NEW_FILE_REGISTERED")
        
        # Second check should match
        result2 = self.integrity.check_file(self.test_file)
        self.assertEqual(result2["status"], "MATCH")
        self.assertTrue(result2["match"])
        
        # Modify file and check again
        self.test_file.write_text("Modified content")
        result3 = self.integrity.check_file(self.test_file)
        self.assertEqual(result3["status"], "MISMATCH")
        self.assertFalse(result3["match"])
    
    def test_config_loading(self):
        """Test configuration loading"""
        config = Config()
        watch_paths = config.get_watch_paths()
        self.assertIsInstance(watch_paths, list)
        
        sensitive_dirs = config.get_sensitive_directories()
        self.assertIsInstance(sensitive_dirs, list)
    
    def tearDown(self):
        """Clean up test files"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

if __name__ == '__main__':
    unittest.main()