# tests/test_cli.py - Fixed CLI testing
import pytest
from unittest.mock import patch, Mock
import sys
from io import StringIO

class TestCLI:
    """Test command-line interface."""
    
    @patch('sys.argv', ['motionstream', '--help'])
    def test_help_command(self):
        """Test that help command works without requiring HF_TOKEN."""
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            with patch('sys.exit') as mock_exit:
                try:
                    from app import main
                    main()
                except SystemExit:
                    pass
                
                # Check that help was displayed
                output = mock_stdout.getvalue()
                assert 'MotionStream' in output
                assert 'scan' in output
                assert 'file_path' in output
    
    def test_no_arguments_provided(self):
        """Test handling when no arguments are provided."""
        with patch('sys.argv', ['motionstream']):  # No command provided
            with patch('sys.exit') as mock_exit:
                with patch('sys.stderr', new_callable=StringIO):
                    from app import main
                    main()
                    
                    # Should exit with code 2 (argparse error for missing required args)
                    mock_exit.assert_called_with(2)
    
    def test_missing_hf_token_during_scan(self):
        """Test handling of missing HF_TOKEN when actually trying to scan."""
        with patch.dict('os.environ', {}, clear=True):  # Clear HF_TOKEN
            with patch('sys.argv', ['motionstream', 'scan', 'requirements.txt']):
                with patch('sys.exit') as mock_exit:
                    with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
                        from app import main
                        main()
                        
                        # Should have exited with code 1 (HF_TOKEN missing)
                        mock_exit.assert_called_with(1)
                        
                        # Should have shown error message
                        output = mock_stdout.getvalue()
                        assert 'HF_TOKEN environment variable not set' in output
    
    @patch.dict('os.environ', {'HF_TOKEN': 'fake_token'})
    @patch('app.scan_command')  # Mock the entire scan_command function
    def test_scan_command_with_token_success(self, mock_scan_command):
        """Test scan command with HF_TOKEN set and successful scan."""
        # Mock scan_command to return success
        mock_scan_command.return_value = True
        
        with patch('sys.argv', ['motionstream', 'scan', 'requirements.txt']):
            with patch('sys.exit') as mock_exit:
                from app import main
                main()
                
                # Should have called scan_command
                mock_scan_command.assert_called_once_with('requirements.txt', 'console')
                
                # Should exit successfully
                mock_exit.assert_called_with(0)
    
    @patch.dict('os.environ', {'HF_TOKEN': 'fake_token'})
    @patch('app.scan_command')  # Mock the scan_command function
    def test_scan_command_with_token_failure(self, mock_scan_command):
        """Test scan command when scanning fails."""
        # Mock scan_command to return failure
        mock_scan_command.return_value = False
        
        with patch('sys.argv', ['motionstream', 'scan', 'requirements.txt']):
            with patch('sys.exit') as mock_exit:
                from app import main
                main()
                
                # Should have called scan_command
                mock_scan_command.assert_called_once_with('requirements.txt', 'console')
                
                # Should exit with error code
                mock_exit.assert_called_with(1)
    
    def test_invalid_command(self):
        """Test handling of invalid commands."""
        with patch('sys.argv', ['motionstream', 'invalid_command', 'file.txt']):
            with patch('sys.exit') as mock_exit:
                with patch('sys.stderr', new_callable=StringIO):
                    from app import main
                    main()
                    
                    # Should exit with error code 2 (argparse error)
                    mock_exit.assert_called_with(2)
    
    @patch.dict('os.environ', {'HF_TOKEN': 'fake_token'})
    def test_output_format_arguments(self):
        """Test that different output format arguments work."""
        test_formats = ['console', 'json', 'html']
        
        for output_format in test_formats:
            with patch('app.scan_command') as mock_scan_command:
                mock_scan_command.return_value = True
                
                with patch('sys.argv', ['motionstream', 'scan', 'requirements.txt', '--output', output_format]):
                    with patch('sys.exit'):
                        from app import main
                        main()
                        
                        # Should have called scan_command with correct format
                        mock_scan_command.assert_called_once_with('requirements.txt', output_format)