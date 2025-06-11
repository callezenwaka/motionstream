# tests/test_scan_command.py - Test the scan_command function specifically
import pytest
from unittest.mock import patch, Mock
import tempfile
from pathlib import Path

class TestScanCommand:
    """Test the scan_command function in isolation."""
    
    @patch.dict('os.environ', {'HF_TOKEN': 'fake_token'})
    @patch('app.create_security_agent')
    @patch('app.parse_dependency_file')  # ✅ Fixed: Mock where it's imported
    @patch('builtins.print')  # Suppress output
    def test_successful_scan(self, mock_print, mock_parser, mock_agent):
        """Test successful scanning workflow."""
        from app import scan_command
        
        # Mock dependencies
        mock_parser.return_value = [
            {'name': 'requests', 'version': '2.25.1'},
            {'name': 'django', 'version': '3.2.0'}
        ]
        
        # Mock agent
        mock_agent_instance = Mock()
        mock_agent_instance.run.return_value = "Security analysis complete. No critical vulnerabilities found."
        mock_agent.return_value = mock_agent_instance
        
        # Mock Summary formatter
        with patch('app.Summary') as mock_summary_class:
            mock_formatter = Mock()
            mock_summary_class.return_value = mock_formatter
            
            # Mock the spinner to avoid threading issues in tests
            with patch('app.run_with_spinner') as mock_spinner:
                # Make spinner just call the function directly
                def side_effect(func, *args, **kwargs):
                    return func()
                mock_spinner.side_effect = side_effect
                
                # Test the scan
                result = scan_command('requirements.txt', 'console')
                
                # Verify success
                assert result == True
                
                # Verify dependencies were parsed
                mock_parser.assert_called_once_with('requirements.txt')
                
                # Verify agent was created and used
                mock_agent.assert_called_once()
                mock_agent_instance.run.assert_called_once()
                
                # Verify formatter was used
                mock_summary_class.assert_called_once_with(output_format='console')
                mock_formatter.display_results.assert_called_once()
    
    @patch.dict('os.environ', {'HF_TOKEN': 'fake_token'})
    @patch('app.parse_dependency_file')  # ✅ Fixed: Mock where it's imported
    @patch('builtins.print')  # Suppress output
    def test_no_dependencies_found(self, mock_print, mock_parser):
        """Test handling when no dependencies are found."""
        from app import scan_command
        
        # Mock empty dependencies
        mock_parser.return_value = []
        
        # Mock the spinner
        with patch('app.run_with_spinner') as mock_spinner:
            def side_effect(func, *args, **kwargs):
                return func()
            mock_spinner.side_effect = side_effect
            
            # Test the scan
            result = scan_command('empty_requirements.txt')
            
            # Should return False
            assert result == False
            
            # Should have tried to parse
            mock_parser.assert_called_once_with('empty_requirements.txt')
    
    @patch.dict('os.environ', {'HF_TOKEN': 'fake_token'})
    @patch('app.create_security_agent')
    @patch('app.parse_dependency_file')  # ✅ Fixed: Mock where it's imported
    @patch('builtins.print')  # Suppress output
    def test_agent_returns_no_result(self, mock_print, mock_parser, mock_agent):
        """Test handling when agent returns None."""
        from app import scan_command
        
        # Mock dependencies
        mock_parser.return_value = [{'name': 'requests', 'version': '2.25.1'}]
        
        # Mock agent returning None
        mock_agent_instance = Mock()
        mock_agent_instance.run.return_value = None
        mock_agent.return_value = mock_agent_instance
        
        # Mock the spinner
        with patch('app.run_with_spinner') as mock_spinner:
            def side_effect(func, *args, **kwargs):
                return func()
            mock_spinner.side_effect = side_effect
            
            # Test the scan
            result = scan_command('requirements.txt')
            
            # Should return False when agent returns None
            assert result == False
    
    @patch.dict('os.environ', {'HF_TOKEN': 'fake_token'})
    @patch('app.parse_dependency_file')  # ✅ Fixed: Mock where it's imported
    @patch('builtins.print')  # Suppress output
    def test_file_parsing_error(self, mock_print, mock_parser):
        """Test handling of file parsing errors."""
        from app import scan_command
        
        # Mock file parsing error
        mock_parser.side_effect = FileNotFoundError("File not found")
        
        # Mock the spinner to let the exception propagate
        with patch('app.run_with_spinner') as mock_spinner:
            def side_effect(func, *args, **kwargs):
                return func()
            mock_spinner.side_effect = side_effect
            
            # Test should handle the exception gracefully
            result = scan_command('nonexistent.txt')
            
            # Should return False due to error handling
            assert result == False
    
    @patch.dict('os.environ', {'HF_TOKEN': 'fake_token'})  
    @patch('app.create_security_agent')
    @patch('app.parse_dependency_file')  # ✅ Fixed: Mock where it's imported
    @patch('builtins.print')  # Suppress output
    def test_different_output_formats(self, mock_print, mock_parser, mock_agent):
        """Test different output formats."""
        from app import scan_command
        
        # Mock dependencies and agent
        mock_parser.return_value = [{'name': 'requests', 'version': '2.25.1'}]
        mock_agent_instance = Mock()
        mock_agent_instance.run.return_value = "Analysis complete"
        mock_agent.return_value = mock_agent_instance
        
        # Test each output format
        for output_format in ['console', 'json', 'html']:
            with patch('app.Summary') as mock_summary_class:
                mock_formatter = Mock()
                mock_summary_class.return_value = mock_formatter
                
                # Mock the spinner
                with patch('app.run_with_spinner') as mock_spinner:
                    def side_effect(func, *args, **kwargs):
                        return func()
                    mock_spinner.side_effect = side_effect
                    
                    result = scan_command('requirements.txt', output_format)
                    
                    # Should succeed
                    assert result == True
                    
                    # Should use correct format
                    mock_summary_class.assert_called_with(output_format=output_format)
                    
            # Reset mocks for next iteration
            mock_parser.reset_mock()
            mock_agent.reset_mock()
            mock_agent_instance.reset_mock()