# tests/test_package_scan.py - Test vulnerability scanning
import pytest
from unittest.mock import Mock, patch
from src.tools.package_scan import PackageScanTool

class TestPackageScanTool:
    """Test the package vulnerability scanner."""
    
    def test_tool_initialization(self):
        """Test that the tool initializes correctly."""
        tool = PackageScanTool()
        assert tool.name == "package_scan"
        assert tool.osv_batch_url == "https://api.osv.dev/v1/querybatch"
    
    @patch('src.tools.package_scan.requests.post')
    def test_successful_scan(self, mock_post):
        """Test successful vulnerability scanning."""
        # Mock successful API response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "results": [
                {
                    "vulns": [
                        {"id": "GHSA-j8r2-6x86-q33q", "modified": "2023-03-14T05:47:39.989396Z"}
                    ]
                },
                {"vulns": []}  # No vulnerabilities for second package
            ]
        }
        mock_post.return_value = mock_response
        
        tool = PackageScanTool()
        packages = [
            {"name": "requests", "version": "2.25.1"},
            {"name": "numpy", "version": "1.20.0"}
        ]
        
        result = tool.forward(packages)
        
        # Should find one vulnerability
        assert len(result) == 1
        assert result[0]["package"] == "requests"
        assert result[0]["vulnerability_id"] == "GHSA-j8r2-6x86-q33q"
        
        # Verify API was called correctly
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == "https://api.osv.dev/v1/querybatch"
        
        # Check the query structure
        query_data = call_args[1]['json']
        assert 'queries' in query_data
        assert len(query_data['queries']) == 2
        assert query_data['queries'][0]['package']['name'] == 'requests'
    
    @patch('src.tools.package_scan.requests.post')
    def test_api_error_handling(self, mock_post):
        """Test handling of API errors."""
        # Mock API error
        mock_post.side_effect = Exception("API Error")
        
        tool = PackageScanTool()
        packages = [{"name": "requests", "version": "2.25.1"}]
        
        result = tool.forward(packages)
        
        # Should return empty list on error
        assert result == []
    
    def test_empty_package_list(self):
        """Test handling of empty package list."""
        tool = PackageScanTool()
        result = tool.forward([])
        assert result == []