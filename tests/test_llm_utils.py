# tests/test_llm_utils.py
import sys
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.llm_utils import load_model, OllamaModel, LMStudioModel

class TestLLMUtils(unittest.TestCase):
    
    def setUp(self):
        """Set up test environment."""
        # Create a temporary config file
        self.temp_config = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.yaml')
        self.temp_config.write("""
llm:
  model: config-test-model
  offline_mode: false
""")
        self.temp_config.close()
        
        # Create mock for transformers pipeline
        self.mock_pipeline = MagicMock()
        self.mock_pipeline.return_value = "mock_model"
        
        # Create mock for requests
        self.mock_response = MagicMock()
        self.mock_response.status_code = 200
        self.mock_response.json.return_value = [{"id": "test-model"}]
        
    def tearDown(self):
        """Clean up after tests."""
        os.unlink(self.temp_config.name)
    
    def test_load_model_with_no_llm_flag(self):
        """Test that no model is loaded when no_llm is True."""
        model = load_model(model_name="test-model", no_llm=True)
        self.assertIsNone(model)
    
    @patch('tools.llm_utils.pipeline')
    def test_load_model_with_specified_name(self, mock_pipeline):
        """Test loading a model with a specified name."""
        mock_pipeline.return_value = "test_pipeline"
        
        model = load_model(model_name="test-model", no_llm=False)
        
        # Check that pipeline was called with the correct arguments
        mock_pipeline.assert_called_once()
        self.assertEqual(mock_pipeline.call_args[1]['model'], "test-model")
        self.assertEqual(model, "test_pipeline")
    
    @patch('os.environ.get')
    @patch('tools.llm_utils.pipeline')
    def test_load_model_from_environment(self, mock_pipeline, mock_env_get):
        """Test loading a model from an environment variable."""
        mock_env_get.return_value = "env-test-model"
        mock_pipeline.return_value = "env_test_pipeline"
        
        model = load_model(model_name=None, no_llm=False)
        
        # Check that environment variable was checked
        mock_env_get.assert_called_with("SECURITY_ASSISTANT_MODEL", None)
        
        # Check that pipeline was called with the correct model name
        mock_pipeline.assert_called_once()
        self.assertEqual(mock_pipeline.call_args[1]['model'], "env-test-model")
        self.assertEqual(model, "env_test_pipeline")
    
    @patch('os.environ.get')
    @patch('tools.llm_utils.pipeline')
    def test_load_model_from_config(self, mock_pipeline, mock_env_get):
        """Test loading a model from config file."""
        # Set up mocks
        mock_env_get.return_value = None
        mock_pipeline.return_value = "config_test_pipeline"
        
        # Replace the config file path in the function
        with patch('tools.llm_utils.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value = open(self.temp_config.name)
            model = load_model(model_name=None, no_llm=False)
            
            # Check that pipeline was called with the correct model name
            mock_pipeline.assert_called_once()
            self.assertEqual(mock_pipeline.call_args[1]['model'], "config-test-model")
            self.assertEqual(model, "config_test_pipeline")
    
    @patch('tools.llm_utils.pipeline')
    @patch('ollama.generate')
    def test_ollama_model(self, mock_ollama_generate, mock_pipeline):
        """Test the OllamaModel wrapper."""
        # Make transformers pipeline fail to trigger Ollama fallback
        mock_pipeline.side_effect = Exception("Pipeline error")
        
        # Set up the Ollama mock
        mock_ollama_generate.return_value = {"response": "Ollama response"}
        
        # Create an Ollama model
        with patch('tools.llm_utils.ollama') as mock_ollama:
            mock_ollama.generate = mock_ollama_generate
            
            # Mock importing ollama
            with patch.dict('sys.modules', {'ollama': mock_ollama}):
                ollama_model = OllamaModel("llama2")
                
                # Test the model
                result = ollama_model("test prompt", max_tokens=100, temperature=0.5)
                
                # Check that Ollama generate was called correctly
                mock_ollama_generate.assert_called_with(
                    model="llama2",
                    prompt="test prompt",
                    max_tokens=100,
                    temperature=0.5
                )
                
                # Check the result format
                self.assertEqual(result, [{"generated_text": "Ollama response"}])
    
    @patch('tools.llm_utils.requests.post')
    def test_lm_studio_model(self, mock_post):
        """Test the LMStudioModel wrapper."""
        # Set up the mock response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"text": "LM Studio response"}]
        }
        mock_post.return_value = mock_response
        
        # Create an LM Studio model
        lm_studio_model = LMStudioModel("test-model")
        
        # Test the model
        result = lm_studio_model("test prompt", max_tokens=100, temperature=0.5)
        
        # Check that the request was made correctly
        mock_post.assert_called_with(
            "http://localhost:1234/v1/completions",
            json={
                "model": "test-model",
                "prompt": "test prompt",
                "max_tokens": 100,
                "temperature": 0.5
            }
        )
        
        # Check the result format
        self.assertEqual(result, [{"generated_text": "LM Studio response"}])
    
    @patch('tools.llm_utils.pipeline')
    @patch('tools.llm_utils.requests.get')
    def test_fallback_to_lm_studio(self, mock_get, mock_pipeline):
        """Test fallback to LM Studio when transformers fails."""
        # Make transformers pipeline fail
        mock_pipeline.side_effect = Exception("Pipeline error")
        
        # Set up mock for LM Studio API
        mock_get.return_value = self.mock_response
        
        # Mock LM Studio model for testing
        with patch('tools.llm_utils.LMStudioModel') as mock_lm_studio:
            mock_lm_studio.return_value = "lm_studio_model"
            
            # Load model with test-model name
            model = load_model(model_name="test-model", no_llm=False)
            
            # Check that LM Studio was tried
            mock_get.assert_called_with("http://localhost:1234/v1/models")
            
            # Check that LM Studio model was created
            mock_lm_studio.assert_called_with("test-model")
            
            # Check the returned model
            self.assertEqual(model, "lm_studio_model")
    
    @patch('tools.llm_utils.pipeline')
    @patch('tools.llm_utils.requests.get')
    def test_no_model_available(self, mock_get, mock_pipeline):
        """Test behavior when no model is available."""
        # Make transformers pipeline fail
        mock_pipeline.side_effect = Exception("Pipeline error")
        
        # Make LM Studio API fail
        mock_get.side_effect = Exception("Connection error")
        
        # Attempt to load model
        model = load_model(model_name="test-model", no_llm=False)
        
        # Should return None when no model is available
        self.assertIsNone(model)

if __name__ == '__main__':
    unittest.main()