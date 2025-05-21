# tests/test_llm_utils.py
import pytest
from tools.llm_utils import load_model, OllamaModel, LMStudioModel

# No need for path manipulation - pytest handles this automatically

def test_load_model_with_no_llm_flag():
    """Test that no model is loaded when no_llm is True."""
    model = load_model(model_name="test-model", no_llm=True)
    assert model is None

def test_load_model_with_specified_name(mocker):
    """Test loading a model with a specified name."""
    # Create a mock for the pipeline function
    mock_pipeline = mocker.MagicMock(return_value="test_pipeline")
    
    # Mock the transformers module with our pipeline mock
    mock_transformers = mocker.MagicMock()
    mock_transformers.pipeline = mock_pipeline
    
    # Mock the import to return our mock module
    mocker.patch.dict('sys.modules', {'transformers': mock_transformers})
    
    model = load_model(model_name="test-model", no_llm=False)

    # Check that pipeline was called with the correct arguments
    mock_pipeline.assert_called_once()
    assert mock_pipeline.call_args[0][0] == "text-generation"
    assert mock_pipeline.call_args[1]['model'] == "test-model"
    assert model == "test_pipeline"

# def test_load_model_from_environment(mocker, monkeypatch):
#     """Test loading a model from an environment variable."""
#     monkeypatch.setenv("SECURITY_ASSISTANT_MODEL", "env-test-model")
#     # Mock the transformers.pipeline function
#     mock_pipeline = mocker.patch('transformers.pipeline', return_value="env_test_pipeline")

#     model = load_model(model_name=None, no_llm=False)

#     # Check that pipeline was called with the correct model name
#     mock_pipeline.assert_called_once()
#     assert mock_pipeline.call_args[1]['model'] == "env-test-model"
#     assert model == "env_test_pipeline"

def test_load_model_from_environment(mocker, monkeypatch):
    """Test loading a model from an environment variable."""
    monkeypatch.setenv("SECURITY_ASSISTANT_MODEL", "env-test-model")
    
    # Create a mock module with mock pipeline function
    mock_transformers = mocker.MagicMock()
    mock_pipeline = mocker.MagicMock(return_value="env_test_pipeline")
    mock_transformers.pipeline = mock_pipeline
    
    # Mock the import statement
    mocker.patch.dict('sys.modules', {'transformers': mock_transformers})
    
    model = load_model(model_name=None, no_llm=False)
    
    # Check that pipeline was called with the correct model name
    mock_pipeline.assert_called_once()
    assert mock_pipeline.call_args[0][0] == "text-generation"
    assert mock_pipeline.call_args[1]['model'] == "env-test-model"
    assert model == "env_test_pipeline"

# def test_load_model_from_config(mocker, temp_config_file, monkeypatch):
#     """Test loading a model from config file."""
#     # Ensure environment variable is not set for this test
#     monkeypatch.delenv("SECURITY_ASSISTANT_MODEL", raising=False)

#     # Create a mock for the pipeline function
#     mock_pipeline = mocker.MagicMock(return_value="config_test_pipeline")
    
#     # Mock the transformers module with our pipeline mock
#     mock_transformers = mocker.MagicMock()
#     mock_transformers.pipeline = mock_pipeline
    
#     # Mock the import to return our mock module
#     mocker.patch.dict('sys.modules', {'transformers': mock_transformers})
    
#     # Use the path from the fixture and monkey patch the open function
#     # Note: This depends on how tools.llm_utils loads the config file
#     def mock_open_func(file_path, *args, **kwargs):
#         if file_path == "config.yaml":  # Match the actual file name in llm_utils.py
#             return open(temp_config_file, *args, **kwargs)
#         return open(file_path, *args, **kwargs)
    
#     mocker.patch('builtins.open', mock_open_func)

#     model = load_model(model_name=None, no_llm=False)

#     # Check that pipeline was called with the correct model name
#     mock_pipeline.assert_called_once()
#     assert mock_pipeline.call_args[0][0] == "text-generation"
#     assert mock_pipeline.call_args[1]['model'] == "test-model-from-config"
#     assert model == "config_test_pipeline"

def test_load_model_from_config(mocker, temp_config_file, monkeypatch):
    """Test loading a model from config file."""
    # Ensure environment variable is not set for this test
    monkeypatch.delenv("SECURITY_ASSISTANT_MODEL", raising=False)
    
    # Create a mock for the transformers module with pipeline function
    mock_transformers = mocker.MagicMock()
    mock_pipeline = mocker.MagicMock(return_value="config_test_pipeline")
    mock_transformers.pipeline = mock_pipeline
    
    # Mock the import statement
    mocker.patch.dict('sys.modules', {'transformers': mock_transformers})
    
    # Use the path from the fixture and monkey patch the open function
    def mock_open_func(file_path, *args, **kwargs):
        if file_path == "config.yaml":  # Match the actual file name in llm_utils.py
            return open(temp_config_file, *args, **kwargs)
        return open(file_path, *args, **kwargs)
    
    mocker.patch('builtins.open', mock_open_func)
    
    model = load_model(model_name=None, no_llm=False)
    
    # Check that pipeline was called with the correct model name
    mock_pipeline.assert_called_once()
    assert mock_pipeline.call_args[0][0] == "text-generation"
    assert mock_pipeline.call_args[1]['model'] == "test-model-from-config"
    assert model == "config_test_pipeline"

# def test_load_model_from_config(mocker, temp_config_file, monkeypatch):
#     """Test loading a model from config file."""
#     # Ensure environment variable is not set for this test
#     monkeypatch.delenv("SECURITY_ASSISTANT_MODEL", raising=False)

#     # Mock the transformers.pipeline function
#     mock_pipeline = mocker.patch('transformers.pipeline', return_value="config_test_pipeline")
    
#     # Use the path from the fixture and monkey patch the open function
#     # Note: This depends on how tools.llm_utils loads the config file
#     def mock_open_func(file_path, *args, **kwargs):
#         if file_path == "config.yaml":  # Match the actual file name in llm_utils.py
#             return open(temp_config_file, *args, **kwargs)
#         return open(file_path, *args, **kwargs)
    
#     mocker.patch('builtins.open', mock_open_func)

#     model = load_model(model_name=None, no_llm=False)

#     # Check that pipeline was called with the correct model name
#     mock_pipeline.assert_called_once()
#     assert mock_pipeline.call_args[1]['model'] == "test-model-from-config"
#     assert model == "config_test_pipeline"

def test_ollama_model(mocker):
    """Test the OllamaModel wrapper."""
    # Mock the ollama module and its generate function
    mock_ollama = mocker.MagicMock()
    mock_ollama.generate.return_value = {"response": "Ollama response"}
    
    # Add to sys.modules
    mocker.patch.dict('sys.modules', {'ollama': mock_ollama})
    
    # Create an Ollama model
    ollama_model = OllamaModel("llama2")
    
    # Test the model
    result = ollama_model("test prompt", max_tokens=100, temperature=0.5)
    
    # Check that Ollama generate was called correctly
    mock_ollama.generate.assert_called_with(
        model="llama2",
        prompt="test prompt",
        max_tokens=100,
        temperature=0.5
    )
    
    # Check the result format
    assert result == [{"generated_text": "Ollama response"}]

def test_lm_studio_model(mocker):
    """Test the LMStudioModel wrapper."""
    mock_response = mocker.MagicMock()
    mock_response.json.return_value = {
        "choices": [{"text": "LM Studio response"}]
    }
    # Mock requests.post directly
    mock_post = mocker.patch('requests.post', return_value=mock_response)
    
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
    assert result == [{"generated_text": "LM Studio response"}]

def test_fallback_to_lm_studio(mocker):
    """Test fallback to LM Studio when transformers fails."""
    # Make transformers pipeline fail by raising an exception
    mocker.patch('transformers.pipeline', side_effect=Exception("Pipeline error"))
    
    # Also mock the import of ollama to make sure it's skipped
    mocker.patch.dict('sys.modules', {'ollama': None})
    
    # Set up mock for LM Studio API
    mock_response = mocker.MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [{"id": "test-model"}]
    mock_get = mocker.patch('requests.get', return_value=mock_response)
    
    # Mock LMStudioModel
    mock_lm_studio = mocker.patch('tools.llm_utils.LMStudioModel', return_value="lm_studio_model")
    
    # Load model with test-model name
    model = load_model(model_name="test-model", no_llm=False)
    
    # Check that LM Studio was tried
    mock_get.assert_called_with("http://localhost:1234/v1/models")
    
    # Check that LM Studio model was created
    mock_lm_studio.assert_called_with("test-model")
    
    # Check the returned model
    assert model == "lm_studio_model"

def test_no_model_available(mocker):
    """Test behavior when no model is available."""
    # Make transformers pipeline fail
    mocker.patch('transformers.pipeline', side_effect=Exception("Pipeline error"))
    
    # Also mock the import of ollama to make sure it's skipped
    mocker.patch.dict('sys.modules', {'ollama': None})
    
    # Make LM Studio API fail
    mocker.patch('requests.get', side_effect=Exception("Connection error"))
    
    # Attempt to load model
    model = load_model(model_name="test-model", no_llm=False)
    
    # Should return None when no model is available
    assert model is None