# In tools/llm_utils.py
import os
import yaml
import requests

class OllamaModel:
    """Wrapper for Ollama models"""
    def __init__(self, model_name):
        import ollama
        self.model_name = model_name
        self.client = ollama
        
    def __call__(self, prompt, max_tokens=500, temperature=0.1):
        response = self.client.generate(
            model=self.model_name,
            prompt=prompt,
            max_tokens=max_tokens,
            temperature=temperature
        )
        return [{"generated_text": response["response"]}]

class LMStudioModel:
    """Wrapper for LM Studio local server"""
    def __init__(self, model_name):
        self.model_name = model_name
        self.api_url = "http://localhost:1234/v1/completions"
        
    def __call__(self, prompt, max_tokens=500, temperature=0.1):
        response = requests.post(
            self.api_url,
            json={
                "model": self.model_name,
                "prompt": prompt,
                "max_tokens": max_tokens,
                "temperature": temperature
            }
        )
        data = response.json()
        return [{"generated_text": data["choices"][0]["text"]}]

def load_model(model_name=None, no_llm=False):
    """
    Dynamically load an LLM model based on user preference.
    Returns None if no model should be used.
    
    Args:
        model_name: Name or path of model to load
        no_llm: If True, don't load any model
        
    Returns:
        Loaded model object or None if no model should be used
    """
    if no_llm:
        print("Running without LLM enhancements - using rule-based analysis only")
        return None
        
    # Check for model specification
    if not model_name:
        # Check environment variable first
        model_name = os.environ.get("SECURITY_ASSISTANT_MODEL", None)
        
        # Check config file second
        if not model_name:
            try:
                with open("config.yaml", "r") as f:
                    config = yaml.safe_load(f)
                    model_name = config.get("llm", {}).get("model", None)
            except:
                pass
                
    # Try different approaches in order of preference
    if model_name:
        try:
            # 1. Try loading directly using transformers
            try:
                from transformers import pipeline
                print(f"Loading model: {model_name}")
                return pipeline("text-generation", model=model_name, device_map="auto")
            except Exception as e:
                print(f"Failed to load with transformers: {e}")
            
            # 2. Try Ollama if it looks like an Ollama model
            if "/" not in model_name and model_name.lower() != model_name:
                try:
                    import ollama
                    print(f"Trying Ollama with model: {model_name}")
                    return OllamaModel(model_name)  # Custom wrapper class
                except Exception as e:
                    print(f"Ollama not available: {e}")
                    
            # 3. Try LM Studio on default port
            try:
                response = requests.get("http://localhost:1234/v1/models")
                if response.status_code == 200:
                    print("Found LM Studio - checking for requested model")
                    models = response.json()
                    if any(m["id"] == model_name for m in models):
                        return LMStudioModel(model_name)  # Custom wrapper class
            except Exception as e:
                print(f"LM Studio not available: {e}")
        except Exception as general_error:
            print(f"Error loading model: {general_error}")
            
    print("No model specified or found - running without LLM enhancements")
    return None