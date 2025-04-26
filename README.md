# Santé

## AI-Powered Healthcare Triage System

Santé is an open-source AI triage system designed to prioritize patient care by analyzing initial complaints and directing them to appropriate medical specialists. By automating the preliminary assessment process, Santé helps healthcare providers focus their attention on the most critical cases first.

## 🌟 Features

- **Smart Triage**: Analyzes patient complaints and symptoms to determine urgency levels
- **Specialty Routing**: Directs patients to the appropriate medical specialty based on their symptoms
- **Priority Queuing**: Ensures critical cases receive immediate attention
- **Multilingual Support**: Processes patient information in multiple languages
- **HIPAA-Compliant**: Built with privacy and security at its core

## 🧠 AI Models

Santé leverages state-of-the-art open-source healthcare AI models:

- **Core Triage Engine**: Built on ClinicalBERT for understanding medical terminology and patient descriptions
- **Symptom Analysis**: Uses BioGPT to process and understand complex symptom descriptions
- **Response Generation**: Implements ChatDoctor for generating appropriate guidance to patients
- **Clinical Prediction**: Incorporates CPLLM for predicting potential diagnoses from symptom patterns

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- PyTorch 1.9+
- Transformers 4.15+
- Hugging Face account for model access

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/sante.git
cd sante

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download pre-trained models
python scripts/download_models.py
```

### Basic Usage

```python
from sante import TriageAgent

# Initialize the triage agent
agent = TriageAgent()

# Process a patient complaint
result = agent.triage("I've been experiencing chest pain and shortness of breath for the past 2 hours")

# Get triage results
print(f"Urgency Level: {result.urgency}")
print(f"Recommended Specialty: {result.specialty}")
print(f"Suggested Action: {result.action}")
```

## 📊 Model Training & Fine-tuning

Santé can be fine-tuned on your institution's data for improved performance:

```bash
# Prepare your dataset in the required format
python scripts/prepare_data.py --input your_data.csv --output processed_data

# Fine-tune the model
python scripts/finetune.py --data processed_data --output_dir ./fine_tuned_model
```

## 🧪 Evaluation

We evaluate Santé's performance on multiple metrics:

- Urgency classification accuracy
- Specialty routing precision
- Critical case identification recall
- Response appropriateness

```bash
# Run evaluation suite
python scripts/evaluate.py --model ./fine_tuned_model --test_data ./test_data
```

## 📖 Documentation

For comprehensive documentation, visit our [documentation site](https://sante.readthedocs.io/) or check the `docs/` directory.

## 🤝 Contributing

Contributions to Santé are welcome! Please see our [Contributing Guidelines](CONTRIBUTING.md) for more details.

## 📄 License

Santé is released under the [MIT License](LICENSE).

## 📞 Support

For support, please open an issue on GitHub or contact the maintainers at support@sante-ai.org.

## 🙏 Acknowledgements

Santé builds upon several open-source healthcare AI models. We're grateful to the researchers and organizations who have made their work available to the community:

- ClinicalBERT by Alsentzer et al.
- BioGPT by Microsoft Research
- ChatDoctor by Kent Hospital AI Lab
- CPLLM by Medical AI Research Consortium

---

**Note**: Santé is designed to assist healthcare professionals in the triage process and is not intended to replace professional medical advice, diagnosis, or treatment. Always consult qualified healthcare providers for medical concerns.
