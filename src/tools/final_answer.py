# src/tools/final_answer.py
from typing import Any, Dict
from smolagents.tools import Tool

class FinalAnswerTool(Tool):
    name = "final_answer"
    description = """Provides the final security analysis answer in a standardized format. 
        REQUIRED: Use this tool with a dictionary containing:
        - vulnerable_packages: dict with package names as keys, list of vulnerability info as values
        - upgrade_recommendations: dict with package upgrade instructions  
        - overall_risk_assessment: string with overall security summary
        
        Example: {"vulnerable_packages": {"pkg": [{"vulnerability_id": "CVE-123", "severity": "High"}]}, "upgrade_recommendations": {"pkg": "upgrade to v2.0"}, "overall_risk_assessment": "Medium risk"}
    """
    
    inputs = {
        'answer': {
            'type': 'object', 
            'description': 'Security analysis result as a dictionary with vulnerable_packages, upgrade_recommendations, and overall_risk_assessment keys'
        }
    }
    output_type = "object"

    def __init__(self):
        self.is_initialized = False

    def forward(self, answer: Any) -> Dict[str, Any]:
        """
        Process and standardize the final security analysis answer.
        
        Args:
            answer: The security analysis answer (should be dict)
            
        Returns:
            Standardized security report dictionary
        """
        # If it's already a dict, ensure it has the required structure
        if isinstance(answer, dict):
            standardized = {
                "vulnerable_packages": {},
                "upgrade_recommendations": {},
                "overall_risk_assessment": "No assessment provided"
            }
            
            # Extract vulnerable_packages from various possible locations
            if "vulnerable_packages" in answer:
                standardized["vulnerable_packages"] = answer["vulnerable_packages"]
            elif "executive_summary" in answer and isinstance(answer["executive_summary"], dict):
                if "vulnerable_packages" in answer["executive_summary"]:
                    standardized["vulnerable_packages"] = answer["executive_summary"]["vulnerable_packages"]
            
            # Extract other fields
            if "upgrade_recommendations" in answer:
                standardized["upgrade_recommendations"] = answer["upgrade_recommendations"]
            if "overall_risk_assessment" in answer:
                standardized["overall_risk_assessment"] = answer["overall_risk_assessment"]
                
            return standardized
        
        # Fallback for non-dict inputs
        return {
            "vulnerable_packages": {},
            "upgrade_recommendations": {},
            "overall_risk_assessment": str(answer)
        }