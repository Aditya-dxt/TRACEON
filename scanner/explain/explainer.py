"""
scanner/explain/explainer.py

Model-card and lineage extraction assistant.
Uses Gemini API (or structured regex heuristic fallback) to interpret model READMEs.
Strict Rule: This module can NEVER set severity or a verdict. Output is labelled as explanation only.
"""

import os
import re
import json
import urllib.request
from typing import Dict, Any, Optional


class ModelCardExplainer:
    def __init__(self, api_key: Optional[str] = None, model_name: str = "gemini-1.5-flash"):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model_name = model_name

    def explain(self, model_card_text: str) -> Dict[str, Any]:
        """
        Parses model card markdown and returns extracted metadata.
        Output is validated and explicitly marked with type='explanation'.
        """
        if self.api_key:
            try:
                extracted = self._call_gemini(model_card_text)
                if extracted:
                    return self._wrap_explanation(extracted, method="gemini")
            except Exception:
                pass

        # Robust offline regex/heuristic fallback
        extracted = self._heuristic_parse(model_card_text)
        return self._wrap_explanation(extracted, method="heuristic_fallback")

    def _wrap_explanation(self, data: Dict[str, Any], method: str) -> Dict[str, Any]:
        return {
            "type": "explanation",
            "extraction_method": method,
            "disclaimer": "LLM output is for informational context only. Deterministic checks and policy decide verdicts.",
            "data": {
                "base_model": data.get("base_model", "unknown"),
                "licence": data.get("licence", "unknown"),
                "datasets": data.get("datasets", []),
                "task": data.get("task", "general"),
                "summary": data.get("summary", "")
            }
        }

    def _call_gemini(self, text: str) -> Optional[Dict[str, Any]]:
        prompt = (
            "You are an AI security assistant. Analyze this model card text and extract the following fields in JSON format:\n"
            "- base_model: string (name of the foundation model, or 'none')\n"
            "- licence: string (e.g. 'apache-2.0', 'mit', 'llama-community', etc.)\n"
            "- datasets: list of strings (datasets mentioned)\n"
            "- task: string\n"
            "- summary: string (1-sentence summary)\n"
            "Return ONLY the JSON object. Do NOT assign any security verdict or severity.\n\n"
            f"MODEL CARD:\n{text[:8000]}"
        )
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"response_mime_type": "application/json"}
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            res_json = json.loads(resp.read().decode("utf-8"))
            candidate_text = res_json["candidates"][0]["content"]["parts"][0]["text"]
            return json.loads(candidate_text)

    def _heuristic_parse(self, text: str) -> Dict[str, Any]:
        """Offline parser for model cards using regex patterns."""
        base_model = "unknown"
        licence = "unknown"
        datasets = []
        task = "general"

        # Check for YAML frontmatter at start
        yaml_match = re.search(r"^---\s*(.*?)\s*---", text, re.DOTALL)
        if yaml_match:
            frontmatter = yaml_match.group(1)
            # Find base_model
            bm = re.search(r"(?:base_model|base-model):\s*([^\n]+)", frontmatter, re.IGNORECASE)
            if bm:
                base_model = bm.group(1).strip().strip("\"'")
            # Find license
            lic = re.search(r"(?:license|licence):\s*([^\n]+)", frontmatter, re.IGNORECASE)
            if lic:
                licence = lic.group(1).strip().strip("\"'")
            # Find datasets
            ds_matches = re.findall(r"-\s*([a-zA-Z0-9_\-\/]+)", frontmatter)
            if ds_matches:
                datasets = ds_matches[:5]

        # Scan prose if frontmatter was missing or partial
        if licence == "unknown":
            lic_search = re.search(r"(?:license|licence)[:\s]+([a-zA-Z0-9\.\-_]+)", text, re.IGNORECASE)
            if lic_search:
                licence = lic_search.group(1).strip()

        if base_model == "unknown":
            bm_search = re.search(r"(?:fine-tuned from|based on|base model)[:\s]+([a-zA-Z0-9\.\-_/]+)", text, re.IGNORECASE)
            if bm_search:
                base_model = bm_search.group(1).strip()

        summary = f"Model card parsed. Licence: {licence}, Base model: {base_model}."
        return {
            "base_model": base_model,
            "licence": licence,
            "datasets": datasets,
            "task": task,
            "summary": summary
        }
