"""ClauseGuard — offline contract risk analyzer."""

from .core import analyze, AnalysisResult, Finding, DETECTORS

__version__ = "1.0.0"
__all__ = ["analyze", "AnalysisResult", "Finding", "DETECTORS", "__version__"]
