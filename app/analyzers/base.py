from abc import ABC, abstractmethod
from typing import List
from app.http.response import NormalizedResponse
from app.findings.models import Finding
from app.core.logger import setup_logger

class BaseAnalyzer(ABC):
    def __init__(self):
        self.logger = setup_logger(self.__class__.__name__)

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the analyzer"""
        pass

    @abstractmethod
    def analyze(self, response: NormalizedResponse) -> List[Finding]:
        """
        Analyze a normalized HTTP response and return a list of findings.
        Must not crash on malformed responses.
        """
        pass
