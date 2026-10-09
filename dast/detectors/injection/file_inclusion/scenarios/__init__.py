"""File Inclusion & Path Traversal Scenarios Package."""

from dast.detectors.injection.file_inclusion.scenarios.base import BaseFileInclusionScenario
from dast.detectors.injection.file_inclusion.scenarios.high_prefix import HighPrefixScenario
from dast.detectors.injection.file_inclusion.scenarios.low_traversal import LowTraversalScenario
from dast.detectors.injection.file_inclusion.scenarios.medium_nested import MediumNestedScenario
from dast.detectors.injection.file_inclusion.scenarios.php_wrapper import PHPWrapperScenario
from dast.detectors.injection.file_inclusion.scenarios.rfi_probe import RFIProbeScenario

__all__ = [
    "BaseFileInclusionScenario",
    "LowTraversalScenario",
    "MediumNestedScenario",
    "HighPrefixScenario",
    "PHPWrapperScenario",
    "RFIProbeScenario",
]

