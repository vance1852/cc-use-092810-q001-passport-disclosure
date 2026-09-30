"""人形储能电池资产结构化校准数据的基础组件。"""

from .contracts import Observation, Protocol, ValidationError
from .analysis import ALGORITHM_VERSION, analyze, bootstrap_mean_interval
from .disclosure import DisclosureService
from .numeric import NumericSummary, WilsonInterval
from .passports import CLAIM_CATALOG, build_package_content, build_passport_content
from .service import TrialService

__all__ = [
    "NumericSummary",
    "Observation",
    "Protocol",
    "ValidationError",
    "WilsonInterval",
    "ALGORITHM_VERSION",
    "CLAIM_CATALOG",
    "DisclosureService",
    "TrialService",
    "analyze",
    "bootstrap_mean_interval",
    "build_package_content",
    "build_passport_content",
]

__version__ = "0.1.0"
