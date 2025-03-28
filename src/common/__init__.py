from whenever import Instant, TimeDelta
from collections.abc import Iterator
from abc import ABC, abstractmethod
import typing

class STIXConversionException(Exception):
    pass

class Indicator:
    def __init__(self, source_indicator: dict, tlp: str, valid_for: TimeDelta, source: str):
        self.name = source_indicator["name"]
        self.pattern = source_indicator["pattern"]
        self.pattern_type = source_indicator["pattern_type"]
        self.valid_from = Instant.parse_rfc3339(source_indicator["valid_from"])
        self.valid_to = self.valid_from + valid_for
        self.tlp = tlp
        self.source = source
    
    def __str__(self):
        return f"{self.name} (tlp:{self.tlp})"

class IndicatorBatch:
    def __init__(self, indicators: list[Indicator], last_added: Instant):
        self.indicators = indicators
        self.last_added = last_added

class IndicatorSource(ABC):
    @abstractmethod
    def produce(self, collection_name: str, since: typing.Optional[Instant], valid_for: TimeDelta) -> Iterator[IndicatorBatch]:
        pass

    @abstractmethod
    def name(self) -> str:
        pass

class IndicatorDestination(ABC):
    @abstractmethod
    def consume(self, indicators: list[Indicator]):
        pass