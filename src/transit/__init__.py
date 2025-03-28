from .crowdstrikedestination import CrowdStrikeIndicatorDestination
from .taxii21source import TAXII21IndicatorSource
from .edldestination import EDLDestination
from common import Indicator, IndicatorSource, IndicatorDestination
from whenever import TimeDelta
from collections.abc import Iterator
from logging import Logger
import shelve
import os

def copy_to(log: Logger, source: IndicatorSource, destinations: list[IndicatorDestination], collection_name: str, valid_for: TimeDelta, state_dir: str):
    with shelve.open(os.path.join(state_dir, "feed_bookmarks"), "c") as shelf:
        feed_source_name = f"{source.name()}_{collection_name}"
        feed_last_read = shelf[feed_source_name] if feed_source_name in shelf else None
        log.info(f"Starting copy for source/dest pair named {feed_source_name} (last timestamp is {feed_last_read})")
        indicators = []
        for batch in source.produce(collection_name, feed_last_read, valid_for):
            for indicator in batch.indicators:
                indicators.append(indicator)
            if batch.last_added is not None:
                shelf[feed_source_name] = batch.last_added
                log.info(f"Updated last added for {feed_source_name} to {batch.last_added}")
        log.info("Finished source retrieval.  Starting filter")
        original_length = len(indicators)
        indicators = list(dedupe(indicators))
        log.info(f"Filter finished - removed {original_length - len(indicators)} duplicate indicators from {original_length} source indicators.  Starting destination upload")
        for destination in destinations:
            try:
                destination.consume(indicators)
            except Exception as err:
                log.exception(err)
                raise err

def dedupe(source_indicators: Iterator[Indicator]) -> Iterator[Indicator]:
    seen_indicators = set()
    for indicator in sorted(source_indicators, key=lambda indicator: indicator.valid_from, reverse=True): # descending order
        indicator_key = (indicator.pattern, indicator.pattern_type)
        if not indicator_key in seen_indicators:
            seen_indicators.add(indicator_key)
            yield indicator