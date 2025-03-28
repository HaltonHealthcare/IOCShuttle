from common import Indicator, IndicatorSource, IndicatorBatch
from taxii2client.v21 import Server, as_pages
from whenever import Instant, TimeDelta
from collections.abc import Iterator
from logging import Logger
import logging
import typing

taxii2logger = logging.getLogger("taxii2client")
taxii2logger.propagate = True
while taxii2logger.hasHandlers():
    taxii2logger.removeHandler(taxii2logger.handlers[0])

tlp_to_level = {"white":0, "green":1, "amber":2, "red":3}
level_to_tlp = {0:"white", 1:"green", 2:"amber", 3:"red"}

class TAXII21IndicatorSource(IndicatorSource):
    def __init__(self, log: Logger, url: str, user: str, password: str):
        self.server = Server(url, user=user, password=password)
        self.log = log
    
    def produce(self, collection_name: str, since: typing.Optional[Instant], valid_for: TimeDelta) -> Iterator[IndicatorBatch]:
        if since is None:
            since = Instant.now() - valid_for
        api_root = self.server.api_roots[0]
        collections = [collection for collection in api_root.collections if collection.title == collection_name]
        collection = collections[0] if collections else None
        if collection is None:
            raise Exception(f"Could not locate collection with title \"{collection_name}\"")
        for envelope in as_pages(collection.get_objects, per_request=200, type="indicator,marking-definition,identity", added_after=since.format_rfc3339().replace(" ", "T")):
            indicators = []
            if "objects" in envelope:
                marking_definitions = dict([(obj["id"], obj) for obj in envelope["objects"] if obj["type"] == "marking-definition"])
                identities = dict([(obj["id"], obj["name"]) for obj in envelope["objects"] if obj["type"] == "identity"])
                for obj in [obj for obj in envelope["objects"] if obj["type"] == "indicator"]:
                    object_markings = [marking_definitions[marking_definition] for marking_definition in obj["object_marking_refs"]]
                    tlp_markings = [object_marking["definition"]["tlp"].lower() for object_marking in object_markings if object_marking["definition_type"].lower() == "tlp"]
                    highest_tlp = level_to_tlp[max(tlp_to_level[tlp_marking] for tlp_marking in tlp_markings)]
                    indicators.append(Indicator(obj, highest_tlp, valid_for, identities[obj["created_by_ref"]]))
            last_added = None
            if "x_cyber_gc_ca_date_added_last" in envelope:
                self.log.info(f"Received {len(indicators)} indicators dated {envelope["x_cyber_gc_ca_date_added_last"]}")
                last_added = Instant.parse_rfc3339(envelope["x_cyber_gc_ca_date_added_last"])
            yield IndicatorBatch(indicators, last_added)
    
    def name(self) -> str:
        return self.server.title