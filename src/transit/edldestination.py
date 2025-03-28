from common import Indicator, STIXConversionException, IndicatorDestination
from whenever import Instant
from logging import Logger
from netaddr import IPAddress, IPSet
from typing import Callable
from collections.abc import Iterator
import shelve
import re
import tempfile
import shutil
import os

edl_fqdn_from_stix = re.compile(r"^\[domain-name:value\s*=\s*'(?P<fqdn>(?:(?:(?!-))(?:xn--|_)?[a-z0-9-]{0,61}[a-z0-9]{1,1}\.)*(?:xn--)?(?:[a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,}))'\]$")
edl_ip_from_stix = re.compile(r"^\[ipv4-addr:value\s*=\s*\'(?P<address>(?:(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d)\.?\b){4}|[a-fA-F0-9:]+)\'\]$")
edl_url_from_stix = re.compile(r"^\[url:value\s*=\s*\'(?P<url>.+)\'\]$")

class EDLShelf:
    def __init__(self, name: str):
        self.name = name
    
    def __enter__(self):
        self.shelf = shelve.open(self.name, "c")
        return self
    
    def __exit__(self, exception_type, exception_value, exception_traceback):
        self.shelf.close()

    def add_if_newer(self, item: str, valid_to: Instant):
        if item not in self.shelf or self.shelf[item] < valid_to:
            self.shelf[item] = valid_to
    
    def expire(self, now: Instant):
        for (key, valid_to) in self.shelf.items():
            if valid_to < now:
                del self.shelf[key]
    
    def export(self, to: str, compact: Callable[[Iterator[str]], Iterator[str]]):
        with tempfile.NamedTemporaryFile(mode="w", newline="\n", encoding="utf8", delete=True, delete_on_close=False) as tmp:
            for line in compact(self.shelf.keys()):
                tmp.write(line)
                tmp.write("\n")
            tmp.close()
            shutil.copyfile(tmp.name, to)

def compact_ips(source: Iterator[str]) -> Iterator[str]:
    ips = IPSet([IPAddress(x) for x in source])
    ips.compact()
    return (x.__str__() for x in ips)

def strip_proto(source: Iterator[str]) -> Iterator[str]:
    return (x.partition("//")[2] for x in source)

class EDLDestination(IndicatorDestination):
    def __init__(self, log: Logger, state_dir: str, output_dir: str, domain_filename: str, ip_filename: str, url_filename: str):
        self.log = log
        self.state_dir = state_dir
        self.output_dir = output_dir
        self.domain_filename = domain_filename
        self.ip_filename = ip_filename
        self.url_filename = url_filename

    def consume(self, indicators: list[Indicator]):
        with EDLShelf(os.path.join(self.state_dir, "edl_domains")) as domains, EDLShelf(os.path.join(self.state_dir, "edl_ips")) as ips, EDLShelf(os.path.join(self.state_dir, "edl_urls")) as urls:
            for indicator in indicators:
                try:
                    edl_entry = self.convert(indicator)
                except STIXConversionException as err:
                    self.log.warn(err)
                    continue
                match (edl_entry["type"]):
                    case "domain":
                        domains.add_if_newer(edl_entry["value"], indicator.valid_to)
                    case "ip":
                        ips.add_if_newer(edl_entry["value"], indicator.valid_to)
                    case "url":
                        urls.add_if_newer(edl_entry["value"], indicator.valid_to)
            now = Instant.now()
            domains.expire(now)
            ips.expire(now)
            urls.expire(now)

            domains.export(os.path.join(self.output_dir, self.domain_filename), lambda x: x)
            ips.export(os.path.join(self.output_dir, self.ip_filename), compact_ips)
            urls.export(os.path.join(self.output_dir, self.url_filename), strip_proto)

    def convert(self, indicator: Indicator) -> dict:
        if indicator.pattern_type != "stix":
            raise STIXConversionException(f"Pattern type {indicator.pattern_type} isn't convertible")
        ioc = {}
        try:
            for expression_fragment in edl_fqdn_from_stix.finditer(indicator.pattern):
                if expression_fragment is not None:
                    ioc["type"] = "domain"
                    ioc["value"] = expression_fragment.groupdict()["fqdn"].lower()
                    return ioc
            for expression_fragment in edl_ip_from_stix.finditer(indicator.pattern):
                if expression_fragment is not None:
                    ioc["type"] = "ip"
                    ioc["value"] = IPAddress(expression_fragment.groupdict()["address"].lower()).__str__()
                    return ioc
            for expression_fragment in edl_url_from_stix.finditer(indicator.pattern):
                if expression_fragment is not None:
                    ioc["type"] = "url"
                    ioc["value"] = expression_fragment.groupdict()["url"].lower()
                    return ioc
        except Exception as err:
            raise STIXConversionException(err)
        raise STIXConversionException(f"Pattern \"{indicator.pattern}\" cannot be coerced into a EDL list member")