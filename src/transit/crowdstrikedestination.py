from common import Indicator, STIXConversionException, IndicatorDestination
from falconpy import IOC
from http import HTTPStatus
from whenever import Instant
from logging import Logger
import re

cs_hash_from_stix = re.compile(r"file:hashes\.'(?P<type>[\w-]+)'\s*=\s*'(?P<value>[a-zA-Z\d]+)'")
cs_fqdn_from_stix = re.compile(r"^\[domain-name:value\s*=\s*'(?P<fqdn>(?:(?:(?!-))(?:xn--|_)?[a-z0-9-]{0,61}[a-z0-9]{1,1}\.)*(?:xn--)?(?:[a-z0-9][a-z0-9\-]{0,60}|[a-z0-9-]{1,30}\.[a-z]{2,}))'\]$")
cs_ipv4_from_stix = re.compile(r"^\[ipv4-addr:value\s*=\s*\'(?P<address>(?:(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d)\.?\b){4})\'\]$")
cs_ipv6_from_stix = re.compile(r"^\[ipv6-addr:value\s*=\s*\'(?P<address>[a-fA-F0-9:]+)\'\]$")

stix_hash_type_to_cs = {"SHA-256": "sha256", "MD5": "md5"}

class CrowdStrikeIndicatorDestination(IndicatorDestination):
    def __init__(self, log: Logger, client_id: str, client_secret: str, base_url: str, action: str, severity: str):
        self.action = action
        self.severity = severity
        self.falcon = IOC(client_id=client_id, client_secret=client_secret, base_url=base_url)
        self.log = log

    def consume(self, indicators: list[Indicator]):
        if len(indicators) != 0:
            indicators = self.convert_all_dedupe(indicators)
            self.log.info("Finished converting IoCs to CrowdStrike format")
            for indicator in indicators:
                response = self.falcon.indicator_combined(from_parent=False, filter=f"type:'{indicator["type"]}'+value:'{indicator["value"]}'")
                if self.is_error_response(response):
                    continue
                existing_id = None
                if len(response["body"]["resources"]) > 0:
                    remote_expiration = Instant.parse_rfc3339(response["body"]["resources"][0]["expiration"])
                    self.log.info(f"Found existing indicator with expiration {remote_expiration}")
                    local_expiration = Instant.parse_rfc3339(indicator["expiration"])
                    if remote_expiration >= local_expiration:
                        self.log.info("Remote indicator has a later expiration than local - skipping")
                        continue
                    existing_id = response["body"]["resources"][0]["id"]
                if existing_id is None:
                    self.log.info("Creating new remote indicator")
                    response = self.falcon.indicator_create(body={"comment": "Automated batch upload", "indicators": indicator})
                    self.is_error_response(response)
                else:
                    self.log.info("Updating remote indicator")
                    indicator["id"] = existing_id
                    response = self.falcon.indicator_update(body={"comment": "Automated batch upload", "indicators": indicator})
                    self.is_error_response(response)
                self.is_error_response(response)
    
    def is_error_response(self, response: dict) -> bool:
        if not HTTPStatus(response["status_code"]).is_success:
            if "resources" in response["body"]:
                for message in response["body"]["resources"]:
                    if message["message_type"] == "warning":
                        self.log.warning(message["message"])
                    else:
                        self.log.error(message["message"])
            else:
                for error in response["body"]["errors"]:
                    self.log.error(error["message"])
            return True
        return False
    
    def convert_all_dedupe(self, source_indicators: list[Indicator]) -> list[dict]:
        indicators = []
        seen_indicators = set()
        for indicator in sorted(source_indicators, key=lambda indicator: indicator.valid_from, reverse=True): # descending order
            try:
                converted = self.convert(indicator)
                if not (converted["type"], converted["value"]) in seen_indicators:
                    seen_indicators.add((converted["type"], converted["value"]))
                    indicators.append(converted)
            except STIXConversionException as warn:
                self.log.warning(warn)
        self.log.info(f"Removed {len(source_indicators) - len(indicators)} duplicate indicators from {len(source_indicators)} source indicators")
        return indicators

    def convert(self, indicator: Indicator) -> dict:
        if indicator.pattern_type != "stix":
            raise STIXConversionException(f"Pattern type {indicator.pattern_type} isn't convertible")
        ioc = {
            "action": self.action,
            "mobile_action": self.action,
            "applied_globally": True,
            "severity": self.severity,
            "retrodetects": True,
            "description": indicator.name,
            "expiration": indicator.valid_to.format_rfc3339().replace(" ", "T").replace("Z", "000Z"),
            "platforms": ["mac", "windows", "linux"],
            "tags": [f"tlp:{indicator.tlp}"],
            "source": indicator.source
        }
        for expression_fragment in cs_hash_from_stix.finditer(indicator.pattern):
            if expression_fragment is not None:
                hash = expression_fragment.groupdict()
                if hash["type"] in stix_hash_type_to_cs:
                    ioc["type"] = stix_hash_type_to_cs[hash["type"]]
                    ioc["value"] = hash["value"].lower()
                    return ioc
        for expression_fragment in cs_fqdn_from_stix.finditer(indicator.pattern):
            if expression_fragment is not None:
                ioc["type"] = "domain"
                ioc["value"] = expression_fragment.groupdict()["fqdn"].lower()
                return ioc
        for expression_fragment in cs_ipv4_from_stix.finditer(indicator.pattern):
            if expression_fragment is not None:
                ioc["type"] = "ipv4"
                ioc["value"] = expression_fragment.groupdict()["address"].lower()
                return ioc
        for expression_fragment in cs_ipv6_from_stix.finditer(indicator.pattern):
            if expression_fragment is not None:
                ioc["type"] = "ipv6"
                ioc["value"] = expression_fragment.groupdict()["address"].lower()
                return ioc
        raise STIXConversionException(f"Pattern \"{indicator.pattern}\" cannot be coerced into a CrowdStrike IoC")