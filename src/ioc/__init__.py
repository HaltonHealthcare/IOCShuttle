import pip_system_certs.wrapt_requests
from transit import CrowdStrikeIndicatorDestination, TAXII21IndicatorSource, copy_to, EDLDestination
from whenever import TimeDelta
import logging
import logging.handlers
import tomllib
import os
import schedule
import time

def main() -> int:
    with open("config.toml", "rb") as f:
        config = tomllib.load(f)

    log_handler = logging.handlers.TimedRotatingFileHandler(os.path.join(config["general"]["log_dir"], "transit.log"), when="D", interval=1, backupCount=15)
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(process)d]: %(message)s", "%b %d %H:%M:%S")
    log_handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)

    state_dir = config["general"]["state_dir"]
    valid_for = TimeDelta(hours=config["intelligence"]["valid_for_days"] * 24)

    sources = {}
    for source_name, source_config in config["source"].items():
        log = logging.getLogger(f"source_{source_name}")
        match source_config["type"]:
            case "taxii21":
                sources[source_name] = TAXII21IndicatorSource(log, source_config["url"], source_config["username"], source_config["password"])
            case _:
                logging.fatal(f"Unknown source type {source_config["type"]}")
                raise SystemExit
    
    destinations = {}
    for destination_name, destination_config in config["destination"].items():
        log = logging.getLogger(f"destination_{destination_name}")
        match destination_config["type"]:
            case "crowdstrike":
                destinations[destination_name] = CrowdStrikeIndicatorDestination(log, destination_config["client_id"], destination_config["client_secret"], destination_config["url"], destination_config["action"], destination_config["severity"])
            case "edl":
                destinations[destination_name] = EDLDestination(log, state_dir, destination_config["output_dir"], destination_config["domain"], destination_config["ip"], destination_config["url"])
            case _:
                logging.fatal(f"Unknown destination type {destination_config["type"]}")
                raise SystemExit
    
    for connection_name, connection_config in config["connection"].items():
        log = logging.getLogger(f"connection_{connection_name}")
        schedule.every(config["intelligence"]["frequency_minutes"]).minutes.do(copy_to, log=log, source=sources[connection_config["source"]], destinations=[destinations[destination_name] for destination_name in connection_config["destinations"]], collection_name=connection_config["collection"], valid_for=valid_for, state_dir=state_dir)
    
    schedule.run_all()
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except KeyboardInterrupt:
            break
