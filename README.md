# IOCShuttle
A small python tool for continually importing IoCs from a TAXII feed into various locations (EDL lists, Crowdstrike, etc.)

# Building/Running

It's recommended to use [uv](https://github.com/astral-sh/uv/releases/tag/0.6.10) to manage the python environment.  Execute `uv run .\main.py` to run the project.

# Configuring

All configuration is store in `config.toml`.  An example configuration with documentation is provided.  Configuration is split in three parts: sources, destinations, and connections.  Sources define one or more TAXII 2.1 locations to retrieve IoCs from.  Destinations define one or more crowdstrike connections, or EDL list destinations.  Connections pair defined sources with defined destinations.

# Sync Operation

Each sync cycle, IoCs will be retrieved.  They will be broken down into URLs, domains, and hashes.  Only these types of IoCs are supported by this tool.  IoCs will be valid for a period of time defined in the config file.  This time will be counted from the last time a particular hash/URL/domain was seen.  When an IoC expires, it will be removed by CrowdStrike, or removed off the EDL list.