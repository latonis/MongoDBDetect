# Detection-as-Code with MongoDB Change Streams
This repository is an example implementation of a monitoring system that implements detection-as-code principles with Python and MongoDB with Change Streams.
The examples contain an agent to collect and forward logs, an engine to process the logs and alert if desired, and rule files to be loaded by the detection engine.

## Slides
Slides are available [here](./MongoDB-and-DaC.pdf).

## Environment Variables

These environment variables are all needed for the detection engine to function.

The monitoring agent reuiqres the variables prefixed with `CHANGE_`.
```bash
export ALERT_COLLECTION_NAME=alert 
export CONFIG_COLLECTION_NAME=configuration
export CHANGE_COLLECTION_NAME=process
export CHANGE_DB_NAME=monitoring                      
export CHANGE_STREAM_DB="mongodb://localhost:27017"
```
## Running the Engine
```bash
python engine/detection.py
```

## Running the Agent
The agent requires sudo privileges due to the eBPF portion of the code.
```bash
python3 engine/detection.py
```
## Directory
```bash
.
├── collection
│   └── agent.py
├── engine
│   ├── detection.py
│   ├── __init__.py
│   ├── rule.py
│   └── tests
│       ├── __init__.py
│       └── test_engine.py
├── infra
│   ├── docker-compose.yml
│   ├── init.js
│   └── initRS.sh
├── LICENSE
├── MongoDB-and-DaC.pdf
├── pyproject.toml
├── readme.md
└── rules
    ├── shadow.py
    ├── shadow.yaml
    └── tmp_output_redir.yaml
```