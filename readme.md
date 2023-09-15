# Detection-as-Code with MongoDB Change Streams
This repository is an example implementation of a monitoring system that implements detection-as-code principles with Python and MongoDB with Change Streams.
The examples contain an agent to collect and forward logs, an engine to process the logs and alert if desired, and rule files to be loaded by the detection engine.

## Environment Variables

These environment variables are needed for the detection engine to know where to look for the logs to monitor.
```bash
export CHANGE_COLLECTION_NAME=process
export CHANGE_DB_NAME=monitoring                      
export CHANGE_STREAM_DB="mongodb://localhost:27017"
```


## Directory
```bash
├── collection
│   └── agent.py
├── engine
│   ├── detection.py
│   ├── __init__.py
│   └── rule.py
├── infra
│   ├── docker-compose.yml
│   ├── init.js
│   └── initRS.sh
├── LICENSE
├── readme.md
└── rules
    ├── shadow.yaml
    └── tmp_pipe.yaml
```