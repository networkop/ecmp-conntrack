#!/bin/bash

chmod +x agent.py 
docker build -t df-agent .
docker image tag df-agent:latest networkop/df-agent:latest
docker push networkop/df-agent
