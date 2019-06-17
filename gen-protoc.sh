#!/usr/bin/env bash

# Generate protobuf compiled files
protoc --python_out=aioesphomeapi -I aioesphomeapi aioesphomeapi/*.proto

# https://github.com/protocolbuffers/protobuf/issues/1491
sed -i '' 's/import api_options_pb2 as api__options__pb2/from . import api_options_pb2 as api__options__pb2/' aioesphomeapi/api_pb2.py
