#!/bin/sh

rush rebuild
api-extractor run --local --verbose
api-documenter markdown --input-folder ../../common/temp --output-folder docs
