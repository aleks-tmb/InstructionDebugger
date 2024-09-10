#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <build-dir>"
  exit 1
fi

kotlinc Client.kt -include-runtime -d $1/Client.jar