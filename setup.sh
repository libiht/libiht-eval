#!/bin/bash

# TODO

# TODO: Check container with kernel module capabilities
# https://dummdida.tumblr.com/post/117157045170/modprobe-in-a-docker-container

# Setup the environment variables
echo "Setting up environment variables..."
export PIN_ROOT=$PWD/tools/pin
export DYNAMORIO_HOME=$PWD/tools/dynamorio
export PATH=$PIN_ROOT:$DYNAMORIO_HOME/bin64:$PATH