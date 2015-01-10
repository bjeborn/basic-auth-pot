#!/bin/bash

PATH=$PATH:/sbin
bapdir=$(dirname "$(readlink -f "$0")")
start-stop-daemon -S -p ${bapdir}/bap.pid -m -o -b -a ${bapdir}/bap.py
