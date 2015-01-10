#!/bin/bash

PATH=$PATH:/sbin
bapdir=$(dirname "$(readlink -f "$0")")
/sbin/start-stop-daemon -K -p ${bapdir}/bap.pid --remove-pidfile
