#!/bin/bash
cd $1
nohup ./t-rex-64 -i -c 8 >/dev/null 2>&1 &
