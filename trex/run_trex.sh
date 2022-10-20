#!/bin/bash
cd $1
nohup python3 run_trex.py -b $2 -v $3 -t $4 -r $5 -nc $6 &
