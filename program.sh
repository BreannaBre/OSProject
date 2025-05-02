#!/bin/bash
rm -rf mediator_pipe
mkfifo mediator_pipe
sudo python3 opensnoop.py | python3 dissector.py > mediator_pipe &
python3 confirmer.py
