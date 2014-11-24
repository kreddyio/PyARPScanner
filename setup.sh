#!/bin/bash
echo "Adding support to third-party modules"
sudo apt-get install python-dev
echo "Installing required modules"
sudo pip install netifaces
sudo pip install scapy
echo "Modules installed."