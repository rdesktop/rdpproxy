#!/bin/sh
./rdpproxy | ./pparser.py - -  | grep Key
