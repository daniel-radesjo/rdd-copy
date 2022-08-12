#!/bin/sh

echo "----------Testing the message printer"

rm -f msgprinter.log msgprinter-stderr.log

#./tmsgprinter msgprinter.log "testing the message printer" U1 U2 U3 R1 R2 R3 2> msgprinter-stderr.log

python tmsgprinter.py msglog.txt stderr_msglog.txt errorcodes.txt

rm -f msgprinter.log msgprinter-stderr.log
echo "----------Finished testing the message printer"
