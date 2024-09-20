#!/bin/bash

run() {
	sn=${1}
	tn=${2}
	cmd=$(printf "ssh node-0%x /mnt/mac/tests/run.sh --target=%x --use-gw\n" ${sn} ${tn})
	echo "${cmd} &"
	$cmd &
}

run 1 4
run 2 8
run 3 10
run 6 7
run 9 12
run 5 11

#run 1 17
#run 2 12
#run 3 33
#
#run 4 10
#run 5 16
#run 6 34
#
#run 7 35
#run 8 11
#run 9 36

# wait for all background tests to finish
wait
