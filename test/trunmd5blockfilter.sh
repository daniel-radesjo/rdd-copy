#!/bin/sh

# This script runs the tblockmd5 unit test and verifies the test's output.
# The test produces several files with MD5 hash values of 
# blocks of data. This script runs tblockmd5 and calculates the MD5 hash 
# values of the output files. These values are checked and when they do not
# match the expected values, the script exits with an error.

# md5sum seems to exit without an error when the input file 
# does not exist.

PYTHON=python
pyout="python-block-md5.txt"

# The output files we expect
outfiles=""
outfiles="${outfiles} block-md5-bs1572864-chunk1572864.txt"
outfiles="${outfiles} block-md5-bs1024-chunk1024.txt"
outfiles="${outfiles} block-md5-bs1024-chunk1048576.txt"
outfiles="${outfiles} block-md5-bs1024-chunk13373.txt"
outfiles="${outfiles} block-md5-bs1024-chunk3382912.txt"
outfiles="${outfiles} block-md5-bs13373-chunk1024.txt"
outfiles="${outfiles} block-md5-bs13373-chunk1048576.txt"
outfiles="${outfiles} block-md5-bs13373-chunk13373.txt"
outfiles="${outfiles} block-md5-bs13373-chunk3382912.txt"
outfiles="${outfiles} block-md5-bs1048576-chunk1024.txt"
outfiles="${outfiles} block-md5-bs1048576-chunk1048576.txt"
outfiles="${outfiles} block-md5-bs1048576-chunk13373.txt"
outfiles="${outfiles} block-md5-bs1048576-chunk3382912.txt"
outfiles="${outfiles} block-md5-bs3382912-chunk1024.txt"
outfiles="${outfiles} block-md5-bs3382912-chunk1048576.txt"
outfiles="${outfiles} block-md5-bs3382912-chunk13373.txt"
outfiles="${outfiles} block-md5-bs3382912-chunk3382912.txt"

# Run the unit test
./tmd5blockfilter

i=0
for outfile in $outfiles
do
	i=`expr $i + 1`

	# outfile format: block-md5-bs<block size>-chunk<chunk size>.txt
	bs=`expr $outfile : 'block-md5-bs\([0-9]*\).*\.txt'`
	$PYTHON blockhash.py image.img $bs > $pyout

	# Check if the output file exists.
	if ! [ -e $outfile ]; then
		echo "ERROR: output file $outfile does not exist"
		exit 1
	fi

	if ! cmp $outfile $pyout
	then
		echo "ERROR: test case $i: errors in output file $outfile"
		exit 1
	fi

	rm -f $pyout
	rm -f $outfile
	echo "File $outfile is OK (removed)";
done

rm -f block-md5-bs*.txt
