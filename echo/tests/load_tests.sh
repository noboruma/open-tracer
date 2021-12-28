#!/bin/bash

TMPPATH="/tmp"
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
TMPSOCK="$TMPPATH/test.sock"
FILE_NUM=$3
NUM_THREADS=$4
FILE_SEQ=$(seq 1 1 $FILE_NUM)
BINARY_PATH=$1
GRPCURL_PATH=$2

_term() {
    kill $EBPF_PID
    rm $TMPSOCK
    exit 0
}
trap _term TERM INT

pwait() {
    while [ $(jobs -p | wc -l) -ge $1 ]; do
        sleep 1
    done
}

print_res() {
    SUCCESS_COUNT=`$1 -plaintext -import-path $SCRIPTPATH/../proto -authority "d" -proto kernel_tracer.proto -d '{}' -unix "$TMPSOCK" kernel_tracer.KernelTracer/GetMetrics | jq ".eventSuccessCount"`

    FAILURE_COUNT=`$1 -plaintext -import-path $SCRIPTPATH/../proto -authority "d" -proto kernel_tracer.proto -d '{}' -unix "$TMPSOCK" kernel_tracer.KernelTracer/GetMetrics | jq ".eventFailureCount"`

    BUFFER_CAP=`$1 -plaintext -import-path $SCRIPTPATH/../proto -authority "d" -proto kernel_tracer.proto -d '{}' -unix "$TMPSOCK" kernel_tracer.KernelTracer/GetMetrics | jq ".ebfBufferCapacity"`

    echo "success: $SUCCESS_COUNT, failure: $FAILURE_COUNT, buf cap: $BUFFER_CAP"
}

prepare_files() {
    echo "Prepare files"
    for i in $FILE_SEQ
    do
        touch $TMPPATH/dummy$i
    done
}

cleanup() {
    echo "\nCleaning..."
    for i in $FILE_SEQ
    do
        rm $TMPPATH/dummy$i
    done
}

prepare_files

echo "Run"
$BINARY_PATH --socket-path $TMPSOCK&
EBPF_PID=$!

start=$(date +%s)

for i in $FILE_SEQ
do
    cat $TMPPATH/dummy$i&
    pwait $NUM_THREADS
done

print_res $GRPCURL_PATH
end=$(date +%s)

MEMUSE=`sudo pmap $EBPF_PID | grep total`
echo "Took: $((${end} - ${start})) sec"
echo "Memory usage: $MEMUSE"

cleanup

_term
