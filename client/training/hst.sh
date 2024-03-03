#!/bin/bash

# Define constants
LOG_DIR="./logs"
OUTPUT_FILE="./monitor.txt"
PID_FILE="./udg.pid"

start() {
    echo "Starting monitoring script..."
        # Ensure the monitoring script isn't already running
    if [ -f $PID_FILE ]; then
        echo "Monitoring script is already running."
        return
    fi

    # Run in background
    (
        while true; do
            NOW=$(date '+%Y-%m-%d %H:%M:%S')

            if [ "$(ls -A $LOG_DIR)" ]; then
                python3 HST.py
                echo "PROCESSED $NOW" >> $OUTPUT_FILE
            else
                echo "EMPTY $NOW" >> $OUTPUT_FILE
            fi

            sleep 21600
        done
    ) & echo $! > $PID_FILE

    echo "Monitoring script started."
}

stop() {
    if [ ! -f $PID_FILE ]; then
        echo "Monitoring script is not running or pid file is missing."
        return
    fi

    echo "Stopping monitoring script..."
    kill $(cat $PID_FILE) && rm $PID_FILE
    echo "Monitoring script stopped."
}

restart() {
    echo "Restarting monitoring script..."
    stop
    # Wait a moment to ensure the process has fully terminated before restarting
    sleep 2
    start
}


case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
    restart
    ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
        ;;
esac
