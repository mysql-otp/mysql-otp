#!/bin/bash
# Author: Andrey Nikishaev, Viktor Söderqvist
LOG_FORMAT='* %s [%ci]'
echo "Change log"
echo "=========="
git tag -l | sort -V -u -r | while read TAG ; do
    echo
    if [ $NEXT ]; then
        echo "$NEXT"
        echo "-----"
    fi
    GIT_PAGER=cat git log --no-merges --format="$LOG_FORMAT" $TAG..$NEXT
    NEXT=$TAG
done
FIRST=$(git tag -l | head -1)
echo
echo "$FIRST"
echo "-----"
GIT_PAGER=cat git log --no-merges --format="$LOG_FORMAT" $FIRST
