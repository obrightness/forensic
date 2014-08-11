#!/bin/sh


for idx in 1 2 3 4
do
    ./pcapcat -r $1  -w stream${idx}.dump -d $idx
done
