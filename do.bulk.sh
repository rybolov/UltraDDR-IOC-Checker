#!/bin/bash

for f in ./data/*.txt  # All advisory lists should be a .txt file
do
  echo "Processing $f"
  # take action on each file. $f store current file name
  python3 ./ddr-ioc-checker.py -i $f
done
git add ./data/*.txt  # All advisory lists
git add ./data/*.csv   # All output files
git commit -m "Updated analysis CSV files."