#!/bin/bash

name="$1"
echo "Relinking files to $name"
for f in $(ls "$name")
do
    ln -sf "$name/$f" "$f"
done
