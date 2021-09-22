#!/bin/bash
# Check JSON first!
if $(cat threatq_app/threatq.json | jq . > /dev/null); then
    for f in threatq_app/*.py threatq_app/**/*.py;
        do
            ./compile_app.py -s $f -d
        done;
    app_version=$(cat threatq_app/threatq.json | jq -r .app_version)
    ./compile_app.py -t -v $app_version
else
    echo "BAD JSON"
fi
