#!/bin/bash
###########################################################################################################
# File: compile.sh
#
# ThreatQuotient Proprietary and Confidential
# Copyright (c)2021 ThreatQuotient, Inc. All rights reserved.
#
# NOTICE: All information contained herein, is, and remains the property of ThreatQuotient, Inc.
# The intellectual and technical concepts contained herein are proprietary to ThreatQuotient, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law.
#
# Dissemination of this information or reproduction of this material is strictly forbidden unless prior
# written permission is obtained from ThreatQuotient, Inc.
###########################################################################################################

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
