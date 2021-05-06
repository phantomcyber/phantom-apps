#!/bin/bash

# This script will take the code in the phcybereason folder, copy it to the Splunk Phantom server,
# compile it on the server and then install it.

# For this to work, you must have passwordless ssh login setup for the Splunk Phantom server.
# (You need to add your SSH public key into the phantomjs machines authorized_keys file.)
PHANTOM_SERVER=192.168.56.101
PHANTOM_USER=phantom

# Create a temporary build folder
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TEMP_DIR=$SCRIPT_DIR/tmp
echo $SCRIPT_DIR
# Create a tarball of the phcybereason folder in the tmp dir
rm -rf $TEMP_DIR
mkdir -p $TEMP_DIR
cd $TEMP_DIR
tar -czvf phcybereason.tgz ../phcybereason

# Copy the tarball to the phantom server
scp phcybereason.tgz $PHANTOM_USER@$PHANTOM_SERVER:~/

# Unpack the tarball on the server
ssh $PHANTOM_USER@$PHANTOM_SERVER tar -zxvf phcybereason.tgz

# Compile the source on the server
ssh $PHANTOM_USER@$PHANTOM_SERVER "cd phcybereason && phenv python /opt/phantom/bin/compile_app.pyc -i"

# Get the compiled tar file back from the server and store it in the dist folder. This file can be installed from the Phantom UI.
DIST_DIR=$SCRIPT_DIR/release
rm -rf $DIST_DIR
mkdir -p $DIST_DIR
RELEASE_FILE=$DIST_DIR
scp $PHANTOM_USER@$PHANTOM_SERVER:~/phcybereason.tgz $RELEASE_FILE
# # cd $SCRIPT_DIR