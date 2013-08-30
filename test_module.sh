#!/bin/bash
# declare STRING variable

echo off

TARGET_IP="192.168.1.24"
TARGET_PATH=/root/
MODULE_NAME=http
USER_NAME=root

#print variable on a screen
echo "Testing kernel module on target $TARGET_IP"

echo "Copy of $MODULE_NAME.ko to $TARGET_IP"
scp $MODULE_NAME.ko $USER_NAME@$TARGET_IP:$TARGET_PATH$MODULE_NAME.ko

echo "loading of module into kernem"
ssh $USER_NAME@$TARGET_IP "rmmod $MODULE_NAME;insmod $MODULE_NAME.ko"

echo "basic module testing"
#wget -O tmp.html http://$TARGET_IP:9090/  
rm tmp.html
