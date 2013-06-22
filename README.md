# Http Kernel Module
=========

USE ON YOUR OWN RISK. WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.

## Introduction

This is a Linux kernel module for handling http protocol inside kernel, the project will provide an new implementation of "RFC 2616" with most of the process in kernel mode.


## Latest Stable Version

NO STABLE VERSION : just a quick and dirty hack to explore kernel network development.
Kernel version : 3.2.0-4-amd64


## Building and installing 

    git clone https://github.com/lcantat/kern_http.git
    cd kern_http
    export CONFIG_HTTP=m;make
    sudo insmod http.ko
    
If you whan to test : you can test with the following command
    wget http://127.0.0.1:9090/



