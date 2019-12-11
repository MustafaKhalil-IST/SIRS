# Hardware Locator - SIRS 2019/2020

[![N|Solid](https://cldup.com/dTxpPi9lDf.thumb.png)](https://nodesource.com/products/nsolid)

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)
# Introduction
Hardware Locator is an application that makes user able to track his devices locations, in a way that guarantees confidentiality, Authenticity and Non repudiation.

# Requirements
  - python 3.7.4 and PIP
  - PyCryptodome
  - Hashlib, passlib
  - requests
  - PybLuez
  - Flask
  - flask_httpauth
  - SQL Alchemy: flask_sqlalchemy
  - SQLite database management system

# How to Run Servers?
  - Servers run only in Linux
  - To run Auth Server, In Command Line run: 
```sh
$ cd AuthServer
$ pip install -r requirments.txt
$ python3.7 server.py
```
- To run Locations Server, In Command Line run: 
```sh
$ cd LocationsServer
$ pip install -r requirments.txt
$ python3.7 server.py
```
  - make sure that the public and private keys are in keys directory in each server, and each one has the public key of the other.

# How to Run Client?
### Windows
- make sure that bluetooth is working
- In cmd, run
```sh
$ cd ClientAppWindows
$ pip install -r requirments.txt
$ python3.7 main.py
```
### Linux
- make sure that bluetooth is working, to install PyBluez in linux do the following
```sh
$ sudo apt-get update
$ sudo apt-get install python-pip python-dev ipython
$ sudo apt-get install bluetooth libbluetooth-dev
$ sudo pip install pybluez
```
- In Command line, run
```sh
$ cd ClientAppLinux
$ pip install -r requirments.txt
$ python3.7 main.py
```



