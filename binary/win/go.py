#!/usr/bin/env python3
# Minimal version of Duino-Coin PC Miner, useful for developing own apps.
# Created by revox 2020-2021
# Modifications made by Robert Furr (robtech21) and YeahNotSewerSide
# Mining Pools added by mkursadulusoy - 2021-09-06
# CUDA integration by Khaluza Yaroslav

import hashlib
import os
from socket import socket
import sys  # Only python3 included libraries
import time
import ssl
import select
from json import load as jsonload
import subprocess

import requests

what_time = 0

soc = socket()



def current_time():
    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)
    return current_time

username = input("Your name: ")

def fetch_pools():
    while True:
        try:
            response = requests.get(
                "https://server.duinocoin.com/getPool"
            ).json()
            NODE_ADDRESS = response["ip"]
            NODE_PORT = response["port"]

            return NODE_ADDRESS, NODE_PORT
        except Exception as e:
            print (f'{current_time()} : Error retrieving mining node, retrying in 15s')
            time.sleep(15)

def goMine(thehash, predhash, diff):
    print(thehash, predhash, diff)
    hashingStartTime = time.time()
    
    result = subprocess.run(["core.exe", thehash, predhash, str(diff)], capture_output=True, text=True)
    result = int(result.stdout)
    
    hashingStopTime = time.time()
    timeDifference = hashingStopTime - hashingStartTime
    hashrate = result / timeDifference
    print("RESULT:", result, "Hashrate",hashrate/1000)
    return [True, result, hashrate]



while True:
    try:
        print(f'{current_time()} : Searching for fastest connection to the server')
        try:
            NODE_ADDRESS, NODE_PORT = fetch_pools()
        except Exception as e:
            NODE_ADDRESS = "server.duinocoin.com"
            NODE_PORT = 2813
            print(f'{current_time()} : Using default server port and address')
        soc.connect((str(NODE_ADDRESS), int(NODE_PORT)))
        print(f'{current_time()} : Fastest connection found')
        server_version = soc.recv(100).decode()
        print (f'{current_time()} : Server Version: '+ server_version)
        # Mining section
        while True:
            soc.send(bytes(
                "JOB,"
                + str(username)
                + ",MEDIUM",
                encoding="utf8"))


            # Receive work
            job = soc.recv(1024).decode().rstrip("\n")
            # Split received data to job and difficulty 
            job = job.split(",")
            difficulty = job[2]
##########################################################
            status, result, hashrate = goMine(job[0], job[1], job[2])
            if status:
                # Send numeric result to the server
                soc.send(bytes(
                    str(result)
                    + ","
                    + str(hashrate)
                    + ",Mini",
                    encoding="utf8"))

                # Get feedback about the result
                feedback = soc.recv(1024).decode().rstrip("\n")
                # If result was good
                if feedback == "GOOD":
                    print(f'{current_time()} : Accepted share',
                            result,
                            "Hashrate",
                            int(hashrate/1000),
                            "kH/s",
                            "Difficulty",
                            difficulty)
                        # If result was incorrect
                elif feedback == "BAD":
                    print(f'{current_time()} : Rejected share',
                            result,
                            "Hashrate",
                            int(hashrate/1000),
                            "kH/s",
                            "Difficulty",
                            difficulty)

    except ZeroDivisionError as e:
        print(f'{current_time()} : Error occured: ' + str(e) + ", restarting in 5s.")
        time.sleep(5)
        os.execl(sys.executable, sys.executable, *sys.argv)
