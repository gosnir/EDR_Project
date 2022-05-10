#!/usr/bin/python3

import socket
from os import path, remove
from platform import system
from subprocess import check_output, run
from threading import Thread
from time import sleep
import requests
import colorama
from scapy.all import *

# Gets the running OS as a variable:
runningOS = system()

HOST = '0.0.0.0'  # Server IP.
PORT = 5050  # Server's listening port.

# list of restricted sites
restrictedSitesList = []

# If using Windows, init() will have ANSI color codes converted to the Windows versions
colorama.init()

# main:
# Creates a socket object.
# Connects to server and prints the welcome message.
def main():
	global clientSocket
	global restrictedSitesList
	# Client's Socket Object:
	clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	print('Trying to connect to the server...')
	try:
		clientSocket.connect((HOST, PORT))  # Connects to the server's socket.
		print(f'\033[1;32;40m[INFO]\033[0m You are connected to: {HOST} in port: {PORT}.')
		welcomeMessage = clientSocket.recv(1024)  # Receives welcome message.
		print(welcomeMessage.decode())
		thankyou = 'thanks'
		clientSocket.send(thankyou.encode())
		sites = clientSocket.recv(1024)  # Receives restricted sites list and adds to restrictedSitesList.
		sites_decoded = sites.decode()
		websites = sites_decoded.split()
		for site in websites:
			restrictedSitesList.append(site)
        
	except socket.error as error:
		exit(f'\033[1;31;40m[ERROR]\033[0m Connecting to the server failed:\n\033[31m{error}\033[0m')

# MITM:
# Checks for duplications in ARP table in both Linux and Windows.
# Iterates through the MAC addresses in the ARP table, adding them to a list.
# If a duplication occurs - the value of the MAC in the dictionary will rise by 1.
# For every MAC key that has a value of more than 1, it will send a warning message to the server.
# The scan happens every 15 seconds, can be changed.
def MITM():
    while True:
        macList = []
        macDict = {}
        if runningOS == "Windows":
            ARPmacs = check_output("arp -a", shell=True).decode()

            for line in ARPmacs.splitlines():
                if "dynamic" in line:
                    macList.append(line[24:41])

            for MAC in macList:
                if MAC in macDict:
                    macDict[MAC] = macDict[MAC] + 1
                else:
                    macDict[MAC] = 1

            for MAC, value in macDict.items():
                if value >= 2:
                    clientSocket.send(f'\033[1;33;40m[WARNING]\033[0m Found MAC address duplication. Possible Man in the Middle Attack!\nCheck this MAC: {MAC}\n\n'.encode())

        elif runningOS == "Linux":
            ARPmacs = check_output("arp | awk '{print $3}' | grep -v HW | grep -v eth0", shell=True).decode()
            for line in ARPmacs.splitlines():
                macList.append(line)

            for MAC in macList:
                if MAC in macDict:
                    macDict[MAC] = macDict[MAC] + 1
                else:
                    macDict[MAC] = 1
            for MAC, value in macDict.items():
                if value >= 2:
                    clientSocket.send(f'\033[1;33;40m[WARNING]\033[0m Found MAC address duplication. Possible Man in the Middle Attack!\nCheck this MAC: {MAC}\n\n'.encode())
        sleep(15)

# findDNS: 
# Sniffs DNS quearys of the client.
# Gets only the name of the website from the queary. Setting it to url variable.
# If the name of the site from the restrictedSitesList found in the current sniffed url variable - sends an alert to the server.
def findDNS(pkt):
    if pkt.haslayer(DNS):
        if "Qry" in pkt.summary():  # Only quearys.
            # Gets only the name of the website from the queary:
            url = pkt.summary().split('\"')[-2].replace("", "")[2:-2]
            for site in restrictedSitesList:
                if site in url:
                    clientSocket.send(f'\033[1;35;40m[ALERT]\033[0m Entered a restricted website:\n{site}\n\n'.encode())

# Start of the Script:
if __name__ == '__main__':
    main()
    Thread(target=MITM).start()
    Thread(target=sniff(prn=findDNS)).start()
