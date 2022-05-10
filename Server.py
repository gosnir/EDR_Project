#!/usr/bin/python3

#Server.py - server side of project EDR
#Runs a listening server, Clients can connect to the server any time.
#monitors if a client has been disconnected and knows how many clients are connected.
#logs relevant data to log files, data such as duplicated MAC addresses and surfing in blacklist websites.

import socket
from pathlib import Path
from subprocess import check_output, run
from threading import Thread
from time import sleep

PROJECTPATH = Path(__file__).resolve().parent
HOST = '0.0.0.0'
PORT = 5050

# Socket object.
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

connectionsCount = 0  # How many clients are connected to the server.
activeAddressesList = []  # List of connected addresses.
openClientSocketsList = []  # List of open socket connections

# Sends restricted websites list to the client:
def restrictedsites(conn):
	recvthanks = conn.recv(1024)
	restrictedWebsites = 'facebook youtube ynet netflix blackweb'
	conn.send(restrictedWebsites.encode())

# main:
# Binds socket to ((HOST, PORT)), listening to connections, accepting new connections, sets a format for connName.
# Sends welcome message to new clients, appends new client's socket objects and connName to the lists.
# Starts 2 threads: One for handling clients and the other for checking connections with clients.
def main():
    try:
        serverSocket.bind((HOST, PORT))  # Bind the socket.
    except socket.error as error:
        exit(f'\033[1;31;40m[ERROR]\033[0m Error in Binding the Server:\n{error}')
    print(f'\033[1;32;40m[INFO]\033[0m Listening on port {PORT} - Waiting for connections...')
    serverSocket.listen()
    for clientSocket in openClientSocketsList:
        # Closes all preavious connections if Server.py restarted:
        clientSocket.close()
        # Deletes all previous open client sockets and active addresses from the lists:
        del openClientSocketsList[:], activeAddressesList[:]

    while True:
        try:
            # Accepts connections:
            conn, (address, port) = serverSocket.accept()
            # Appends the client's socket to the list:
            openClientSocketsList.append(conn)
            # Set a format for the connName using client's address and port:
            connName = '{}:{}'.format(address, port)
            print(f'\033[1;32;40m[INFO]\033[0m {connName} Connected!')
            welcomeMessage = f'Successfully connected to EDR Server at {HOST}:{PORT}.'
            # Sends welcome message to the client:
            conn.send(welcomeMessage.encode())
            restrictedsites(conn)
            global connectionsCount
            connectionsCount += 1  # Adding +1 to the connections count.
            # Appends the new address to the activeAddressesList:
            activeAddressesList.append(connName)
            # Prints current connections count:
            print(f'\033[1;32;40m[INFO]\033[0m Number of Active Connections: {connectionsCount}')
            # Starts a new thread to handle each client (args are the connection and formatted connection name):
            Thread(target=handleClient, args=(conn, connName)).start()
            # Starts a checkConnections thread:
            Thread(target=checkConnections).start()
        except socket.error as acceptError:
            print(f'\033[1;31;40m[ERROR]\033[0m Accepting Connection from: {conn.getpeername()}:\n{acceptError}')
            continue


# handleClient(conn, connName):
# Main function to recieve data from all clients.
# Handles client connections using args from main.
# If data has "MAC" in it, logs the data to 'MitMLogger.log'
# If data has "restricted" in it, logs the data to 'RestrictedSitesLogger.log'
def handleClient(conn, connName):
    while True:
        try:
            data = conn.recv(4096).decode()
            if "MAC" in data:
                # Timestamp for the log file:
                timestamp = check_output("date -u +'%d/%m/%Y %H:%M'", shell=True).decode().rstrip()
                print('\033[1;33;40m[WARNING]\033[0m Possible Man in the Middle attack. Check MitMLogger.log')
                with open(f"{PROJECTPATH}/MitMLogger.log", "a+") as MitMLog:
                    MitMLog.write(f"[{timestamp}]\t[{connName}]:\n{data}")  # Logs the MitM attack from the client to 'MitMLogger.log'

            if "restricted" in data:
                # Timestamp for the log file:
                timestamp = check_output("date -u +'%d/%m/%Y %H:%M'", shell=True).decode().rstrip()
                print(f'\033[1;35;40m[ALERT]\033[0m Someone entered to a restricted site. Check RestrictedSitesLogger.log')
                with open(f'{PROJECTPATH}/RestrictedSitesLogger.log', 'a+') as restrictedLog:
                    restrictedLog.write(f"[{timestamp}]\t[{connName}]:\n{data}")  # Logs the restricted site from the client to 'RestrictedSitesLogger.log'
        except:
            pass


# checkConnections:
# Checks what clients are alive by iterating through every client socket object and trying to send a whitespace string.
# If an exception occurs, it means that the client is dead.
# Deletes the client socket object and address from the lists and decreasing 1 from connections count.
# This check happens every 30 seconds.
def checkConnections():
	while True:
		global connectionsCount
		if len(openClientSocketsList) != 0:
			for x, currentSocket in enumerate(openClientSocketsList):
				try:
					# Send a whitespace to every socket in the list:
					pingToClientMessage = ' '
					currentSocket.send(pingToClientMessage.encode())
				except:
					print(f'\033[1;32;40m[INFO]\033[0m Client {x} Disconnected!')
					# Deletes the client socket and address from the lists:
					del openClientSocketsList[x], activeAddressesList[x]
					connectionsCount -= 1
					if connectionsCount == 0:  # If no connections left:
						print(f'\033[1;32;40m[INFO]\033[0m No active connections left.')
					else:  # If there are still connections left:
						print(f'\033[1;32;40m[INFO]\033[0m Number of Active Connections: {connectionsCount}')
						print(f'\033[1;32;40m[INFO]\033[0m Active addresses connected:')
						# Prints a list of the current open connections:
						for index, value in enumerate(activeAddressesList):
							print(f'{index}. {value}')
					continue
		sleep(30)

# Start of the Script:
if __name__ == '__main__':
    main()
