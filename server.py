import struct
import sys
from dataclasses import dataclass
import servermodule
import threading
import socket


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


@dataclass
class ServerCfg:
    Id: str
    UDP: int
    TCP: int


@dataclass
class Client:
    Id: str
    Status: str = servermodule.DISCONNECTED
    Id_Comm: int = 0
    IP_Address: str = 0


@dataclass
class UDP_PDU:
    Type: str
    Id_Trans: str
    Id_Comm: str
    Data: str


serverCfg = ServerCfg
cfgFile = "server.cfg"
authFile = "bbdd_dev.dat"
debug_mode = False
clients = []


def errorMsg(text):
    print(Colors.FAIL + "[ERROR] =>\t" + text + Colors.ENDC)


def checkCfgFile(filename):
    if filename.find(".cfg") < 0:
        return False
    return True


def checkAuthFile(filename):
    if filename.find(".dat") < 0:
        return False
    return True


def checkParams():
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "-d":
            global debug_mode
            debug_mode = True
        elif sys.argv[i] == "-c":
            if i + 1 <= len(sys.argv) and checkCfgFile(sys.argv[i + 1]):
                global cfgFile
                cfgFile = sys.argv[i + 1]
            else:
                errorMsg("Wrong config file name entered (filename.cfg)")
                exit(-1)
            i += 1
        elif sys.argv[i] == "-u":
            if i + 1 <= len(sys.argv) and checkAuthFile(sys.argv[i + 1]):
                global authFile
                authFile = sys.argv[i + 1]
            else:
                errorMsg("Wrong authorized clients file name entered (filename.dat)")
                exit(-1)
            i += 1
        else:
            errorMsg("Wrong program parameters entered")
            exit(-1)
        i += 1


def readCfgFile():
    file = open(cfgFile, "r")
    lines = file.read().splitlines()
    global serverCfg
    for i in range(len(lines)):
        if lines[i].startswith("Id") > 0:
            Id = lines[i].split(" ")[2]
            serverCfg.Id = Id
        elif lines[i].startswith("UDP") > 0:
            UDP = lines[i].split(" ")[2]
            serverCfg.UDP = UDP
        elif lines[i].startswith("TCP") > 0:
            TCP = lines[i].split(" ")[2]
            serverCfg.TCP = TCP


def readAuthFile():
    file = open(authFile, "r")
    lines = file.read().splitlines()
    global clients
    for i in range(len(lines)):
        client = Client(lines[i])
        clients.append(client)


def startServer():
    mainUDPSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mainUDPSocket.bind(('', int(serverCfg.UDP)))

    mainTCPSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mainTCPSocket.bind(('', int(serverCfg.TCP)))

    mainUDPThread = threading.Thread(target=handleUDPConnections, args=(mainUDPSocket,))
    mainTCPThread = threading.Thread(target=handleTCPConnections, args=(mainTCPSocket,))

    mainUDPThread.start()
    mainTCPThread.start()
    handleTerminalInput()


def handleUDPConnections(mainUDPSocket: socket.socket):  # HANDLING UDP CONNECTIONS AND THREAD EVERY NEW CONNECTION.
    while 1:
        (bytesReceived, (ip, port)) = mainUDPSocket.recvfrom(sys.getsizeof(UDP_PDU), socket.MSG_WAITALL)
        clientUDPThread = threading.Thread(target=handleUDPConnection, args=(bytesReceived, ip, port,))
        clientUDPThread.start()


def handleUDPConnection(bytesReceived, ip, port):
    packet = unpackUDP(bytesReceived)


def unpackUDP(bytesReceived: bytes):
    unpackedPacket = struct.unpack('B 11s 11s 61s', bytesReceived)
    packetType = unpackedPacket[0]
    packetId_Trans = unpackedPacket[1].decode().split("\x00")[0]
    packetId_Comm = unpackedPacket[2].decode().split("\x00")[0]
    try:
        packetData = unpackedPacket[3].decode().split("\x00")[0]
    except UnicodeDecodeError:
        packetData = ""
    return UDP_PDU(packetType, packetId_Trans, packetId_Comm, packetData)


def handleTCPConnections(
        mainTCPSocket):  # HANDLING TCP CONNECTIONS AND THREADING EVERY NEW CONNECTIONS AND SAVING IT TO CLIENT CLASS
    pass


def handleTerminalInput():  # USER TERMINAL INPUT
    pass


if __name__ == "__main__":
    checkParams()
    readCfgFile()
    readAuthFile()
    startServer()
