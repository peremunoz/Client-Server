#!/usr/bin/env python3
import struct
import sys
from dataclasses import dataclass
from dataclasses import field
import servermodule
import threading
import socket
import random
import select
import time


#   Colors Class for formatting purposes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


#   Dataclasses
@dataclass
class ServerCfg:
    Id: str
    UDP: int
    TCP: int
    mainTCP: socket.socket
    mainUDP: socket.socket


@dataclass
class Element:
    Id: str
    Value: str = "None"

    def isFrom(self, client):
        for i in range(len(client.Elements)):
            if client.Elements[i].Id == self.Id:
                return True
        return False

    def store(self, client, date, packetType):
        for i in range(len(client.Elements)):
            if client.Elements[i].Id == self.Id:
                client.Elements[i].Value = self.Value
        dataFile = open(client.Id + ".data", "a")
        dataFile.write(date.split(";")[0] + ";" + date.split(";")[1] + ";" + typeToString(
            packetType) + ";" + self.Id + ";" + self.Value + "\n")
        okMsg("Successfully stored element " + self.Id + " value: " + self.Value + " for client " + client.Id)
        dataFile.close()


@dataclass
class Client:
    Id: str
    Status: str = servermodule.DISCONNECTED
    Id_Comm: str = ""
    IP_Address: str = ""
    defaultUDPort: int = 0
    firstALIVE: bool = True
    ALIVEReceived: bool = False
    ALIVEsLost: int = 0
    ALIVETimer: threading.Thread = None
    newUDPort: int = 0
    TCP: int = 0
    Elements: list[Element] = field(default_factory=list)

    def setStatus(self, status):
        self.Status = status
        infoMsg("Client with id " + str(self.Id) + " in status " + statusToString(self.Status))

    def resetALIVE(self):
        self.firstALIVE = True
        self.ALIVEReceived = False
        self.ALIVEsLost = 0


@dataclass
class UDP_PDU:
    Type: str
    Id_Trans: str
    Id_Comm: str
    Data: str

    def send(self, socketToSend, client, port):
        packetPacked = packUDP(self)
        bytesSent = socketToSend.sendto(packetPacked, (client.IP_Address, port))
        while bytesSent != UDPPacketSize:  # 84 = size of UDP_PDU
            bytesSent += socketToSend.sendto(packetPacked[bytesSent:], (client.IP_Address, port))
        debugMsg("Packet " + typeToString(self.Type) + " sent correctly to " + client.Id)

    def incorrectALIVE(self, client):
        if str(self.Id_Trans) != client.Id or self.Id_Comm != str(client.Id_Comm) or self.Data != "":
            return True
        return False


@dataclass
class TCP_PDU:
    Type: str
    Id_Trans: str
    Id_Comm: str
    Element: str
    Value: str
    Info: str

    def send(self, socketToSend: socket.socket, client):
        packetPacked = packTCP(self)
        socketToSend.sendall(packetPacked)
        debugMsg("Packet " + typeToString(self.Type) + " sent correctly to " + client.Id)


#   Constants
UDPPacketSize = 84
TCPPacketSize = 1 + 11 + 11 + 8 + 16 + 80
Z = 2
T = 1
W = 3
X = 3
M = 3
V = 2
S = 3

#   Global variables
serverCfg = ServerCfg
cfgFile = "server.cfg"
authFile = "bbdd_dev.dat"
debug_mode = False
clients = []


#       CHECK PARAMETERS FUNCTIONS

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


def checkCfgFile(filename):
    if filename.find(".cfg") < 0:
        return False
    return True


def checkAuthFile(filename):
    if filename.find(".dat") < 0:
        return False
    return True


#       READING CONFIGURATION FUNCTIONS

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


#       SERVER INITIALIZATION

def startServer():
    mainUDPSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mainUDPSocket.bind(('', int(serverCfg.UDP)))

    mainTCPSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mainTCPSocket.bind(('', int(serverCfg.TCP)))

    mainUDPThread = threading.Thread(target=handleUDPConnections, args=(mainUDPSocket,))
    mainUDPThread.daemon = True
    mainTCPThread = threading.Thread(target=handleTCPConnections, args=(mainTCPSocket,))
    mainTCPThread.daemon = True

    serverCfg.mainUDP = mainUDPSocket
    serverCfg.mainTCP = mainTCPSocket

    mainUDPThread.start()
    mainTCPThread.start()
    handleTerminalInput()


#       UDP FUNCTIONS

def handleUDPConnections(mainUDPSocket: socket.socket):  # HANDLING UDP CONNECTIONS AND THREAD EVERY NEW CONNECTION.
    while 1:
        (bytesReceived, (ip, port)) = mainUDPSocket.recvfrom(UDPPacketSize, socket.MSG_WAITALL)
        debugMsg("New thread created for attending UDP")
        clientUDPThread = threading.Thread(target=switcher, args=(bytesReceived, ip, port, mainUDPSocket,))
        clientUDPThread.start()


def switcher(bytesPacket, ip, port, mainUDPSocket):
    packet = unpackUDP(bytesPacket)

    if not packetFromAuthedUser(packet):
        debugMsg("Received a packet from unknown user")
        sendREG_REJ(mainUDPSocket, ip, port, "Client with id: " + packet.Id_Trans + " not authed in server")
        return

    client = searchClient(packet.Id_Trans)
    client.IP_Address = ip
    client.defaultUDPort = port

    if packet.Type == servermodule.REG_REQ:
        client.resetALIVE()
        handleRegisterRequest(packet, mainUDPSocket, client)
    elif packet.Type == servermodule.ALIVE:
        handlePeriodicCommunication(packet, mainUDPSocket, client)
    else:
        debugMsg("Error packet type received: " + typeToString(
            packet.Type) + " with client " + client.Id + " in status " + statusToString(
            client.Status))
        client.setStatus(servermodule.DISCONNECTED)


def packUDP(packet: UDP_PDU):
    packedPacket = struct.pack("B 11s 11s 61s", packet.Type, str(packet.Id_Trans).encode(),
                               str(packet.Id_Comm).encode(), str(packet.Data).encode())
    return packedPacket


def unpackUDP(bytesReceived: bytes):
    unpackedPacket = struct.unpack('B 11s 11s 61s', bytesReceived)
    packetType = unpackedPacket[0]
    packetId_Trans = unpackedPacket[1].split(b"\x00")[0].decode()
    packetId_Comm = unpackedPacket[2].split(b"\x00")[0].decode()
    packetData = unpackedPacket[3].split(b"\x00")[0].decode()
    return UDP_PDU(packetType, packetId_Trans, packetId_Comm, packetData)


def handleRegisterRequest(REG_REQPacket, mainUDPSocket, client: Client):
    if REG_REQPacket.Id_Comm != "0000000000" or REG_REQPacket.Data != "":
        if REG_REQPacket.Data != "":
            debugMsg("Received a REG_REQ packet [DATA NOT EMPTY]")
            sendREG_REJ(mainUDPSocket, client.IP_Address, client.defaultUDPort,
                        "Wrong information in packet REG_REQ [DATA NOT EMPTY]")
        else:
            debugMsg("Received a REG_REQ packet [WRONG ID COMMUNICATION]")
            sendREG_REJ(mainUDPSocket, client.IP_Address, client.defaultUDPort,
                        "Wrong information in packet REG_REQ [WRONG ID COMMUNICATION]")
        client.setStatus(servermodule.DISCONNECTED)
        return

    debugMsg("Correct REG_REQ packet received from client " + client.Id)

    if client.Status != servermodule.DISCONNECTED:
        sendREG_REJ(mainUDPSocket, client.IP_Address, client.defaultUDPort,
                    "Client with id: " + client.Id + " it's not in status DISCONNECTED")
        client.setStatus(servermodule.DISCONNECTED)
        return

    Id_Comm = random.randint(1000000000, 9999999999)
    client.Id_Comm = Id_Comm

    clientUDPSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientUDPSocket.bind(("", 0))
    newUDPPort = clientUDPSocket.getsockname()[1]
    client.newUDPort = newUDPPort

    sendREG_ACK(mainUDPSocket, client)
    debugMsg("Opened new UDP-Port (" + str(newUDPPort) + ") for client " + client.Id)

    client.setStatus(servermodule.WAIT_INFO)
    inputs, outputs, excepts = select.select([clientUDPSocket], [], [], Z * T)
    if len(inputs) == 0:
        debugMsg("REG_INFO packet not received from client " + client.Id)
        client.setStatus(servermodule.DISCONNECTED)
        clientUDPSocket.close()
        return

    (REG_INFOBytes, (_, _)) = clientUDPSocket.recvfrom(UDPPacketSize, socket.MSG_WAITALL)
    REG_INFOPacket = unpackUDP(REG_INFOBytes)

    if REG_INFOPacket.Type != servermodule.REG_INFO:
        debugMsg("Error packet type received: " + typeToString(
            REG_INFOPacket.Type) + " with client " + client.Id + " in status " + statusToString(
            client.Status))
        client.setStatus(servermodule.DISCONNECTED)
        clientUDPSocket.close()
        return

    if REG_INFOPacket.Id_Trans != str(client.Id) or REG_INFOPacket.Id_Comm != str(Id_Comm) or len(
            REG_INFOPacket.Data) < 7:
        if REG_INFOPacket.Id_Trans != str(client.Id):
            debugMsg("Wrong information in packet REG_INFO from client " + client.Id + "[WRONG ID TRANSMITTER]")
            sendINFO_NACK(clientUDPSocket, client, "Wrong information in packet REG_INFO [WRONG ID TRANSMITTER]")
        elif REG_INFOPacket.Id_Comm != str(Id_Comm):
            debugMsg("Wrong information in packet REG_INFO from client " + client.Id + "[WRONG ID COMMUNICATION]")
            sendINFO_NACK(clientUDPSocket, client, "Wrong information in packet REG_INFO [WRONG ID COMMUNICATION]")
        else:
            debugMsg("Wrong information in packet REG_INFO from client " + client.Id + "[WRONG ELEMENT INFO]")
            sendINFO_NACK(clientUDPSocket, client, "Wrong information in packet REG_INFO [WRONG ELEMENT INFO]")
        client.setStatus(servermodule.DISCONNECTED)
        clientUDPSocket.close()
        return

    debugMsg("Correct REG_INFO packet received from " + client.Id)
    storeREG_INFOData(REG_INFOPacket.Data, client)

    sendINFO_ACK(clientUDPSocket, client)
    client.setStatus(servermodule.REGISTERED)
    clientALIVETimer = threading.Thread(target=ALIVETimer, args=(client,))
    client.ALIVETimer = clientALIVETimer
    clientALIVETimer.start()
    debugMsg("Started new ALIVE timer for client " + client.Id + " with name " + clientALIVETimer.name)
    clientUDPSocket.close()


def sendREG_ACK(socketToSend, client: Client):
    REG_ACKPacket = UDP_PDU(servermodule.REG_ACK, serverCfg.Id, client.Id_Comm, str(client.newUDPort))
    REG_ACKPacket.send(socketToSend, client, client.defaultUDPort)


def sendINFO_ACK(socketToSend, client):
    INFO_ACKPacket = UDP_PDU(servermodule.INFO_ACK, serverCfg.Id, client.Id_Comm, str(serverCfg.TCP))
    INFO_ACKPacket.send(socketToSend, client, client.defaultUDPort)


def sendINFO_NACK(socketToSend, client, reason):
    INFO_NACKPacket = UDP_PDU(servermodule.INFO_NACK, serverCfg.Id, client.Id_Comm, reason)
    INFO_NACKPacket.send(socketToSend, client, client.defaultUDPort)

    #   END OF REGISTER PROCESS


def storeREG_INFOData(data, client: Client):
    client.TCP = data.split(",")[0]
    for i in range(len(data.split(";"))):
        element = Element(data.split(",")[1].split(";")[i], "")
        client.Elements.append(element)


def sendREG_REJ(socketToSend, ip, port, reason):
    REG_REJPacket = UDP_PDU(servermodule.REG_REJ, serverCfg.Id, "0000000000", reason)
    REG_REJPacked = packUDP(REG_REJPacket)
    bytesSent = socketToSend.sendto(REG_REJPacked, (ip, port))
    while bytesSent != UDPPacketSize:
        bytesSent += socketToSend.sendto(REG_REJPacked[bytesSent:], (ip, port))
    debugMsg("Packet REG_REJ sent correctly to " + str(ip) + ":" + str(port))


def handlePeriodicCommunication(ALIVE: UDP_PDU, mainUDPSocket: socket.socket, client: Client):
    if ALIVE.incorrectALIVE(client):
        debugMsg("Incorrect ALIVE packet received from " + client.Id)
        sendALIVE_REJ(mainUDPSocket, client)
        client.setStatus(servermodule.DISCONNECTED)
        return

    if client.firstALIVE and client.Status == servermodule.REGISTERED:
        debugMsg("Correct first ALIVE packet received from client " + client.Id)
        client.setStatus(servermodule.SEND_ALIVE)
        client.firstALIVE = False
    elif not client.firstALIVE and client.Status == servermodule.SEND_ALIVE:
        debugMsg("Correct ALIVE packet received from client " + client.Id)
    else:
        debugMsg("Error packet type received: " + typeToString(
            ALIVE.Type) + " with client " + client.Id + " in status " + statusToString(
            client.Status))
        return

    client.ALIVEReceived = True
    sendALIVE(mainUDPSocket, client)


def ALIVETimer(client: Client):
    if client.firstALIVE:
        time.sleep(W)
        if not client.ALIVEReceived and client.Status == servermodule.REGISTERED:
            debugMsg("First ALIVE packet not received from client " + client.Id)
            client.setStatus(servermodule.DISCONNECTED)
            return

    while client.ALIVEsLost < S and client.Status == servermodule.SEND_ALIVE:
        if client.ALIVETimer.name != threading.current_thread().name:
            debugMsg("Thread ALIVE timer with name " + threading.current_thread().name + " exited")
            return
        time.sleep(V)
        if client.ALIVEReceived:
            client.ALIVEReceived = False
            client.ALIVEsLost = 0
        elif not client.ALIVEReceived:
            client.ALIVEsLost += 1
            debugMsg("Total lost ALIVEs: " + str(client.ALIVEsLost))
    if client.ALIVEsLost == 3:
        client.setStatus(servermodule.DISCONNECTED)


def sendALIVE(socketToSend, client: Client):
    ALIVEPacket = UDP_PDU(servermodule.ALIVE, serverCfg.Id, client.Id_Comm, client.Id)
    ALIVEPacket.send(socketToSend, client, client.defaultUDPort)


def sendALIVE_REJ(socketToSend, client: Client):
    ALIVE_REJPacket = UDP_PDU(servermodule.ALIVE_REJ, serverCfg.Id, client.Id_Comm, "Incorrect ALIVE received")
    ALIVE_REJPacket.send(socketToSend, client, client.defaultUDPort)


#       TCP FUNCTIONS

def handleTCPConnections(mainTCPSocket: socket.socket):
    while 1:
        mainTCPSocket.listen(1)
        (clientTCPSocket, (ip, port)) = mainTCPSocket.accept()
        debugMsg("New thread created for attending TCP in port" + str(port))
        clientTCPThread = threading.Thread(target=handleTCPConnection, args=(clientTCPSocket, ip, port,))
        clientTCPThread.start()


def handleTCPConnection(clientSocket: socket.socket, ip, port):
    inputs, outputs, excepts = select.select([clientSocket], [], [], M)
    if len(inputs) == 0:
        debugMsg("Packet not received from " + str(ip) + ":" + str(port) + " via TCP")
        clientSocket.close()
        return

    bytesReceived = clientSocket.recv(TCPPacketSize, socket.MSG_WAITALL)

    packetReceived = unpackTCP(bytesReceived)

    if packetReceived.Type != servermodule.SEND_DATA:
        debugMsg("Packet of type " + packetReceived.Type + " received from TCP connection!")
        clientSocket.close()
        return

    if not packetFromAuthedUser(packetReceived):
        debugMsg("Received a packet from unknown user via TCP")
        DATA_REJ = TCP_PDU(servermodule.DATA_REJ, serverCfg.Id, "0000000000", "", "", "Wrong client Id")
        sendDATA_REJ(DATA_REJ, clientSocket, ip, port)
        clientSocket.close()
        return

    client = searchClient(packetReceived.Id_Trans)

    if packetReceived.Id_Comm != str(client.Id_Comm):
        debugMsg("Received an incorrect SEND_DATA packet [WRONG COMMUNICATION ID]")
        DATA_REJ = TCP_PDU(servermodule.DATA_REJ, serverCfg.Id, "0000000000", packetReceived.Element,
                           packetReceived.Value, "[WRONG COMMUNICATION ID]")
        DATA_REJ.send(clientSocket, client)
        client.setStatus(servermodule.DISCONNECTED)
        clientSocket.close()
        return

    if client.Status != servermodule.SEND_ALIVE:
        debugMsg("Received SEND_DATA packet in status " + statusToString(client.Status))
        clientSocket.close()
        return

    element = Element(packetReceived.Element, packetReceived.Value)

    if not element.isFrom(client):
        debugMsg("Received SEND_DATA packet with an element that doesn't match any of the stored")
        DATA_NACK = TCP_PDU(servermodule.DATA_NACK, serverCfg.Id, client.Id_Comm, packetReceived.Element,
                            packetReceived.Value, "Element" + packetReceived.Element + "is not from client")
        DATA_NACK.send(clientSocket, client)
        clientSocket.close()
        return

    debugMsg("Correct SEND_DATA packet received from client " + client.Id)
    element.store(client, packetReceived.Info, packetReceived.Type)

    DATA_ACK = TCP_PDU(servermodule.DATA_ACK, serverCfg.Id, client.Id_Comm, packetReceived.Element,
                       packetReceived.Value, client.Id)
    DATA_ACK.send(clientSocket, client)

    clientSocket.close()
    debugMsg("Ended thread for attending TCP requests from port " + str(port))


def unpackTCP(bytesReceived: bytes):
    unpackedPacket = struct.unpack('B 11s 11s 8s 16s 80s', bytesReceived)
    packetType = unpackedPacket[0]
    packetId_Trans = unpackedPacket[1].split(b"\x00")[0].decode()
    packetId_Comm = unpackedPacket[2].split(b"\x00")[0].decode()
    packetElement = unpackedPacket[3].split(b"\x00")[0].decode()
    packetElementValue = unpackedPacket[4].split(b"\x00")[0].decode()
    packetInfo = unpackedPacket[5].split(b"\x00")[0].decode()
    return TCP_PDU(packetType, packetId_Trans, packetId_Comm, packetElement, packetElementValue, packetInfo)


def packTCP(packet: TCP_PDU):
    packedPacket = struct.pack('B 11s 11s 8s 16s 80s', packet.Type, str(packet.Id_Trans).encode(),
                               str(packet.Id_Comm).encode(), str(packet.Element).encode(),
                               str(packet.Value).encode(), str(packet.Info).encode())
    return packedPacket


def sendDATA_REJ(DATA_REJPacket, socketToSend, ip, port):
    DATA_REJPacked = packTCP(DATA_REJPacket)
    socketToSend.sendall(DATA_REJPacked)
    debugMsg("Packet DATA_REJ sent correctly to " + str(ip) + ":" + str(port))


#       CONSOLE HANDLING FUNCTIONS

def handleTerminalInput():  # USER TERMINAL INPUT
    while 1:
        command = input(Colors.CYAN + "➪\t")
        line = command.split(" ")
        if len(line[0]) < 1:
            continue
        elif line[0] == "list":
            listCommand()
        elif line[0] == "set":
            setCommand(line[1:])
        elif line[0] == "get":
            getCommand(line[1:])
        elif line[0] == "quit":
            quitCommand()
        else:
            errorMsg("The command entered is incorrect!")
            printAvailableCommands()


def quitCommand():
    exit(0)


def setCommand(line):
    if len(line) < 3:
        errorMsg("Error usage of set command!!\n  set <client_id> <element_id> <value>")
        return

    clientId = line[0]
    elementId = line[1]
    elementValue = line[2]

    client = searchClient(clientId)
    element = Element(elementId, elementValue)

    if client is None:
        errorMsg("Client id not exists!")
        return

    if element.isFrom(client) is False:
        errorMsg(element.Id + " is not from " + client.Id)
        return

    if len(elementValue) < 1 or len(elementValue) > 15:
        errorMsg("Element value can't be None or greater than 15 numbers")
        return

    if elementId.split("-")[2] == "O":
        errorMsg("You can't modify a sensor element!!")
        return

    if client.Status != servermodule.SEND_ALIVE:
        errorMsg("Client " + client.Id + "isn't in status SEND_ALIVE. Can't do the operation!")
        return

    #   Correct set command entered

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.bind(('', 0))

    try:
        clientSocket.connect((client.IP_Address, int(client.TCP)))
    except socket.error:
        errorMsg("Can't connect with client for sending SET_DATA packet!")
        client.setStatus(servermodule.DISCONNECTED)
        clientSocket.close()
        return

    debugMsg("TCP connection established with " + client.Id)

    SET_DATA = TCP_PDU(servermodule.SET_DATA, serverCfg.Id, client.Id_Comm, element.Id, element.Value, client.Id)
    SET_DATA.send(clientSocket, client)

    inputs, outputs, excepts = select.select([clientSocket], [], [], M)
    if len(inputs) == 0:
        print(Colors.WARNING + "Client " + client.Id + "didn't answer to SET_DATA packet... resending information...")
        clientSocket.close()
        return

    packetInBytes = clientSocket.recv(TCPPacketSize, socket.MSG_WAITALL)

    packet = unpackTCP(packetInBytes)
    if packet.Id_Trans != client.Id or packet.Id_Comm != str(client.Id_Comm) or packet.Element != element.Id:
        debugMsg("Received an incorrect " + typeToString(packet.Type) + " from client " + client.Id)
        client.setStatus(servermodule.DISCONNECTED)
        clientSocket.close()
        return

    if packet.Type == servermodule.DATA_NACK:
        print(Colors.WARNING + "Received a DATA_NACK packet from " + client.Id + ". Resending information...")
        clientSocket.close()
        return

    if packet.Type == servermodule.DATA_REJ:
        debugMsg("Received a DATA_REJ packet from " + client.Id)
        errorMsg("Element value rejected from client " + client.Id)
        client.setStatus(servermodule.DISCONNECTED)
        clientSocket.close()
        return

    if packet.Type == servermodule.DATA_ACK:
        debugMsg("Received a DATA_ACK packet from " + client.Id)
        element.store(client, packet.Info, SET_DATA.Type)

    clientSocket.close()


def getCommand(line):
    if len(line) < 2:
        errorMsg("Error usage of get command!!\n  get <client_id> <element_id>")
        return

    clientId = line[0]
    elementId = line[1]

    client = searchClient(clientId)
    element = Element(elementId)

    if client is None:
        errorMsg("Client id not exists!")
        return

    if element.isFrom(client) is False:
        errorMsg(element.Id + " is not from " + client.Id)
        return

    if client.Status != servermodule.SEND_ALIVE:
        errorMsg("Client " + client.Id + "isn't in status SEND_ALIVE. Can't do the operation!")
        return

    #   Correct get command entered

    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSocket.bind(('', 0))

    try:
        clientSocket.connect((client.IP_Address, int(client.TCP)))
    except socket.error:
        errorMsg("Can't connect with client for sending GET_DATA packet!")
        client.setStatus(servermodule.DISCONNECTED)
        clientSocket.close()
        return

    debugMsg("TCP connection established with " + client.Id)

    GET_DATA = TCP_PDU(servermodule.GET_DATA, serverCfg.Id, client.Id_Comm, element.Id, "", client.Id)
    GET_DATA.send(clientSocket, client)

    inputs, outputs, excepts = select.select([clientSocket], [], [], M)
    if len(inputs) == 0:
        print(Colors.WARNING + "Client " + client.Id + "didn't answer to GET_DATA packet... resending information...")
        clientSocket.close()
        return

    packetInBytes = clientSocket.recv(TCPPacketSize, socket.MSG_WAITALL)

    packet = unpackTCP(packetInBytes)

    if packet.Id_Trans != client.Id or packet.Id_Comm != str(client.Id_Comm) or packet.Element != element.Id:
        debugMsg("Received an incorrect " + typeToString(packet.Type) + " from client " + client.Id)
        client.setStatus(servermodule.DISCONNECTED)
        clientSocket.close()
        return

    if packet.Type == servermodule.DATA_NACK:
        print(Colors.WARNING + "Received a DATA_NACK packet from " + client.Id + ". Resending information...")
        clientSocket.close()
        return

    if packet.Type == servermodule.DATA_REJ:
        debugMsg("Received a DATA_REJ packet from " + client.Id)
        errorMsg("Element value rejected from client " + client.Id)
        client.setStatus(servermodule.DISCONNECTED)
        clientSocket.close()
        return

    if packet.Type == servermodule.DATA_ACK:
        debugMsg("Received a DATA_ACK packet from " + client.Id)
        element.store(client, packet.Info, GET_DATA.Type)

    clientSocket.close()


def printAvailableCommands():
    print(Colors.UNDERLINE + "\tCOMMANDS AVAILABLE:" + Colors.END)
    print(Colors.CYAN + "\t➵ set <client_id> <element_id> <value>")
    print("\t\tSets a value to a client element")
    print("\t➵ get <client_id> <element_id>")
    print("\t\tGets the value from a client element")
    print("\t➵ list")
    print("\t\tLists all the clients with its stats, comm. id, ip addresses and elements")
    print("\t➵ quit")
    print("\t\tExits the server closing all the buffers, sockets, etc.")


def listCommand():
    print(Colors.WARNING + "╔═══════════╦════════════╦══════════════╦═══════════════╦═════════════════════")
    print("║ CLIENT ID ║   STATUS   ║ COMM. ID\t║ IP ADDRESS\t║      ELEMENTS")
    print("╠═══════════╬════════════╬══════════════╬═══════════════╬═════════════════════")
    print("╚═══════════╩════════════╩══════════════╩═══════════════╩═════════════════════")
    for i in range(len(clients)):
        actualClient = clients[i]
        print(" " + actualClient.Id + "  " + statusToString(actualClient.Status) + "\t   " + str(
            actualClient.Id_Comm) + "\t   " + str(actualClient.IP_Address) + "\t   ", end="")
        for k in range(len(actualClient.Elements)):
            print(actualClient.Elements[k].Id, end=" ")
        print("")


#       AUXILIARY FUNCTIONS

def statusToString(status):
    if status == servermodule.DISCONNECTED:
        return "DISCONNECTED"
    elif status == servermodule.WAIT_INFO:
        return "WAIT_INFO"
    elif status == servermodule.REGISTERED:
        return "REGISTERED"
    elif status == servermodule.NOT_REGISTERED:
        return "NOT_REGISTERED"
    elif status == servermodule.WAIT_ACK_REG:
        return "WAIT_ACK_REG"
    elif status == servermodule.WAIT_ACK_INFO:
        return "WAIT_ACK_INFO"
    elif status == servermodule.SEND_ALIVE:
        return "SEND_ALIVE"
    else:
        return "Unknown status"


def typeToString(packetType):
    if packetType == servermodule.REG_REQ:
        return "REG_REQ"
    elif packetType == servermodule.REG_ACK:
        return "REG_ACK"
    elif packetType == servermodule.REG_NACK:
        return "REG_NACK"
    elif packetType == servermodule.REG_REJ:
        return "REG_REJ"
    elif packetType == servermodule.REG_INFO:
        return "REG_INFO"
    elif packetType == servermodule.INFO_ACK:
        return "INFO_ACK"
    elif packetType == servermodule.INFO_NACK:
        return "INFO_NACK"
    elif packetType == servermodule.INFO_REJ:
        return "INFO_REJ"
    elif packetType == servermodule.ALIVE:
        return "ALIVE"
    elif packetType == servermodule.ALIVE_NACK:
        return "ALIVE_NACK"
    elif packetType == servermodule.ALIVE_REJ:
        return "ALIVE_REJ"
    elif packetType == servermodule.SEND_DATA:
        return "SEND_DATA"
    elif packetType == servermodule.DATA_ACK:
        return "DATA_ACK"
    elif packetType == servermodule.DATA_NACK:
        return "DATA_NACK"
    elif packetType == servermodule.DATA_REJ:
        return "DATA_REJ"
    elif packetType == servermodule.SET_DATA:
        return "SET_DATA"
    elif packetType == servermodule.GET_DATA:
        return "GET_DATA"
    else:
        return "Unknown packet type"


def searchClient(clientId):
    for i in range(len(clients)):
        if clients[i].Id == clientId:
            return clients[i]
    return None


def packetFromAuthedUser(packet):
    userToSearch = packet.Id_Trans
    for i in range(len(clients)):
        if clients[i].Id == userToSearch:
            return True
    return False


#       FORMATTING FUNCTIONS

def errorMsg(text):
    print(Colors.FAIL + "[ERROR] =>\t" + text + Colors.END)


def okMsg(text):
    print(Colors.GREEN + "[OK] =>\t" + text + Colors.END)


def infoMsg(text):
    print("[INFO] =>\t" + Colors.UNDERLINE + Colors.HEADER + text + Colors.END)


def debugMsg(text):
    if debug_mode:
        print(Colors.BLUE + "[DEBUG] =>\t" + text + Colors.END)


#       MAIN FUNCTION

if __name__ == "__main__":
    try:
        checkParams()
        readCfgFile()
        readAuthFile()
        startServer()
    except KeyboardInterrupt:
        serverCfg.mainTCP.close()
        serverCfg.mainUDP.close()
        print(Colors.WARNING + "\n[WARNING] =>\tSERVER EXITED ABRUPTLY")
        exit(0)
