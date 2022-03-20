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


#   COLORS CLASS
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


#   DATACLASSES
@dataclass
class ServerCfg:
    Id: str
    UDP: int
    TCP: int


@dataclass
class Element:
    Id: str
    Data: int = 0


@dataclass
class Client:
    Id: str
    Status: str = servermodule.DISCONNECTED
    Id_Comm: str = 0
    IP_Address: str = 0
    defaultUDPort: int = 0
    firstALIVE: bool = True
    ALIVEReceived: bool = False
    ALIVEsLost: int = 0
    newUDPort: int = 0
    TCP: int = 0
    Elements: list[Element] = field(default_factory=list)

    def setStatus(self, status):
        self.Status = status
        infoMsg("Client with id " + str(self.Id) + " in status " + statusToString(self.Status))


@dataclass
class UDP_PDU:
    Type: str
    Id_Trans: str
    Id_Comm: str
    Data: str


#   CONSTANTS
UDPPacketSize = 84
Z = 2
T = 1  # Time between register packet
W = 3
X = 3

#   GLOBAL VARIABLES
serverCfg = ServerCfg
cfgFile = "server.cfg"
authFile = "bbdd_dev.dat"
debug_mode = False
clients = []


def errorMsg(text):
    print(Colors.FAIL + "[ERROR] =>\t" + text + Colors.ENDC)


def infoMsg(text):
    print("[INFO] =>\t" + Colors.UNDERLINE + Colors.HEADER + text + Colors.ENDC)


def debugMsg(text):
    print(Colors.WARNING + "[DEBUG] =>\t" + text + Colors.ENDC)


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
    else:
        return "Unknown packet type"


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
        (bytesReceived, (ip, port)) = mainUDPSocket.recvfrom(UDPPacketSize, socket.MSG_WAITALL)
        debugMsg("New thread created for attending UDP")
        clientUDPThread = threading.Thread(target=switcher, args=(bytesReceived, ip, port, mainUDPSocket,))
        clientUDPThread.start()


def switcher(bytesPacket, ip, port, mainUDPSocket):
    packet = unpackUDP(bytesPacket)

    if not packetFromAuthedUser(packet):
        sendREG_REJ(mainUDPSocket, ip, port, "Client with id: " + packet.Id_Trans + " not authed in server")
        exit(0)

    client = searchClient(packet.Id_Trans)
    client.IP_Address = ip
    client.defaultUDPort = port

    if packet.Type == servermodule.REG_REQ:
        handleRegisterRequest(packet, mainUDPSocket, client)
    elif packet.Type == servermodule.ALIVE:
        handlePeriodicCommunication(packet, mainUDPSocket, client)
    else:
        debugMsg("Error packet type received: " + typeToString(
            packet.Type) + " with client " + client.Id + " in status " + statusToString(
            client.Status))
        client.setStatus(servermodule.DISCONNECTED)
        exit(0)


def handlePeriodicCommunication(ALIVE: UDP_PDU, mainUDPSocket: socket.socket, client: Client):
    if incorrectALIVE(ALIVE, client):
        print(ALIVE)
        debugMsg("Incorrect ALIVE packet received from " + client.Id)
        sendALIVE_REJ(mainUDPSocket, client)
        client.setStatus(servermodule.DISCONNECTED)
        exit(0)

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
        exit(0)

    client.ALIVEReceived = True
    sendALIVE(mainUDPSocket, client)
    debugMsg("ALIVE response sent to client " + client.Id)


def startALIVETimer(client: Client):
    while client.ALIVEsLost < 4:
        time.sleep(W)
        if client.ALIVEReceived:
            client.ALIVEReceived = False
            client.ALIVEsLost = 0
        elif not client.ALIVEReceived:
            client.ALIVEsLost += 1

    client.setStatus(servermodule.DISCONNECTED)


def handleRegisterRequest(REG_REQPacket, mainUDPSocket, client: Client):
    if REG_REQPacket.Type != servermodule.REG_REQ:
        debugMsg("Error packet type received: " + typeToString(
            REG_REQPacket.Type) + " with client in status " + statusToString(client.Status))
        client.setStatus(servermodule.DISCONNECTED)
        exit(0)

    if REG_REQPacket.Id_Comm != "0000000000" or REG_REQPacket.Data != "":
        debugMsg("Received a REG_REQ packet with wrong information")
        sendREG_REJ(mainUDPSocket, client, "Wrong information in packet REG_REQ")
        client.setStatus(servermodule.DISCONNECTED)
        exit(0)

    debugMsg("Correct REG_REQ packet received from client " + client.Id)

    if client.Status != servermodule.DISCONNECTED:
        sendREG_REJ(mainUDPSocket, client,
                    "Client with id: " + client.Id + " it's not in status DISCONNECTED")
        client.setStatus(servermodule.DISCONNECTED)
        exit(0)

    Id_Comm = random.randint(1000000000, 9999999999)
    client.Id_Comm = Id_Comm
    clientUDPSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientUDPSocket.bind(("", 0))
    newUDPPort = clientUDPSocket.getsockname()[1]
    client.newUDPort = newUDPPort
    sendREG_ACK(mainUDPSocket, client, newUDPPort)
    debugMsg("Opened new UDP-Port (" + str(newUDPPort) + ") for client " + client.Id)

    client.setStatus(servermodule.WAIT_INFO)
    inputs, outputs, excepts = select.select([clientUDPSocket], [], [], Z * T)
    if len(inputs) == 0:
        debugMsg("REG_INFO packet not received from client " + client.Id)
        client.setStatus(servermodule.DISCONNECTED)
        exit(0)

    (REG_INFObytes, (ip, port)) = clientUDPSocket.recvfrom(UDPPacketSize, socket.MSG_WAITALL)
    REG_INFOPacket = unpackUDP(REG_INFObytes)

    if REG_INFOPacket.Type != servermodule.REG_INFO:
        debugMsg("Error packet type received: " + typeToString(
            REG_INFOPacket.Type) + " with client " + client.Id + " in status " + statusToString(
            client.Status))
        client.setStatus(servermodule.DISCONNECTED)
        exit(0)

    if REG_INFOPacket.Id_Trans != str(client.Id) or REG_INFOPacket.Id_Comm != str(Id_Comm):
        debugMsg("Wrong information in packet REG_INFO from client " + client.Id)
        sendINFO_NACK(clientUDPSocket, ip, port, client, "Wrong information in packet REG_INFO")
        client.setStatus(servermodule.DISCONNECTED)
        exit(0)

    debugMsg("REG_INFO packet received correctly from " + client.Id)
    storeREG_INFOData(REG_INFOPacket.Data, client)

    sendINFO_ACK(clientUDPSocket, ip, port, client)
    debugMsg("INFO_ACK packet sent to " + client.Id)
    client.setStatus(servermodule.REGISTERED)
    ALIVEThread = threading.Thread(target=startALIVETimer, args=(client,))
    ALIVEThread.start()
    clientUDPSocket.close()
    exit(0)
    #   END OF REGISTER PROCESS


def sendALIVE(socketToSend, client: Client):
    ALIVEPacket = UDP_PDU(servermodule.ALIVE, serverCfg.Id, client.Id_Comm, client.Id)
    ALIVEPacked = packUDP(ALIVEPacket)
    bytesSent = socketToSend.sendto(ALIVEPacked, (client.IP_Address, client.defaultUDPort))
    while bytesSent != UDPPacketSize:  # 84 = size of UDP_PDU
        bytesSent += socketToSend.sendto(ALIVEPacked[bytesSent:], (client.IP_Address, client.defaultUDPort))


def incorrectALIVE(ALIVEPacket, client):
    if str(ALIVEPacket.Id_Trans) != client.Id or ALIVEPacket.Id_Comm != str(client.Id_Comm) or ALIVEPacket.Data != "":
        return True
    return False


def sendALIVE_REJ(socketToSend, client: Client):
    ALIVE_REJPacket = UDP_PDU(servermodule.ALIVE_REJ, serverCfg.Id, client.Id_Comm, "Incorrect ALIVE received")
    ALIVE_REJPacked = packUDP(ALIVE_REJPacket)
    bytesSent = socketToSend.sendto(ALIVE_REJPacked, (str(client.IP_Address), client.defaultUDPort))
    while bytesSent != UDPPacketSize:  # 84 = size of UDP_PDU
        bytesSent += socketToSend.sendto(ALIVE_REJPacked[bytesSent:], (str(client.IP_Address), client.defaultUDPort))


def storeREG_INFOData(data, client: Client):
    client.TCP = data.split(",")[0]
    for i in range(len(data.split(";"))):
        element = Element(data.split(",")[1].split(";")[i])
        client.Elements.append(element)


def sendINFO_ACK(socketToSend, client):
    INFO_ACKPacket = UDP_PDU(servermodule.INFO_ACK, serverCfg.Id, client.Id_Comm, str(serverCfg.TCP))
    INFO_ACKPacked = packUDP(INFO_ACKPacket)
    bytesSent = socketToSend.sendto(INFO_ACKPacked, (client.IP_Address, client.defaultUDPort))
    while bytesSent != UDPPacketSize:  # 84 = size of UDP_PDU
        bytesSent += socketToSend.sendto(INFO_ACKPacked[bytesSent:], (ip, port))


def sendINFO_NACK(socketToSend, ip, port, client, reason):
    INFO_NACKPacket = UDP_PDU(servermodule.INFO_NACK, serverCfg.Id, client.Id_Comm, reason)
    INFO_NACKPacked = packUDP(INFO_NACKPacket)
    bytesSent = socketToSend.sendto(INFO_NACKPacked, (ip, port))
    while bytesSent != UDPPacketSize:  # 84 = size of UDP_PDU
        bytesSent += socketToSend.sendto(INFO_NACKPacked[bytesSent:], (ip, port))


def sendREG_ACK(socketToSend, ip, port, client, UDPPort):
    REG_ACKPacket = UDP_PDU(servermodule.REG_ACK, serverCfg.Id, client.Id_Comm, UDPPort)
    REG_ACKPacked = packUDP(REG_ACKPacket)
    bytesSent = socketToSend.sendto(REG_ACKPacked, (ip, port))
    while bytesSent != UDPPacketSize:  # 84 = size of UDP_PDU
        bytesSent += socketToSend.sendto(REG_ACKPacked[bytesSent:], (ip, port))


def searchClient(clientId):
    for i in range(sys.getsizeof(clients)):
        if clients[i].Id == clientId:
            return clients[i]


def packetFromAuthedUser(packet: UDP_PDU):
    userToSearch = packet.Id_Trans
    for i in range(sys.getsizeof(clients)):
        if clients[i].Id == userToSearch:
            return True
    return False


def sendREG_REJ(socketToSend, ip, port, reason):
    REG_REJPacket = UDP_PDU(servermodule.REG_REJ, serverCfg.Id, "0000000000", reason)
    REG_REJPacked = packUDP(REG_REJPacket)
    bytesSent = socketToSend.sendto(REG_REJPacked, (ip, port))
    while bytesSent != UDPPacketSize:
        bytesSent += socketToSend.sendto(REG_REJPacked[bytesSent:], (ip, port))


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
