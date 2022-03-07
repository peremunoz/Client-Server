#define _POSIX_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/select.h>
#include <signal.h>
#include <pthread.h>


//  Register-phase packet types definitions
#define REG_REQ 0xa0
#define REG_ACK 0xa1
#define REG_NACK 0xa2
#define REG_REJ 0xa3
#define REG_INFO 0xa4
#define INFO_ACK 0xa5
#define INFO_NACK 0xa6
#define INFO_REJ 0xa7

//  Register-phase stats definitions
#define DISCONNECTED 0xf0
#define NOT_REGISTERED 0xf1
#define WAIT_ACK_REG 0xf2
#define WAIT_INFO 0xf3
#define WAIT_ACK_INFO 0xf4
#define REGISTERED 0xf5
#define SEND_ALIVE 0xf6

//  Periodic-communication packet types definitions
#define ALIVE 0xb0
#define ALIVE_NACK 0xb1
#define ALIVE_REJ 0xb2

//  Send to server packet types definitions
#define SEND_DATA 0xc0
#define DATA_ACK 0xc1
#define DATA_NACK 0xc2
#define DATA_REJ 0xc3
#define SET_DATA 0xc4
#define GET_DATA 0xc5

//  Some colors definitions for formatting purposes
#define debugColorBold "\033[1;34m"
#define debugColor "\033[0;34m"
#define errorColor "\033[0;31m"
#define errorColorBold "\033[1;31m"
#define resetColor "\033[0m"
#define whiteBold "\033[1;37m"
#define white "\033[0;37m"
#define yellow "\033[0;33m"
#define yellowBold "\033[0;33m"
#define green "\033[0;32m"
#define greenBold "\033[1;32m"

//  Constants
#define MAXIMUM_LINE_LENGTH 255
#define P 2
#define Q 4
#define N 6
#define U 3
#define O 4
#define T 2
#define V 3
#define R 2
#define S 3
#define M 3

//  Structs pre-definitions
typedef struct ElementStruct Element;
typedef struct Client_Data Client;
typedef struct Server_Data Server;
typedef struct UDP_PDU UDP;
typedef struct TCP_PDU TCP;

//  Function declarations
void checkParams(int argc, char* argv[]);
bool correctFileName(char filename[]);
void debugMsg();
void errorMsg();
void readCfg();
void storeElements(char* line);
void storeServer(char* line);
char* trimLine(char *buffer);
void storeId(char* line);
void storeLocal(char* line);
void storeUDP(char* line);
void openUDPSocket();
void login();
void infoFormat();
void infoMsg(char text[]);
void receiveRegisterPacket();
UDP buildREG_REQPacket();
void signal_handler(int signal);
void processREG_ACK(UDP packetReceived);
UDP buildREG_INFOPacket();
void processPacketType(UDP packet);
void processREG_NACK(UDP packet);
void processREG_REJ(UDP packet);
void processINFO_ACK(UDP packet);
void processINFO_NACK(UDP packet);
bool correctServerData(UDP packet);
char* getTypeOfPacket(UDP packet);
void setupServAddr();
void periodicCommunication();
UDP buildALIVEPacket();
UDP receiveALIVEPacket();
void createThreads();
int searchElement(char* elemId);
_Noreturn void handleTerminalInput();
void openTCP1Socket();
void printCommands();
void statCommand();
void setCommand(char* token);
void sendCommand(char* token);
void quitCommand();
TCP buildSEND_DATAPacket(char elementId[8]);
void setupServAddrTCP();
char* getElementValue(char* elementId);
char* getNowTime();
bool correctServerDataTCP(TCP packet);
void receiveDATAPacket(char elementId[8]);
bool correctElementData(TCP packet, char elementId[8]);
void ALIVELoop();
void handleTCPConnections();

//  Global variables
bool debug_mode = false;
char clientCfgFile[] = "client.cfg";
Client clientData;
Server serverData;
int udpSock = -1;
int tcpSock1 = -1;  //  TCP socket for accepting server requests
int tcpSock2 = -1;  //  TCP socket for sending data to server
int elementsNumber;
struct sockaddr_in clientAddrUDP, clientAddrTCP1, clientAddrTCP2, serverAddrUDP, serverAddrTCP;
bool resetCommunication = false;
pthread_t terminalThread = (pthread_t) NULL;
pthread_t tcpThread = (pthread_t) NULL;

//  Client data struct
struct Client_Data {
    char Id[10];
    Element* Elements[7];
    int Local_TCP;
    unsigned char Status;
};

//  Server data struct
struct Server_Data {
    char Id_Trans[11];
    char Id_Comm[11];
    char Server[MAXIMUM_LINE_LENGTH];
    int Server_UDP;
    int Server_TCP;
    int newServer_UDP;
};

//  Element struct
struct ElementStruct {
    char Id[8];
    char Data[16];  // Every char is 1 byte --> 15 chars/bytes maximum + \0
};

// UDP PDU Struct
struct UDP_PDU {
    unsigned char Type;
    char Id_Tans[11];
    char Id_Comm[11];
    char Data[61];
};

//  TCP PDU Struct
struct TCP_PDU {
    unsigned char Type;
    char Id_Trans[11];
    char Id_Comm[11];
    char Element[8];
    char Value[16];
    char Info[80];
};

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    checkParams(argc, argv);
    readCfg();
    login();
    return 0;
}

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        infoMsg("CLOSING CLIENT...");
        close(udpSock);
        close(tcpSock1);
        pthread_cancel(terminalThread);
        sleep(1);
        exit(0);
    }
}

//  Checks if there are program arguments. If so, they are treated
void checkParams(int argc, char* argv[]) {
    for (int i=1; i < argc; i++) {  // We start with i=1 because first arg is the program name
        if (strcmp(argv[i], "-c") == 0) {
            if (correctFileName(argv[i+1])) {
                strcpy(clientCfgFile, argv[i+1]);
            } else {
                errorMsg();
                printf("Error in the filename, incorrect format. (filename.cfg)");
                exit(-1);
            }
        } else if (strcmp(argv[i], "-d") == 0) {
            debug_mode = true;
        }
    }
    if (debug_mode) {
        debugMsg();
        printf("End of checkParams() function. Client cfg file set to: %s\n" resetColor, clientCfgFile);
    }
}

//  Checks if the filename is in the correct format
bool correctFileName(char filename[]) {
    char* extension = strchr(filename, '.');    // Search for a '.' in the filename
    if (extension == NULL) return false;    // If there's not, wrong format
    if (strcmp(extension, ".cfg") != 0) return false;   // If the extension it isn't '.cfg', bad format
    return true;
}

void debugMsg() {
    printf(debugColorBold "[DEBUG]\t=>\t" debugColor);
}

void errorMsg() {
    printf(errorColorBold "[ERROR]\t=>\t" errorColor);
}

//  Reads the clientData config file and assign its values to the attributes of the clientData or serverData structs
void readCfg() {
    FILE* fd = fopen(clientCfgFile, "r");
    if (fd == NULL) {
        errorMsg();
        perror("Error opening the client cfg file");
        exit(-1);
    }
    char line[MAXIMUM_LINE_LENGTH];
    while (fgets(line, sizeof(line), fd)) {
        switch (line[0]) {
            case 'I':
                storeId(line);
                break;
            case 'E':
                storeElements(line);
                break;
            case 'L':
                storeLocal(line);
                break;
            default:
                if (line[6] == '-') {
                    storeUDP(line);
                } else {
                    storeServer(line);
                }
                break;
        }
    }
}

//  Stores the client ID in the clientData struct
void storeId(char* line) {
    char* id = trimLine(line);
    strcpy(clientData.Id, id);
    if (debug_mode) {
        debugMsg();
        printf("Client Id copied successfully: %s\n" resetColor, clientData.Id);
    }
}

//  Stores all the elements in the clientData struct
void storeElements(char* line) {
    char* elements = trimLine(line);
    char* token = strtok(elements, ";");
    int index = 0;
    while (token != NULL) {
        Element *element = malloc(sizeof(Element));
        strcpy(element->Id, token);
        token = strtok(NULL, ";");
        clientData.Elements[index] = element;
        if (debug_mode) {
            debugMsg();
            printf("Element n.%i copied successfully: %s\n" resetColor, index, clientData.Elements[index]->Id);
        }
        index += 1;
    }
    elementsNumber = index;
}

//  Stores the TCP port in the clientData struct
void storeLocal(char* line) {
    char* local = trimLine(line);
    clientData.Local_TCP = (strtol(local, NULL, 10));
    if (debug_mode) {
        debugMsg();
        printf("Local-TCP copied successfully: %d\n" resetColor, clientData.Local_TCP);
    }
}

//  Stores the server in the serverData struct
void storeServer(char* line) {
    char* server = trimLine(line);
    strcpy(serverData.Server, server);
    if (debug_mode) {
        debugMsg();
        printf("Server copied successfully: %s\n" resetColor, serverData.Server);
    }
}

//  Stores the UDP port in the serverData struct
void storeUDP(char* line) {
    char* udp = trimLine(line);
    serverData.Server_UDP = (strtol(udp, NULL, 10));
    if (debug_mode) {
        debugMsg();
        printf("Server-UDP copied successfully: %d\n" resetColor, serverData.Server_UDP);
    }
}

//  Auxiliary function for triming a text line
char* trimLine(char *buffer) {
    char* line = strchr(buffer, '='); // Delete chars from the start to the '='
    line++;   // Delete the '=' char
    if (line[0] == ' ') line++; // If there's a whitespace next to the '=', delete it too
    unsigned long lineSize = strlen(line);
    if (line[lineSize-1] == '\n') line[lineSize-1] = '\0';  // Remove the /n char if it exists
    return line;
}

//  Login the client into the server
void login() {
    //  We have udpSock globally pre-initialized at -1. With this, we ensure that socket is created only one time
    if (udpSock < 0) {
        openUDPSocket();
    }
    setupServAddr();
    //  Initialization of the client status
    clientData.Status = NOT_REGISTERED;
    infoMsg("Client in status NOT_REGISTERED\n");

    UDP registerPacket = buildREG_REQPacket();

    //  Send first register packet
    if (sendto(udpSock, &registerPacket, sizeof(UDP), 0,
               (struct sockaddr *) &serverAddrUDP, (socklen_t) sizeof(serverAddrUDP)) < 0) {
        errorMsg();
        perror("Error sending the UDP register packet");
        exit(-1);
    }
    if (debug_mode) {
        debugMsg();
        printf("First register packet sent\n");
    }
    //  Status change because we sent the first packet
    clientData.Status = WAIT_ACK_REG;
    infoMsg("Client in status WAIT_ACK_REG\n");

    struct timeval t;
    int acc;
    fd_set read_fds;

    for (int sign_ups = 0; sign_ups < O; sign_ups++) {   // Register processes
        acc = 0;
        if(debug_mode) {
            debugMsg();
            printf("New register process: number %i\n" resetColor, sign_ups);
        }
        for (int packetsPerSignup = 0; packetsPerSignup < N; packetsPerSignup++) {   // Number of packets for every register process
            // Every packet sent we re-initialize the timeval for preventing it to get stuck at 0
            t.tv_sec = T;
            t.tv_usec = 0;
            if (packetsPerSignup > P && Q * T > acc) { // Increment sending interval after P packets (MAX to Q x T)
                acc = acc + T;
                t.tv_sec += acc;
            }

            FD_ZERO(&read_fds);
            FD_SET(udpSock, &read_fds);
            if (select(udpSock + 1, &read_fds, NULL, NULL, &t)) {   // If we receive a packet, process it
                receiveRegisterPacket();
                // By default, we exit de login function unless we have to keep going in the same register process
                if (!resetCommunication) {
                    return;
                }
            }
            // If not, send another packet
            if (sendto(udpSock, &registerPacket, sizeof(UDP), 0,
                       (struct sockaddr *) &serverAddrUDP, (socklen_t) sizeof(serverAddrUDP)) < 0) {
                errorMsg();
                perror("Error sending the UDP register packet");
                exit(-1);
            }
            if (debug_mode) {
                debugMsg();
                printf("REG_REQ packet N. %i sent. t = %i\n", packetsPerSignup, acc + T);
            }

            //  If we continued the same register process after receiving a packet, we have to re-update
            //  the client status
            if (resetCommunication) {
                clientData.Status = WAIT_ACK_REG;
                infoMsg("Client in status WAIT_ACK_REG\n");
                resetCommunication = false;
            }
        }
        sleep(U);   // Wait U seconds before starting another register process
    }
    errorMsg();
    printf("Can't connect to the server");
    exit(-1);
}

//  Builds a REG_REQ-type packet
UDP buildREG_REQPacket() {
    UDP packet;
    packet.Type = REG_REQ;
    strcpy(packet.Id_Tans, clientData.Id);
    strcpy(packet.Id_Comm, "0000000000");
    strcpy(packet.Data, "");
    return packet;
}

void infoFormat() {
    printf(whiteBold "[INFO]\t=> " white);
}

void infoMsg(char text[]) {
    printf(whiteBold "[INFO]\t=>\t" white "%s" resetColor, text);
}

void okMsg() {
    printf(greenBold "[OK]\t=>\t" green);
}

//  Creates the UDP Socket
void openUDPSocket() {
    udpSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSock < 0) {
        errorMsg();
        perror("Error creating the UDP socket");
        exit(-1);
    }
    //  Set up the client address for the socket (sockaddr_in struct)
    memset(&clientAddrUDP, 0, sizeof (struct sockaddr_in));
    clientAddrUDP.sin_family = AF_INET;
    clientAddrUDP.sin_port = htons(0);
    clientAddrUDP.sin_addr.s_addr = (INADDR_ANY);

    //  Bind the socket to the address set up before
    if (bind(udpSock, (const struct sockaddr *) &clientAddrUDP, sizeof (struct sockaddr_in)) < 0) {
        errorMsg();
        perror("Error binding the UDP socket");
        exit(-1);
    }

    if (debug_mode) {
        debugMsg();
        printf("Socket successfully created and bound.\n");
    }

    if (debug_mode) {
        debugMsg();
        printf("Server address set to:\n"
               "IP: %s\n"
               "Port: %hu\n", inet_ntoa(serverAddrUDP.sin_addr), ntohs(serverAddrUDP.sin_port));
    }
}

void setupServAddr() {
    // Set up the server address struct for receiving packets
    memset(&serverAddrUDP, 0, sizeof(struct sockaddr_in));
    serverAddrUDP.sin_family = AF_INET;
    serverAddrUDP.sin_port = htons(serverData.Server_UDP);
    struct hostent *host = gethostbyname(serverData.Server);
    serverAddrUDP.sin_addr.s_addr = (((struct in_addr*) host->h_addr_list[0])->s_addr);
}

//  Receive the register packet through UDP
void receiveRegisterPacket() {
    UDP packet;
    socklen_t serverAddrSize = sizeof(serverAddrUDP);
    long sizeReceived;
    sizeReceived = recvfrom(udpSock, &packet, sizeof(UDP), MSG_WAITALL,
                            (struct sockaddr *) &serverAddrUDP, &serverAddrSize);
    if (sizeReceived < 0) {
        errorMsg();
        perror("Error receiving the UDP register packet");
        exit(-1);
    }
    if (debug_mode) {
        debugMsg();
        printf("UDP packet type %s received correctly.\n" resetColor, getTypeOfPacket(packet));
    }
    processPacketType(packet);
}

char* getTypeOfPacket(UDP packet) {
    char* charPointer;
    if (packet.Type == REG_ACK) {
        return charPointer="REG_ACK";
    } else if (packet.Type == REG_NACK) {
        return charPointer="REG_NACK";
    } else if (packet.Type == REG_REJ) {
        return charPointer="REG_REJ";
    } else if (packet.Type == INFO_ACK) {
        return charPointer="INFO_ACK";
    } else if (packet.Type == INFO_NACK) {
        return charPointer="INFO_NACK";
    } else if (packet.Type == ALIVE) {
        return charPointer="ALIVE";
    } else if (packet.Type == ALIVE_REJ) {
        return charPointer="ALIVE_REJ";
    }
    return NULL;
}

//  Classifies the packet according to his type
void processPacketType(UDP packet) {
    unsigned char packetType = packet.Type;

    if (packetType == REG_ACK) {
        processREG_ACK(packet);
    } else if (packetType == REG_NACK) {
        processREG_NACK(packet);
    } else if (packetType == REG_REJ) {
        processREG_REJ(packet);
    } else if (packetType == INFO_ACK) {
        processINFO_ACK(packet);
    } else if (packetType == INFO_NACK) {
        processINFO_NACK(packet);
    }
}

//  Process an INFO_NACK-type packet
void processINFO_NACK(UDP packet) {
    if (clientData.Status != WAIT_ACK_INFO && !correctServerData(packet)) {
        errorMsg();
        printf("Wrong client status or wrong packet!!");
        login();
        return;
    }
    clientData.Status = NOT_REGISTERED;
    infoMsg("Client in status NOT_REGISTERED\n");
    resetCommunication = true;
}

bool correctServerData(UDP packet) {
    char *receivedServerIP = inet_ntoa(serverAddrUDP.sin_addr);
    if (strcmp(packet.Id_Tans, serverData.Id_Trans) == 0
    && strcmp(packet.Id_Comm, serverData.Id_Comm) == 0
    && strcmp(serverData.Server, receivedServerIP) == 0) {
        return true;
    }
    return false;
}
bool correctServerDataTCP(TCP packet) {
    if (strcmp(packet.Id_Trans, serverData.Id_Trans) == 0
        && strcmp(packet.Id_Comm, serverData.Id_Comm) == 0) {
        return true;
    }
    return false;
}


//  Process an INFO_ACK-type packet
void processINFO_ACK(UDP packet) {
    if (clientData.Status != WAIT_ACK_INFO || !correctServerData(packet)) {
        errorMsg();
        printf("Wrong client status or wrong packet!!\n");
        login();
        return;
    }
    clientData.Status = REGISTERED;
    infoMsg("Client in status REGISTERED\n");
    serverData.Server_TCP = strtol(packet.Data, NULL, 10);
    periodicCommunication();
}

//  Process a REG_REJ-type packet
void processREG_REJ(UDP packet) {
    login();
}

//  Process a REG_NACK-type packet
void processREG_NACK(UDP packet) {
    clientData.Status = NOT_REGISTERED;
    infoMsg("Client in status NOT_REGISTERED\n");
    resetCommunication = true;
}

//  Process a REG_ACK-type packet
void processREG_ACK(UDP packet) {
    if (clientData.Status != WAIT_ACK_REG) {
        errorMsg();
        printf("Wrong client status or wrong packet!!\n");
        login();
        return;
    }
    //  Copy the communication ID, the server ID and the server IP for securing network purposes
    strcpy(serverData.Id_Trans, packet.Id_Tans);
    strcpy(serverData.Id_Comm, packet.Id_Comm);
    char serverIP[MAXIMUM_LINE_LENGTH];
    strcpy(serverIP, inet_ntoa(serverAddrUDP.sin_addr)); //  IP from network mode to string
    strcpy(serverData.Server, serverIP);
    serverData.newServer_UDP = strtol(packet.Data, NULL, 10);

    UDP REG_INFOPacket = buildREG_INFOPacket();

    // Modify the serverAddrUDP struct for matching the new UDP port received from the server and continue with the communication through it
    serverAddrUDP.sin_port = htons(serverData.newServer_UDP);

    // Send the REG_INFO packet to the server
    if (sendto(udpSock, &REG_INFOPacket, sizeof(UDP), 0,
               (struct sockaddr *) &serverAddrUDP, (socklen_t) sizeof(serverAddrUDP)) < 0) {
        errorMsg();
        perror("Error sending the UDP REG_INFO packet");
        exit(-1);
    }

    clientData.Status = WAIT_ACK_INFO;
    infoMsg("Client in status WAIT_ACK_INFO\n");

    // Initialize some variables for controlling the reception time
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(udpSock, &read_fds);
    struct timeval t;
    t.tv_sec = 2*T;
    t.tv_usec = 0;

    //  If we receive an INFO_ACK packet, process it.
    //  If not, start another login process (function login())
    if (select(udpSock + 1, &read_fds, NULL, NULL, &t)) {
        long sizeReceived = 0;
        socklen_t serverAddrSize = sizeof(serverAddrUDP);
        while (sizeReceived != sizeof(UDP)) {
            sizeReceived += recvfrom(udpSock, &packet, sizeof(UDP), 0,
                                     (struct sockaddr *) &serverAddrUDP, &serverAddrSize);
            if (sizeReceived < 0) {
                errorMsg();
                perror("Error receiving the UDP INFO_ACK packet");
                exit(-1);
            }
        }
        if (debug_mode) {
            debugMsg();
            printf("UDP packet type %s received correctly.\n" resetColor, getTypeOfPacket(packet));
        }
        if (packet.Type != INFO_ACK) {
            login();
        }

        processINFO_ACK(packet);
        return;
    }

    login();
}

//  Builds a REG_INFO-type packet
UDP buildREG_INFOPacket() {
    UDP packet;
    packet.Type = REG_INFO;
    strcpy(packet.Id_Tans, clientData.Id);
    strcpy(packet.Id_Comm, serverData.Id_Comm);

    char data[61];

    sprintf(data, "%d", clientData.Local_TCP);
    strcat(data, ",");

    for (int i=0; i < elementsNumber; i++) {
        strcat(data, clientData.Elements[i]->Id);
        strcat(data, ";");
    }

    data[strlen(data)-1] = '\0';
    strcpy(packet.Data, data);

    return packet;
}

void periodicCommunication() {
    UDP ALIVEPacket = buildALIVEPacket();
    setupServAddr();    //  Reset server address for periodic communication
    if (sendto(udpSock, &ALIVEPacket, sizeof(UDP), 0,
               (const struct sockaddr *) &serverAddrUDP, sizeof(serverAddrUDP)) < 0) {
        errorMsg();
        perror("Error sending ALIVE packet");
        exit(-1);
    }
    if (debug_mode) {
        debugMsg();
        printf("UDP packet type %s sent correctly.\n" resetColor, getTypeOfPacket(ALIVEPacket));
    }
    struct timeval t;
    t.tv_sec = R*V;
    t.tv_usec = 0;
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(udpSock, &read_fds);
    if (select(udpSock + 1, &read_fds, NULL, NULL, &t)) {
        UDP packet = receiveALIVEPacket();
        if (packet.Type == ALIVE && correctServerData(packet) && strcmp(clientData.Id, packet.Data) == 0) {
            createThreads();
            return;
        }
    }
    //  Packet not received in R*T seconds or incorrect packet
    errorMsg();
    printf("First ALIVE not received or incorrect packet\n");
    login();
}

UDP receiveALIVEPacket() {
    UDP packet;
    socklen_t serverAddrSize = sizeof(serverAddrUDP);
    long sizeReceived;
    sizeReceived = recvfrom(udpSock, &packet, sizeof(UDP), MSG_WAITALL,
                            (struct sockaddr *) &serverAddrUDP, &serverAddrSize);
    if (sizeReceived < 0) {
        errorMsg();
        perror("Error receiving the UDP ALIVE packet");
        exit(-1);
    }
    if (debug_mode) {
        debugMsg();
        printf("UDP packet type %s received correctly.\n", getTypeOfPacket(packet));
    }
    return packet;
}

void createThreads() {
    if (clientData.Status != REGISTERED) {
        errorMsg();
        printf("Wrong client status!\n");
        login();
        return;
    }
    clientData.Status = SEND_ALIVE;
    infoMsg("Client in status SEND_ALIVE\n");
    if (tcpSock1 < 0) {
        openTCP1Socket();
    }
    pthread_create(&terminalThread, NULL, (void *(*)(void *)) handleTerminalInput, NULL);
    pthread_create(&tcpThread, NULL, (void *(*)(void *)) handleTCPConnections, NULL);
    ALIVELoop();
}

void ALIVELoop() {
    int ALIVEsLost = 0;
    UDP ALIVEPacket = buildALIVEPacket();
    struct timeval t;
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(udpSock, &read_fds);
    while (ALIVEsLost < S) {
        if (resetCommunication) {
            return;
        }
        sleep(V);
        t.tv_sec = R*V;
        t.tv_usec = 0;
        if (sendto(udpSock, &ALIVEPacket, sizeof(UDP), 0,
                   (const struct sockaddr *) &serverAddrUDP, sizeof(serverAddrUDP)) < 0) {
            errorMsg();
            perror("Error sending ALIVE packet");
            exit(-1);
        }
        if (debug_mode) {
            debugMsg();
            printf("UDP packet type %s sent correctly.\n" resetColor, getTypeOfPacket(ALIVEPacket));
        }
        if (select(udpSock + 1, &read_fds, NULL, NULL, &t)) {
            UDP packet = receiveALIVEPacket();
            if (packet.Type != ALIVE || !correctServerData(packet) || strcmp(clientData.Id, packet.Data) != 0) {
                errorMsg();
                printf("Incorrect packet or mismatching data!!\n");
                pthread_cancel(terminalThread);
                login();
                return;
            }
            ALIVEsLost = 0;
        } else {
            ALIVEsLost++;
        }
    }
    errorMsg();
    printf("Connexion lost with server.\n");
    pthread_cancel(terminalThread);
    login();
}

void handleTCPConnections() {
    while (1) {
        socklen_t* addrLen = (socklen_t *) sizeof(serverAddrTCP);
        if (accept(tcpSock1, (struct sockaddr *) &serverAddrTCP, addrLen) < 0) {
            errorMsg();
            perror("Error accepting TCP1 connection.");
            exit(-1);
        }

        TCP packet;
        if (recv(tcpSock1, &packet, sizeof(TCP), MSG_WAITALL) < 0) {
            errorMsg();
            perror("Error receiving packet from TCP1.");
            exit(-1);
        }

        int elementIndex;
        if (packet.Type == SET_DATA && (elementIndex = searchElement(packet.Element)) > -1 && getElementType(packet.Element) == 0) {
            strcpy(clientData.Elements[elementIndex]->Data, packet.Value);
            TCP DATA_ACKPacket = buildDATA_ACKPacket();
            if (send(tcpSock1, DATA_ACKPacket, sizeof(TCP), 0) < 0) {
                errorMsg();
                perror("Error sending the DATA_ACK packet.");
                exit(-1);
            }
        } else if (packet.Type == GET_DATA) {

        }
    }
}

//  Returns 0 if output type or 1 if input type
int getElementType (char* elementId) {
    int elementIndex = searchElement(elementId);

}

_Noreturn void handleTerminalInput() {
    char line[MAXIMUM_LINE_LENGTH];
    while (1) {
        fgets(line, sizeof(line), stdin);
        line[strlen(line) - 1] = ' ';
        char* token = strtok(line, " ");
        if (token == NULL) {
            errorMsg();
            printf("Invalid command entered!\n");
            printCommands();
        } else if (strcmp(token, "stat") == 0) {
            statCommand();
        } else if (strcmp(token, "quit") == 0) {
            quitCommand();
        } else if (strcmp(token, "set") == 0) {
            setCommand(token);
        } else if (strcmp(token, "send") == 0) {
            sendCommand(token);
        } else {
            errorMsg();
            printf("Invalid command entered!\n");
            printCommands();
        }
    }

}

void statCommand() {
    printf(yellowBold"----------------------------------------\n");
    printf("|\t\t"yellow"Client ID: %s\n", clientData.Id);
    for (int i=0; i < elementsNumber; i++) {
        if (strlen(clientData.Elements[i]->Data) == 0) {
            printf(yellowBold"|\t->"yellow" %s\t\t"yellowBold"->"yellow" (no value)\t\n", clientData.Elements[i]->Id);
        } else {
            printf(yellowBold"|\t->"yellow" %s\t\t"yellowBold"->"yellow" %s\t\n", clientData.Elements[i]->Id, clientData.Elements[i]->Data);
        }
    }
    printf(yellowBold"----------------------------------------\n");
}

void setCommand(char* token) {
    token = strtok(NULL, " ");
    int elementIndex;
    if (token == NULL || strlen(token) != 7 || (elementIndex = searchElement(token)) == -1) {
        errorMsg();
        if (token == NULL) {
            printf("Usage: set <element_id> <new_value>\n");
        } else if (strlen(token) != 7) {
            printf("<element_id> has to be 7 chars.\n");
        } else {
            printf("Specified element Id doesn't exist.\n");
        }
        return;
    }
    token = strtok(NULL, " ");
    if (token == NULL || strlen(token) > 15) {
        errorMsg();
        if (token == NULL) {
            printf("Usage: set <element_id> <new_value>\n");
        } else {
            printf("Element data can´t be bigger than 15 digits.\n");
        }
        return;
    }
    char elementData[15];
    strcpy(elementData, token);
    strcpy(clientData.Elements[elementIndex]->Data, elementData);

    okMsg();
    printf("Value of element set successfully!\n");
}

int searchElement(char* elemId) {
    for (int i=0; i < elementsNumber; i++) {
        if (strcmp(clientData.Elements[i]->Id, elemId) == 0) {
            return i;
        }
    }
    return -1;
}

void sendCommand(char* token) {
    token = strtok(NULL, " ");
    if ( token == NULL || strlen(token) != 7 || (searchElement(token) == -1)) {
        errorMsg();
        if (token == NULL) {
            printf("Usage: send <element_id>\n");
        } else if (strlen(token) != 7) {
            printf("<element_id> has to be 7 chars.\n");
        } else {
            printf("<element_id> not found.\n");
        }
        return;
    }
    char elementId[8];
    strcpy(elementId, token);

    tcpSock2 = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSock2 < 0) {
        errorMsg();
        perror("Error creating the tcp2 socket");
        exit(-1);
    }
    setupServAddrTCP();
    if (connect(tcpSock2, (struct sockaddr *) &serverAddrTCP, sizeof(serverAddrTCP)) < 0) {
        errorMsg();
        perror("Couldn't connect to the server via TCP2 socket");
        exit(-1);
    }

    TCP SEND_DATAPacket = buildSEND_DATAPacket(elementId);

    if (send(tcpSock2, &SEND_DATAPacket, sizeof(TCP), 0) < 0) {
        errorMsg();
        perror("Error sending the SEND_DATA packet through TCP2.");
        exit(-1);
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(tcpSock2, &read_fds);
    struct timeval t;
    t.tv_sec = M;
    t.tv_usec = 0;
    if (select(tcpSock2 + 1, &read_fds, NULL, NULL, &t)) {
        receiveDATAPacket(elementId);
        return;
    }

    infoMsg("DATA response not received, resending SEND_DATA packet to server.\n");
    close(tcpSock2);
}

void receiveDATAPacket(char elementId[8]) {
    TCP packet;
    if (recv(tcpSock2, &packet, sizeof(TCP), 0) < 0) {
        errorMsg();
        perror("Error receiving the DATA Packet");
        exit(-1);
    }

    close(tcpSock2);

    if (packet.Type == DATA_REJ || !correctServerDataTCP(packet) || strcmp(packet.Info, clientData.Id) != 0) {
        pthread_cancel(terminalThread);
        resetCommunication = true;
        login();
        return;
    }

    if (packet.Type == DATA_NACK || !correctElementData(packet, elementId)) {
        if (packet.Type == DATA_NACK) {
            infoMsg("DATA_NACK packet received, resending SEND_DATA packet to server.\n");
        } else {
            infoMsg("Mismatching element information, resending SEND_DATA packet to server.\n");
        }
        return;
    }
    //  If DATA_ACK is the packet received with correct element data

    okMsg();
    printf("Element value successfully stored in server.\n");
}

bool correctElementData(TCP packet, char elementId[8]) {
    if (strcmp(packet.Element, elementId) == 0
    && strcmp(packet.Value, getElementValue(elementId)) == 0) {
        return true;
    }
    return false;
}

TCP buildSEND_DATAPacket(char elementId[8]) {
    TCP packet;
    packet.Type = SEND_DATA;
    strcpy(packet.Id_Trans, clientData.Id);
    strcpy(packet.Id_Comm, serverData.Id_Comm);
    strcpy(packet.Element, elementId);
    char* elementValue;
    elementValue = getElementValue(elementId);
    if (elementValue == NULL) {

    }
    strcpy(elementValue, getElementValue(elementId));
    char* time = getNowTime();
    strcpy(packet.Info, time);
    return packet;
}

char* getNowTime() {
    char* packetInfo = malloc(sizeof(char) * 80);
    char year[5], month[3], day[3], hour[3], minute[3], second[3];
    time_t now;
    time(&now);
    struct tm *time = localtime(&now);
    sprintf(year, "%i", time->tm_year+1900);
    sprintf(month, "%i", time->tm_mon);
    sprintf(day, "%i", time->tm_mday);
    sprintf(hour, "%i", time->tm_hour);
    sprintf(minute, "%i", time->tm_min);
    sprintf(second, "%i", time->tm_sec);
    strcpy(packetInfo, year);
    strcat(packetInfo, "-");
    strcat(packetInfo, month);
    strcat(packetInfo, "-");
    strcat(packetInfo, day);
    strcat(packetInfo, ";");
    strcat(packetInfo, hour);
    strcat(packetInfo, ":");
    strcat(packetInfo, minute);
    strcat(packetInfo, ":");
    strcat(packetInfo, second);
    return packetInfo;
}

char* getElementValue(char* elementId) {
    int elementIndex = searchElement(elementId);
    char* elementValue = malloc(sizeof(char)*16);
    strcpy(elementValue, clientData.Elements[elementIndex]->Data);
    return elementValue;
}

void setupServAddrTCP() {
    memset(&serverAddrTCP, 0, sizeof(serverAddrTCP));
    serverAddrTCP.sin_family = AF_INET;
    serverAddrTCP.sin_port = htons(serverData.Server_TCP);
    serverAddrTCP.sin_addr.s_addr = inet_addr(serverData.Server);
}

void quitCommand() {
    kill(0, SIGINT);
}

void printCommands() {
    printf(yellowBold "\t\t\t\tCOMMANDS AVAILABLE:\n" yellow);
    printf("\t- stat\tSee the client's elements and its values.\n");
    printf("\t- set <element_id> <new_value>\tSet an element value\n");
    printf("\t- send <element_id>\tSend an element value to the server\n");
}

UDP buildALIVEPacket() {
    UDP packet;
    packet.Type = ALIVE;
    strcpy(packet.Id_Tans, clientData.Id);
    strcpy(packet.Id_Comm, serverData.Id_Comm);
    strcpy(packet.Data, "");
    return packet;
}

void openTCP1Socket() {
    tcpSock1 = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSock1 < 0) {
        errorMsg();
        perror("Error opening the TCP1 socket");
        exit(-1);
    }

    //  Set up the client address (TCP) for the TCP1 socket (sockaddr_in struct)
    memset(&clientAddrTCP1, 0, sizeof (struct sockaddr_in));
    clientAddrTCP1.sin_family = AF_INET;
    clientAddrTCP1.sin_port = htons(clientData.Local_TCP);
    clientAddrTCP1.sin_addr.s_addr = (INADDR_ANY);

    //  Bind the socket to the address set up before
    if (bind(tcpSock1, (const struct sockaddr *) &clientAddrTCP1, sizeof (struct sockaddr_in)) < 0) {
        errorMsg();
        perror("Error binding the TCP1 socket");
        exit(-1);
    }

    if (debug_mode) {
        debugMsg();
        printf("TCP1 Socket successfully created and bound.\n");
    }
}