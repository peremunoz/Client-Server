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


//  Register-phase package types definitions
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

//  Some colors definitions for formatting purposes
#define debugColorBold "\033[1;34m"
#define debugColorNormal "\033[0;34m"
#define errorColor "\033[0;31m"
#define resetColor "\033[0m"
#define whiteBold "\033[1;37m"
#define whiteNormal "\033[0;37m"

//  Constants
#define MAXIMUM_LINE_LENGTH 255
#define P 2
#define Q 4
#define N 6
#define U 3
#define O 4
#define T 2

//  Structs pre-definitions
typedef struct ElementStruct Element;
typedef struct Client_Data Client;
typedef struct Server_Data Server;
typedef struct UDP_PDU UDP;

//  Function declarations
void checkParams(int argc, char* argv[]);
bool correctFileName(char filename[]);
void debugMsg();
void readCfg();
void storeElements(char* line);
void storeServer(char* line);
char* trimLine(char *buffer);
void storeId(char* line);
void storeLocal(char* line);
void storeUDP(char* line);
void createUDPSocket();
void login();
void infoFormat();
void infoMsg(char text[]);
void processRegisterPacket();
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

//  Global variables
bool debug_mode = false;
char clientCfgFile[] = "client.cfg";
Client clientData;
Server serverData;
int udpSock = -1;
int elementsNumber;
struct sockaddr_in clientAddr, serverAddr;
bool continueWithSameRegisterProcess = false;

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
};

//  Element struct
struct ElementStruct {
    char Id[7];
    char Data[15];  // Every char is 1 byte --> 15 chars/bytes maximum
};

// UDP PDU Struct
struct UDP_PDU {
    unsigned char Type;
    char Id_Tans[11];
    char Id_Comm[11];
    char Data[61];
};

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    checkParams(argc, argv);
    readCfg();
    login();
    printf("SEND ALIVES!!\n");
    return 0;
}

void signal_handler(int signal) {
    if (signal == SIGINT) {
        infoMsg("CLOSING CLIENT... !!\n\n\n");
        close(udpSock);
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
                printf(errorColor "Error in the filename, incorrect format. (filename.cfg)\n");
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
    printf( debugColorBold "[DEBUG] --> " debugColorNormal);
}

//  Reads the clientData config file and assign its values to the attributes of the clientData or serverData structs
void readCfg() {
    FILE* fd = fopen(clientCfgFile, "r");
    if (fd == NULL) {
        perror(errorColor "Error opening the client cfg file");
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
        memset(element, 0, sizeof(Element));
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
        createUDPSocket();
    }
    //  Initialization of the client status
    clientData.Status = NOT_REGISTERED;
    infoMsg("Client in status NOT_REGISTERED\n");

    UDP registerPacket = buildREG_REQPacket();

    //  Send first register packet
    if (sendto(udpSock, &registerPacket, sizeof(UDP), 0,
               (struct sockaddr *) &serverAddr, (socklen_t) sizeof(serverAddr)) < 0) {
        perror(errorColor "Error sending the UDP register packet");
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
            printf(debugColorNormal "New register process: number %i\n" resetColor, sign_ups);
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
                processRegisterPacket();
                // By default, we exit de login function unless we have to keep going in the same register process
                if (!continueWithSameRegisterProcess) {
                    return;
                }
            }
            // If not, send another packet
            if (sendto(udpSock, &registerPacket, sizeof(UDP), 0,
                       (struct sockaddr *) &serverAddr, (socklen_t) sizeof(serverAddr)) < 0) {
                perror(errorColor "Error sending the UDP register packet");
                exit(-1);
            }
            if (debug_mode) {
                debugMsg();
                printf("REG_REQ packet N. %i sent. t = %i\n", packetsPerSignup, acc + T);
            }

            //  If we continued the same register process after receiving a packet, we have to re-update
            //  the client status
            if (continueWithSameRegisterProcess) {
                clientData.Status = WAIT_ACK_REG;
                infoMsg("Client in status WAIT_ACK_REG\n");
                continueWithSameRegisterProcess = false;
            }
        }
        sleep(U);   // Wait U seconds before starting another register process
    }
    printf(errorColor "[ERROR] --> Can't connect to the server\n");
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
    printf(whiteBold "[INFO] => " whiteNormal);
}

void infoMsg(char text[]) {
    printf(whiteBold "[INFO] => " whiteNormal "%s" resetColor, text);
}

//  Creates the UDP Socket
void createUDPSocket() {
    udpSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSock < 0) {
        perror(errorColor "Error creating the UDP socket");
        exit(-1);
    }
    //  Set up the client address for the socket (sockaddr_in struct)
    memset(&clientAddr, 0, sizeof (struct sockaddr_in));
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_port = htons(0);
    clientAddr.sin_addr.s_addr = (INADDR_ANY);

    //  Bind the socket to the address set up before
    if (bind(udpSock, (const struct sockaddr *) &clientAddr, sizeof (struct sockaddr_in)) < 0) {
        perror(errorColor "Error binding the UDP socket");
        exit(-1);
    }

    if (debug_mode) {
        debugMsg();
        printf("Socket successfully created and bound.\n");
    }

    // Set up the server address struct for receiving packets
    memset(&serverAddr, 0, sizeof(struct sockaddr_in));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverData.Server_UDP);
    struct hostent *host = gethostbyname(serverData.Server);
    serverAddr.sin_addr.s_addr = (((struct in_addr*) host->h_addr_list[0])->s_addr);

    if (debug_mode) {
        debugMsg();
        printf("Server address set to:\n"
               "IP: %s\n"
               "Port: %hu\n", inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port));
    }
}

//  Receive the register packet through UDP
void processRegisterPacket() {
    UDP packet;
    socklen_t serverAddrSize = sizeof(serverAddr);
    long sizeReceived = 0;
    sizeReceived += recvfrom(udpSock, &packet, sizeof(UDP), MSG_WAITALL,
                             (struct sockaddr *) &serverAddr, &serverAddrSize);
    if (sizeReceived < 0) {
        perror(errorColor "Error receiving the UDP register packet");
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
        infoMsg("Wrong client status or wrong packet!!");
        login();
    }
    clientData.Status = NOT_REGISTERED;
    infoMsg("Client in state NOT_REGISTERED\n");
    continueWithSameRegisterProcess = true;
}

bool correctServerData(UDP packet) {
    char *receivedServerIP = inet_ntoa(serverAddr.sin_addr);
    if (strcmp(packet.Id_Tans, serverData.Id_Trans) == 0
    && strcmp(packet.Id_Comm, serverData.Id_Comm) == 0
    && strcmp(serverData.Server, receivedServerIP) == 0) {
        return true;
    }
    return false;
}

//  Process an INFO_ACK-type packet
void processINFO_ACK(UDP packet) {
    if (clientData.Status != WAIT_ACK_INFO || !correctServerData(packet)) {
        infoMsg(errorColor "Wrong client status or wrong packet!!\n");
        login();
        return;
    }
    clientData.Status = REGISTERED;
    infoMsg("Client in status REGISTERED\n");
    serverData.Server_TCP = strtol(packet.Data, NULL, 10);
}

//  Process a REG_REJ-type packet
void processREG_REJ(UDP packet) {
    login();
}

//  Process a REG_NACK-type packet
void processREG_NACK(UDP packet) {
    clientData.Status = NOT_REGISTERED;
    infoMsg("Client in status NOT_REGISTERED\n");
    continueWithSameRegisterProcess = true;
}

//  Process a REG_ACK-type packet
void processREG_ACK(UDP packet) {
    if (clientData.Status != WAIT_ACK_REG) {
        infoMsg("Wrong client status or wrong packet!!\n");
        login();
        return;
    }
    //  Copy the communication and server ID for securing network purposes
    strcpy(serverData.Id_Trans, packet.Id_Tans);
    strcpy(serverData.Id_Comm, packet.Id_Comm);
    char serverIP[MAXIMUM_LINE_LENGTH];
    strcpy(serverIP, inet_ntoa(serverAddr.sin_addr)); //  IP from network mode to string
    strcpy(serverData.Server, serverIP);
    serverData.Server_UDP = strtol(packet.Data, NULL, 10);

    UDP REG_INFOPacket = buildREG_INFOPacket();

    // Modify the serverAddr struct for matching the new UDP port received from the server and continue with the communication through it
    serverAddr.sin_port = htons(serverData.Server_UDP);

    // Send the REG_INFO packet to the server
    if (sendto(udpSock, &REG_INFOPacket, sizeof(UDP), 0,
               (struct sockaddr *) &serverAddr, (socklen_t) sizeof(serverAddr)) < 0) {
        perror(errorColor "Error sending the UDP REG_INFO packet");
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
        socklen_t serverAddrSize = sizeof(serverAddr);
        while (sizeReceived != sizeof(UDP)) {
            sizeReceived += recvfrom(udpSock, &packet, sizeof(UDP), 0,
                                     (struct sockaddr *) &serverAddr, &serverAddrSize);
            if (sizeReceived < 0) {
                perror(errorColor "Error receiving the UDP INFO_ACK packet");
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