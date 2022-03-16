#include "client.h"

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

//  Functions declarations
//      Signal handlers
void quit_handler(int signal);
void relogin_handler(int signal);
//      Reading file.cfg functions
void readCfg();
bool correctFileName(char filename[]);
char* trimLine(char *buffer);
void storeElements(char* line);
void storeServer(char* line);
void storeId(char* line);
void storeLocal(char* line);
void storeUDP(char* line);
//      Login functions
void openUDPSocket();
void login();
void receiveRegisterPacket();
void processPacketType(UDP packet);
void processREG_ACK(UDP packetReceived);
void processREG_NACK();
void processREG_REJ();
void processINFO_ACK(UDP packet);
void processINFO_NACK(UDP packet);
bool correctServerData(UDP packet);
void setupServAddrUDP();
//      Periodic communication functions
void periodicCommunication();
void createThreads();
void* ALIVELoop();
//      Terminal handling functions
void* handleTerminalInput();
void statCommand();
void setCommand(char* token);
void sendCommand(char* token);
void quitCommand();
void printCommands();
//      TCP server requests functions
void openTCP1Socket();
void setupServAddrTCP();
void handleTCPConnections();
void receiveDATAPacket(char elementId[8]);
bool correctServerDataTCP(TCP packet);
bool correctElementData(TCP packet, char elementId[8]);
//      Packet builder functions
UDP buildREG_REQPacket();
UDP buildREG_INFOPacket();
UDP buildALIVEPacket();
UDP receiveALIVEPacket();
TCP buildSEND_DATAPacket(char elementId[8]);
TCP buildSET_DATAResponse(TCP receivedPacket);
TCP buildGET_DATAResponse(int elementIndex);
TCP buildDATA_NACKPacket(TCP receivedPacket);
TCP buildDATA_REJPacket(TCP receivedPacket);
//      Auxiliary functions
void checkParams(int argc, char* argv[]);
char* getTypeOfPacketUDP(UDP packet);
char* getTypeOfPacketTCP(TCP packet);
int searchElement(char* elemId);
char* getElementValue(char* elementId);
char* getNowTime();
int getElementType(char* elementId);
//      Formatting functions
void debugMsg();
void infoMsg(char text[]);
void infoFormat();
void errorMsg();
void okMsg();

//  Global variables
bool debug_mode = false;
char clientCfgFile[] = "client.cfg";
Client clientData;
Server serverData;
int udpSock = -1;
int tcpSock1 = -1;  //  TCP socket for accepting server requests
int tcpSock2 = -1;  //  TCP socket for sending data to server
int elementsNumber; //  Client's element number
struct sockaddr_in clientAddrUDP, clientAddrTCP, serverAddrUDP, serverAddrTCP;
bool resetCommunication = false;
pthread_t terminalThread = (pthread_t) NULL;
pthread_t aliveThread = (pthread_t) NULL;
pid_t mainProcess;

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

//          MAIN FUNCTION

int main(int argc, char* argv[]) {
    mainProcess = getpid();
    signal(SIGUSR2, quit_handler);
    checkParams(argc, argv);
    readCfg();
    login();
    return 0;
}

//          SIGNAL HANDLERS

void quit_handler(int signal) {
    if (signal == SIGUSR2) {
        printf("\n");
        infoMsg("CLOSING CLIENT...\n");
        sleep(1);
        close(udpSock);
        close(tcpSock1);
        close(tcpSock2);
        pthread_cancel(terminalThread);
        pthread_cancel(aliveThread);
        if (debug_mode) {
            debugMsg();
            printf("UDP, TCP1 and TCP2 sockets closed successfully\n");
            debugMsg();
            printf("Terminal input thread and ALIVE packet sending thread ended successfully");
        }
        exit(0);
    }
}

void relogin_handler(int signal) {
    if (signal == SIGUSR1) {
        pthread_cancel(terminalThread);
        pthread_cancel(aliveThread);
        login();
    }
}

//          READING FILE.CFG FUNCTIONS

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

//  Checks if the filename is in the correct format
bool correctFileName(char filename[]) {
    char* extension = strchr(filename, '.');    // Search for a '.' in the filename
    if (extension == NULL) return false;    // If there's not, wrong format
    if (strcmp(extension, ".cfg") != 0) return false;   // If the extension it isn't '.cfg', bad format
    return true;
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

//  Stores the server in the serverData struct
void storeServer(char* line) {
    char* server = trimLine(line);
    strcpy(serverData.Server, server);
    if (debug_mode) {
        debugMsg();
        printf("Server copied successfully: %s\n" resetColor, serverData.Server);
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

//  Stores the TCP port in the clientData struct
void storeLocal(char* line) {
    char* local = trimLine(line);
    clientData.Local_TCP = (strtol(local, NULL, 10));
    if (debug_mode) {
        debugMsg();
        printf("Local-TCP copied successfully: %d\n" resetColor, clientData.Local_TCP);
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

//          LOGIN FUNCTIONS

//  Creates and binds the UDP Socket
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

//  Login the client into the server
void login() {

    //  Define the signal handler every time we enter the login() function if we have to repeat it
    signal(SIGUSR1, relogin_handler);

    //  We have udpSock globally pre-initialized at -1. With this, we ensure that socket is created only one time
    if (udpSock < 0) {
        openUDPSocket();
    }
    setupServAddrUDP();
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
                printf("%s packet N. %i sent. t = %i\n", getTypeOfPacketUDP(registerPacket) ,packetsPerSignup, acc + T);
            }

            //  If we continued the same register process after receiving a packet, we have to re-update
            //  the client status
            if (resetCommunication) {
                clientData.Status = WAIT_ACK_REG;
                infoMsg("Client in status WAIT_ACK_REG\n");
                resetCommunication = false;
                setupServAddrUDP();
            }
        }
        sleep(U);   // Wait U seconds before starting another register process
    }
    errorMsg();
    printf("Can't connect to the server");
    exit(-1);
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
        printf("UDP packet type %s received correctly.\n" resetColor, getTypeOfPacketUDP(packet));
    }
    processPacketType(packet);
}

//  Classifies the packet according to its type
void processPacketType(UDP packet) {
    unsigned char packetType = packet.Type;

    if (packetType == REG_ACK) {
        processREG_ACK(packet);
    } else if (packetType == REG_NACK) {
        processREG_NACK();
    } else if (packetType == REG_REJ) {
        processREG_REJ();
    } else if (packetType == INFO_ACK) {
        processINFO_ACK(packet);
    } else if (packetType == INFO_NACK) {
        processINFO_NACK(packet);
    }
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
        sizeReceived = recvfrom(udpSock, &packet, sizeof(UDP), MSG_WAITALL,
                                (struct sockaddr *) &serverAddrUDP, &serverAddrSize);
        if (sizeReceived < 0) {
            errorMsg();
            perror("Error receiving the UDP INFO_ACK packet");
            exit(-1);
        }
        if (debug_mode) {
            debugMsg();
            printf("UDP packet type %s received correctly.\n" resetColor, getTypeOfPacketUDP(packet));
        }
        processPacketType(packet);
        return;
    }
    login();
}

//  Process a REG_NACK-type packet
void processREG_NACK() {
    clientData.Status = NOT_REGISTERED;
    infoMsg("Client in status NOT_REGISTERED\n");
    resetCommunication = true;
}

//  Process a REG_REJ-type packet
void processREG_REJ() {
    login();
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

//  Checks if the server information stored and the received in the packet matches
bool correctServerData(UDP packet) {
    char *receivedServerIP = inet_ntoa(serverAddrUDP.sin_addr);
    if (strcmp(packet.Id_Tans, serverData.Id_Trans) == 0
        && strcmp(packet.Id_Comm, serverData.Id_Comm) == 0
        && strcmp(serverData.Server, receivedServerIP) == 0) {
        return true;
    }
    return false;
}

//  Sets up the server address struct for receiving packets through UDP
void setupServAddrUDP() {
    memset(&serverAddrUDP, 0, sizeof(struct sockaddr_in));
    serverAddrUDP.sin_family = AF_INET;
    serverAddrUDP.sin_port = htons(serverData.Server_UDP);
    struct hostent *host = gethostbyname(serverData.Server);
    serverAddrUDP.sin_addr.s_addr = (((struct in_addr*) host->h_addr_list[0])->s_addr);
}

//          PERIODIC COMMUNICATION FUNCTIONS

//  Starts the periodic communication process
void periodicCommunication() {
    UDP ALIVEPacket = buildALIVEPacket();
    setupServAddrUDP();    //  Reset server address for periodic communication
    if (sendto(udpSock, &ALIVEPacket, sizeof(UDP), 0,
               (const struct sockaddr *) &serverAddrUDP, sizeof(serverAddrUDP)) < 0) {
        errorMsg();
        perror("Error sending ALIVE packet");
        exit(-1);
    }
    if (debug_mode) {
        debugMsg();
        printf("UDP packet type %s sent correctly.\n" resetColor, getTypeOfPacketUDP(ALIVEPacket));
    }
    struct timeval t;
    t.tv_sec = R*V;
    t.tv_usec = 0;
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(udpSock, &read_fds);
    if (select(udpSock + 1, &read_fds, NULL, NULL, &t)) {
        UDP packet = receiveALIVEPacket();
        //  Correct first ALIVE received
        if (packet.Type == ALIVE && correctServerData(packet) && strcmp(clientData.Id, packet.Data) == 0) {
            createThreads();
            return;
        }
    }
    //  Packet not received in R*T seconds or incorrect packet
    errorMsg();
    printf("First ALIVE not received or incorrect packet\n");
    sleep(V);
    login();
}

//  Creates the threads for sending ALIVE packets to server and handling the user input
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
    pthread_create(&terminalThread, NULL, &handleTerminalInput, NULL);
    pthread_create(&aliveThread, NULL, &ALIVELoop, NULL);
    handleTCPConnections();
}

//  Does the periodic sending of ALIVE packets, and it checks those responses
void* ALIVELoop() {
    int ALIVEsLost = 0;
    UDP ALIVEPacket = buildALIVEPacket();
    struct timeval t;
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(udpSock, &read_fds);
    while (ALIVEsLost < S) {
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
            printf("UDP packet type %s sent correctly.\n" resetColor, getTypeOfPacketUDP(ALIVEPacket));
        }
        if (select(udpSock + 1, &read_fds, NULL, NULL, &t)) {
            UDP packet = receiveALIVEPacket();
            if (packet.Type != ALIVE || !correctServerData(packet) || strcmp(clientData.Id, packet.Data) != 0) {
                errorMsg();
                printf("Incorrect packet or mismatching data!!\n");
                kill(mainProcess, SIGUSR1);
                return NULL;
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
    return NULL;
}

//          TERMINAL HANDLING FUNCTIONS

//  Handles the user input through terminal indefinitely
void* handleTerminalInput() {
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

//  Does the 'stat' command
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
    printf(yellowBold"----------------------------------------\n" resetColor);
}

//  Does the 'set' command
void setCommand(char* token) {
    token = strtok(NULL, " ");
    int elementIndex;
    if (token == NULL || strlen(token) != 7 || (elementIndex = searchElement(token)) == -1) {
        errorMsg();
        if (token == NULL) {
            printf("Usage: set <element_id> <new_value>\n" resetColor);
        } else if (strlen(token) != 7) {
            printf("<element_id> has to be 7 chars.\n" resetColor);
        } else {
            printf("Specified element Id doesn't exist.\n" resetColor);
        }
        return;
    }
    token = strtok(NULL, " ");
    if (token == NULL || strlen(token) > 15) {
        errorMsg();
        if (token == NULL) {
            printf("Usage: set <element_id> <new_value>\n" resetColor);
        } else {
            printf("Element data can´t be bigger than 15 digits.\n" resetColor);
        }
        return;
    }
    char elementData[15];
    strcpy(elementData, token);
    strcpy(clientData.Elements[elementIndex]->Data, elementData);

    okMsg();
    printf("Value of element set successfully!\n" resetColor);
}

//  Does the 'send' command
void sendCommand(char* token) {
    token = strtok(NULL, " ");
    if ( token == NULL || strlen(token) != 7 || (searchElement(token) == -1)) {
        errorMsg();
        if (token == NULL) {
            printf("Usage: send <element_id>\n" resetColor);
        } else if (strlen(token) != 7) {
            printf("<element_id> has to be 7 chars.\n");
        } else {
            printf("<element_id> not found.\n" resetColor);
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

    if (debug_mode) {
        debugMsg();
        printf("%s packet sent correctly\n", getTypeOfPacketTCP(SEND_DATAPacket));
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

    infoMsg("DATA response not received, resending SEND_DATA packet to server...\n");
    close(tcpSock2);
}

//  Does the 'quit' command
void quitCommand() {
    kill(mainProcess, SIGUSR2);
}

//  Prints the accepted commands
void printCommands() {
    printf(yellowBold "\t\t\t\tCOMMANDS AVAILABLE:\n" yellow);
    printf("\t- stat\tSee the client's elements and its values.\n");
    printf("\t- set <element_id> <new_value>\tSet an element value\n");
    printf("\t- send <element_id>\tSend an element value to the server\n");
}

//          TCP server requests handling functions

void openTCP1Socket() {
    tcpSock1 = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSock1 < 0) {
        errorMsg();
        perror("Error opening the TCP1 socket");
        exit(-1);
    }

    //  Set up the client address (TCP) for the TCP1 socket (sockaddr_in struct)
    memset(&clientAddrTCP, 0, sizeof (struct sockaddr_in));
    clientAddrTCP.sin_family = AF_INET;
    clientAddrTCP.sin_port = htons(clientData.Local_TCP);
    clientAddrTCP.sin_addr.s_addr = (INADDR_ANY);

    //  Bind the socket to the address set up before
    if (bind(tcpSock1, (const struct sockaddr *) &clientAddrTCP, sizeof (struct sockaddr_in)) < 0) {
        errorMsg();
        perror("Error binding the TCP1 socket");
        exit(-1);
    }

    if (debug_mode) {
        debugMsg();
        printf("TCP1 Socket successfully created and bound.\n");
    }
}

void setupServAddrTCP() {
    memset(&serverAddrTCP, 0, sizeof(serverAddrTCP));
    serverAddrTCP.sin_family = AF_INET;
    serverAddrTCP.sin_port = htons(serverData.Server_TCP);
    serverAddrTCP.sin_addr.s_addr = inet_addr(serverData.Server);
}

//  Function for handling TCP requests from server (Ran by main process)
void handleTCPConnections() {
    int newTCPsocket;
    while (1) {
        if (listen(tcpSock1, 1) < 0) {
            errorMsg();
            perror("Error listening TCP1 connection.");
            exit(-1);
        }
        socklen_t addrLen = sizeof(serverAddrTCP);

        newTCPsocket = accept(tcpSock1, (struct sockaddr *) &serverAddrTCP, &addrLen);
        if (newTCPsocket < 0) {
            errorMsg();
            perror("Error accepting TCP1 connection");
            exit(-1);
        }

        TCP packet;
        if (recv(newTCPsocket, &packet, sizeof(TCP), MSG_WAITALL) < 0) {
            errorMsg();
            perror("Error receiving packet from TCP1");
            exit(-1);
        }

        int elementIndex = searchElement(packet.Element);
        if (!correctServerDataTCP(packet)) {
            TCP DATA_REJPacket = buildDATA_REJPacket(packet);
            if (send(newTCPsocket, &DATA_REJPacket, sizeof(TCP), 0) < 0) {
                errorMsg();
                perror("Error sending the DATA_REJ packet.");
                exit(-1);
            }
            if (debug_mode) {
                debugMsg();
                printf("%s packet received with mismatching server/client information\n", getTypeOfPacketTCP(packet));
                debugMsg();
                printf("DATA_REJ packet sent correctly\n");
            }
            pthread_cancel(terminalThread);
            pthread_cancel(aliveThread);
            login();
            return;

        } else if (elementIndex < 0 || (packet.Type == SET_DATA && getElementType(packet.Element) == 0)) {
            TCP DATA_NACKPacket = buildDATA_NACKPacket(packet);
            if (send(newTCPsocket, &DATA_NACKPacket, sizeof(TCP), 0) < 0) {
                errorMsg();
                perror("Error sending the DATA_NACK packet.");
                exit(-1);
            }
            if (debug_mode) {
                debugMsg();
                printf("%s packet received with wrong element information\n", getTypeOfPacketTCP(DATA_NACKPacket));
                debugMsg();
                printf("DATA_NACK packet sent correctly\n");
            }

        } else if (packet.Type == SET_DATA && getElementType(packet.Element) == 1) {
            strcpy(clientData.Elements[elementIndex]->Data, packet.Value);
            if (debug_mode) {
                debugMsg();
                printf("Element id: %s set correctly to %s\n", clientData.Elements[elementIndex]->Id, clientData.Elements[elementIndex]->Data);
            }
            TCP SET_DATAResponse = buildSET_DATAResponse(packet);
            if (send(newTCPsocket, &SET_DATAResponse, sizeof(TCP), 0) < 0) {
                errorMsg();
                perror("Error sending the DATA_ACK packet.");
                exit(-1);
            }
            if (debug_mode) {
                debugMsg();
                printf("%s packet received with correct information\n", getTypeOfPacketTCP(packet));
                debugMsg();
                printf("%s packet sent correctly\n", getTypeOfPacketTCP(SET_DATAResponse));
            }
        } else if (packet.Type == GET_DATA) {
            TCP GET_DATAResponse = buildGET_DATAResponse(elementIndex);
            if (send(newTCPsocket, &GET_DATAResponse, sizeof(TCP), 0) < 0) {
                errorMsg();
                perror("Error sending the GET_DATA packet.");
                exit(-1);
            }
            if (debug_mode) {
                debugMsg();
                printf("%s packet received with correct information\n", getTypeOfPacketTCP(packet));
                debugMsg();
                printf("%s packet sent correctly\n", getTypeOfPacketTCP(GET_DATAResponse));
            }
        }
    }
}

//  Receives a DATA_XXX-type packet, and it processes depending on its type
void receiveDATAPacket(char elementId[8]) {
    TCP packet;
    if (recv(tcpSock2, &packet, sizeof(TCP), MSG_WAITALL) < 0) {
        errorMsg();
        perror("Error receiving the DATA Packet");
        exit(-1);
    }

    close(tcpSock2);

    if (packet.Type == DATA_REJ || !correctServerDataTCP(packet) || strcmp(packet.Info, clientData.Id) != 0) {
        errorMsg();
        printf("Incorrect %s packet received. Re-login to server...\n", getTypeOfPacketTCP(packet));
        kill(mainProcess, SIGUSR1);
        return;
    }

    if (packet.Type == DATA_NACK || !correctElementData(packet, elementId)) {
        if (packet.Type == DATA_NACK) {
            infoFormat();
            printf("%s packet received, resending SEND_DATA packet to server.\n" resetColor, getTypeOfPacketTCP(packet));
        } else {
            infoMsg("Mismatching element information, resending SEND_DATA packet to server.\n");
        }
        return;
    }
    //  If DATA_ACK is the packet received with correct element data

    okMsg();
    printf("Element value successfully stored in server.\n" resetColor);
}

//  Checks if the server information stored and the received in the packet matches
bool correctServerDataTCP(TCP packet) {
    if (strcmp(packet.Id_Trans, serverData.Id_Trans) == 0
        && strcmp(packet.Id_Comm, serverData.Id_Comm) == 0) {
        return true;
    }
    return false;
}

//  Checks if the element information stores and the received in the packet matches
bool correctElementData(TCP packet, char elementId[8]) {
    if (strcmp(packet.Element, elementId) == 0
        && strcmp(packet.Value, getElementValue(elementId)) == 0) {
        return true;
    }
    return false;
}

//          PACKET BUILDER FUNCTIONS

//  Builds a REG_REQ-type packet
UDP buildREG_REQPacket() {
    UDP packet;
    packet.Type = REG_REQ;
    strcpy(packet.Id_Tans, clientData.Id);
    strcpy(packet.Id_Comm, "0000000000");
    strcpy(packet.Data, "");
    return packet;
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

//  Builds an ALIVE-type packet
UDP buildALIVEPacket() {
    UDP packet;
    packet.Type = ALIVE;
    strcpy(packet.Id_Tans, clientData.Id);
    strcpy(packet.Id_Comm, serverData.Id_Comm);
    strcpy(packet.Data, "");
    return packet;
}

//  Receives an ALIVE packet
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
        printf("UDP packet type %s received correctly.\n", getTypeOfPacketUDP(packet));
    }
    return packet;
}

//  Builds a SEND_DATA-type packet
TCP buildSEND_DATAPacket(char elementId[8]) {
    TCP packet;
    packet.Type = SEND_DATA;
    strcpy(packet.Id_Trans, clientData.Id);
    strcpy(packet.Id_Comm, serverData.Id_Comm);
    strcpy(packet.Element, elementId);
    strcpy(packet.Value, getElementValue(elementId));
    char* time = getNowTime();
    strcpy(packet.Info, time);
    return packet;
}

//  Builds a DATA_ACK-type packet
TCP buildSET_DATAResponse(TCP receivedPacket) {
    TCP packet;
    packet.Type = DATA_ACK;
    strcpy(packet.Id_Comm, serverData.Id_Comm);
    strcpy(packet.Id_Trans, clientData.Id);
    strcpy(packet.Element, receivedPacket.Element);
    strcpy(packet.Value, receivedPacket.Value);
    char* time = getNowTime();
    strcpy(packet.Info, time);
    return packet;
}

//  Builds an DATA_ACK-type packet
TCP buildGET_DATAResponse(int elementIndex) {
    TCP packet;
    packet.Type = DATA_ACK;
    strcpy(packet.Id_Trans, clientData.Id);
    strcpy(packet.Id_Comm, serverData.Id_Comm);
    strcpy(packet.Element, clientData.Elements[elementIndex]->Id);
    strcpy(packet.Value, clientData.Elements[elementIndex]->Data);
    char* time = getNowTime();
    strcpy(packet.Info, time);
    return packet;
}

//  Builds a DATA_NACK-type packet
TCP buildDATA_NACKPacket(TCP receivedPacket) {
    TCP packet;
    packet.Type = DATA_NACK;
    strcpy(packet.Id_Comm, serverData.Id_Comm);
    strcpy(packet.Id_Trans, clientData.Id);
    strcpy(packet.Element, receivedPacket.Element);
    strcpy(packet.Value, receivedPacket.Value);
    strcpy(packet.Info, "Error in element information.");
    return packet;
}

//  Builds a DATA_REJ-type packet
TCP buildDATA_REJPacket(TCP receivedPacket) {
    TCP packet;
    packet.Type = DATA_REJ;
    strcpy(packet.Id_Trans, clientData.Id);
    strcpy(packet.Id_Comm, serverData.Id_Comm);
    strcpy(packet.Element, receivedPacket.Element);
    strcpy(packet.Value, receivedPacket.Value);
    strcpy(packet.Info, "Mismatching server/client information");
    return packet;
}

//          AUXILIARY FUNCTIONS

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

//  Returns the string-format packet type
char* getTypeOfPacketUDP(UDP packet) {
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
    } else if (packet.Type == REG_INFO) {
        return (charPointer="REG_INFO");
    } else if (packet.Type == INFO_REJ) {
        return (charPointer = "INFO_REJ");
    }
    return NULL;
}

char* getTypeOfPacketTCP(TCP packet) {
    char* charPointer;
    if (packet.Type == SEND_DATA) {
        return (charPointer="SEND_DATA");
    } else if (packet.Type == DATA_ACK) {
    return (charPointer="DATA_ACK");
    } else if (packet.Type == DATA_NACK) {
    return (charPointer="DATA_NACK");
    } else if (packet.Type == DATA_REJ) {
    return (charPointer="DATA_REJ");
    } else if (packet.Type == SET_DATA) {
    return (charPointer="SET_DATA");
    } else if (packet.Type == GET_DATA) {
    return (charPointer="GET_DATA");
    }
    return NULL;
}

//  Searches for the element id. If it's a valid id, returns the index of the Element array. If not, returns -1
int searchElement(char* elemId) {
    for (int i=0; i < elementsNumber; i++) {
        if (strcmp(clientData.Elements[i]->Id, elemId) == 0) {
            return i;
        }
    }
    return -1;
}

//  Gets the element value of the element id specified
char* getElementValue(char* elementId) {
    int elementIndex = searchElement(elementId);
    char* elementValue = malloc(sizeof(char)*16);
    strcpy(elementValue, clientData.Elements[elementIndex]->Data);
    return elementValue;
}

//  Gets the time information in packet format
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

//  Returns 0 if the element id entered is output type or 1 if it's input type
int getElementType (char* elementId) {
    if (strcmp(&elementId[strlen(elementId) - 1], "O") == 0) {
        return 0;
    } else {
        return 1;
    }
}

//          FORMATTING FUNCTIONS

void debugMsg() {
    printf(debugColorBold "[DEBUG]\t=>\t" debugColor);
}

void infoMsg(char text[]) {
    printf(whiteBold "[INFO]\t=>\t" white "%s" resetColor, text);
}

void infoFormat() {
    printf(whiteBold "[INFO]\t=>\t" white);
}

void errorMsg() {
    printf(errorColorBold "[ERROR]\t=>\t" errorColor);
}

void okMsg() {
    printf(greenBold "[OK]\t=>\t" green);
}