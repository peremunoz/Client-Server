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
#define promptColor "\033[0;36m"
#define promptColorBold "\033[1;36m"
#define green "\033[0;32m"
#define greenBold "\033[1;32m"