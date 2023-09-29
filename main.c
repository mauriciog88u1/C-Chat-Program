/*******************************************
* Group Name  : klk manin

* Member1 Name: Mauricio Gonzalez
* Member1 SIS ID: 832932983
* Member1 Login ID: maur88

* Member2 Name: XXXXXX
* Member2 SIS ID: XXXXXX
* Member2 Login ID: XXXXXX
********************************************/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
//#include <cstring>

#define BUFFER_SIZE 140 // Maximum number of chars in chat message
#define CS457_PORT 3360 // Port number used for chat server
#define VERSION 457

#if defined(__APPLE__)
#define OS "en0"
#else
#define OS "eno1"
#endif

struct __attribute__((packed)) packet {
    uint16_t version;
    uint16_t string_length;
    char message[BUFFER_SIZE];

};

int ipChecker(char *ip){
    if (ip == NULL)
        return 0;
    regex_t regex;
    int reti;
    reti = regcomp(&regex, "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$", REG_EXTENDED);
    reti = regexec(&regex, ip, 0, NULL, 0);
    if (!reti) {return 1;}
    else if (reti == REG_NOMATCH) {
        return 0;
    }
    else {
        fprintf(stderr, "Regex match failed\n");
        exit(1);
    }
}
char* get_ip_address() {
    int fd;
    struct ifreq ifr;
    char *ip = malloc(16 * sizeof(char));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, OS, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    strcpy(ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    return ip;
}

void initialize_socket(int *sockfd) {
    if ((*sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Error opening socket");
        exit(1);
    }
}

void set_socket_options(int sockfd) {
    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) < 0) {
        perror("Error setting socket options");
        exit(1);
    }
}

void bind_socket(int sockfd, struct sockaddr_in *serv_addr) {
    if (bind(sockfd, (struct sockaddr *) serv_addr, sizeof(*serv_addr)) < 0) {
        perror("Error binding socket");
        exit(1);
    }
}

void listen_on_socket(int sockfd) {
    if (listen(sockfd, 5) < 0) {
        perror("Error listening on socket");
        exit(1);
    }
}

int accept_connection(int sockfd) {
    int newsockfd;
    if ((newsockfd = accept(sockfd, (struct sockaddr *) NULL, NULL)) < 0) {
        perror("Error accepting connection");
        exit(1);
    }
    return newsockfd;
}

void handle_received_message(char *buffer, int *terminate_chat) {
    printf("Friend: %s", buffer);
    if (strncmp(buffer, "bye", 3) == 0) {
        printf("Friend left the chat. Goodbye!\n");
        *terminate_chat = 1;
    }
}

void handle_sent_message(char *buffer, int newsockfd, int *terminate_chat) {
    printf("You: ");
    fgets(buffer, BUFFER_SIZE, stdin);

    if (write(newsockfd, buffer, BUFFER_SIZE) < 0) {
        perror("Error writing to socket");
        exit(1);
    }
}

void deserialize_packet(char *buffer, struct packet *pkt) {
    pkt->version = ntohs(*(uint16_t*)(buffer));
    pkt->string_length = ntohs(*(uint16_t*)(buffer + 2));
    strncpy(pkt->message, buffer + 4, pkt->string_length);
}

void serialize_packet(struct packet *pkt, char *buffer) {
    uint16_t version = htons(pkt->version);
    uint16_t string_length = htons(pkt->string_length);

    memcpy(buffer, &version, sizeof(version));
    memcpy(buffer + sizeof(version), &string_length, sizeof(string_length));
    memcpy(buffer + sizeof(version) + sizeof(string_length), pkt->message, pkt->string_length);
}

void chat_loop(int newsockfd) {
    char buffer[BUFFER_SIZE];
    int valread;
    int terminate_chat = 0;

    while (!terminate_chat) {
        bzero(buffer, BUFFER_SIZE);
        valread = read(newsockfd, buffer, BUFFER_SIZE - 1);

        if (valread < 0) {
            perror("Error reading from socket");
            exit(1);
        }

        if (valread == BUFFER_SIZE - 1) {
            printf("Error: Input too long!\n");
            continue;
        }

        handle_received_message(buffer, &terminate_chat);
        if (terminate_chat) break;

        bzero(buffer, BUFFER_SIZE);
        handle_sent_message(buffer, newsockfd, &terminate_chat);
    }
}

void server_chat_loop(int newsockfd) {
    char buffer[BUFFER_SIZE + 4]; // 4 extra bytes for version and string length
    struct packet pkt;
    pkt.version = VERSION;

    while (1) {
        bzero(buffer, BUFFER_SIZE + 4);
        int bytes_received = recv(newsockfd, buffer, BUFFER_SIZE + 4, 0);
        if (bytes_received <= 0) {
            printf("Connection closed or error\n");
            exit(1);
        }

        // Deserialize the received packet
        deserialize_packet(buffer, &pkt);
        if (pkt.version != VERSION) {
            printf("Received packet with incorrect version. Ignoring.\n");
            continue;
        }
        pkt.message[pkt.string_length] = '\0';
        printf("Friend: %s", pkt.message);

        // Capture and send your message back to the client
        printf("You: ");
        bzero(pkt.message, BUFFER_SIZE);
        if (fgets(pkt.message, BUFFER_SIZE, stdin) == NULL) {
            printf("Error reading input\n");
            continue;
        }
        pkt.string_length = strlen(pkt.message);
        serialize_packet(&pkt, buffer);
        send(newsockfd, buffer, pkt.string_length + 4, 0);
    }
}

void server() {
    int sockfd, newsockfd;
    struct sockaddr_in serv_addr;

    printf("Welcome to Chat!\nWaiting for a connection on\n%s and port: %d\n", get_ip_address(), CS457_PORT);

    initialize_socket(&sockfd);
    set_socket_options(sockfd);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(get_ip_address());
    serv_addr.sin_port = htons(CS457_PORT);

    bind_socket(sockfd, &serv_addr);
    listen_on_socket(sockfd);

    newsockfd = accept_connection(sockfd);
    printf("Found a Friend! You receive first.\n");

    server_chat_loop(newsockfd);

    close(newsockfd);
    close(sockfd);
}

void validate_port(int port) {
    if (port < 0 || port > 65535) {
        printf("Invalid port number\n");
        exit(1);
    }
}

void connect_to_server(int *sockfd, struct sockaddr_in *serv_addr, char *ip, int port) {
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &serv_addr->sin_addr) <= 0) {
        printf("Invalid address/ Address not supported\n");
        exit(EXIT_FAILURE);
    }

    if (connect(*sockfd, (struct sockaddr *)serv_addr, sizeof(*serv_addr)) < 0) {
        printf("Connection Failed\n");
        exit(EXIT_FAILURE);
    }
}

void client_chat_loop(int sockfd) {
    char buffer[BUFFER_SIZE + 4];
    struct packet pkt;
    pkt.version = VERSION;

    while (1) {
        printf("You: ");
        bzero(pkt.message, BUFFER_SIZE);

        if (fgets(pkt.message, BUFFER_SIZE, stdin) == NULL) {
            printf("Error reading input\n");
            continue;
        }

        pkt.string_length = strlen(pkt.message);
        serialize_packet(&pkt, buffer);
        send(sockfd, buffer, pkt.string_length + 4, 0);

        bzero(buffer, BUFFER_SIZE + 4);
        int bytes_received = recv(sockfd, buffer, BUFFER_SIZE + 4, 0);
        if (bytes_received <= 0) {
            printf("Connection closed or error\n");
            exit(1);
        }

        deserialize_packet(buffer, &pkt);
        if (pkt.version != VERSION) {
            printf("Received packet with incorrect version. Ignoring.\n");
            continue;
        }
        pkt.message[pkt.string_length] = '\0';
        printf("Friend: %s", pkt.message);
    }
}



void client(int port, char *ip) {
    validate_port(port);

    printf("Connecting to server...\n");
    int sockfd;
    struct sockaddr_in serv_addr;

    initialize_socket(&sockfd);

    connect_to_server(&sockfd, &serv_addr, ip, port);

    printf("Connected!\nConnected to a friend! You send first.\n");

    client_chat_loop(sockfd);

    close(sockfd);
}



int main(int argc, char* argv[]){
    int isServer = 0; // Checks if the program is running as a server or client
    if(argc < 2){
        isServer = 1;
    }
    if(isServer == 1){
        server();
    } else {
        int port = 0;
        char* ip = "";
        int opt;
        while((opt = getopt(argc, argv, "p:s:h")) != -1){
            switch(opt){
                case 'p':
                    if(atoi(optarg) == 0){
                        printf("Port is not valid\n");
                        exit(1);
                    }
                    port = atoi(optarg);
                    break;
                case 's':
                    ip = optarg;
                    if (ipChecker(ip) == 0){
                        printf("Invalid ip address\n");
                        exit(1);
                    }
                    break;
                case 'h':
                    printf("Usage: ./chat [-p port] [-s server_ip]\n");
                    exit(0);
                default:
                    printf("<Port/IP> is not valid\n");
                    exit(1);
            }
        }
        client(port, ip);
    }


    return 0;
}

