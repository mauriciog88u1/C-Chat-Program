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
//#include <cstring>

#define BUFFER_SIZE 140 // Maximum number of chars in chat message
#define CS456_PORT 3360 // Port number used for chat server
#define CS456_IP "127.0.0.1"

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

void server(){
    // todo figure out if we are inputting our own ip and port or if we are using the default
    // socket -> bind -> listen -> accept -> read/write -> close
    int sockfd, newsockfd,valread;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in serv_addr;

    printf("Welcome to Chat!\nWaiting for a connection on ip: %s and port: %d\n", CS456_IP, CS456_PORT);

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("Error opening socket");
        exit(1);
    }

    int optval = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) < 0){
        perror("Error setting socket options");
        exit(1);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(CS456_IP); // INADDR_ANY; is used when we dont want to bind to specfic ip
    serv_addr.sin_port = htons(CS456_PORT);

    if(bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
        perror("Error binding socket");
        exit(1);
    }

    if(listen(sockfd, 5) < 0){
        perror("Error listening on socket");
        exit(1);
    }

    if((newsockfd = accept(sockfd, (struct sockaddr *) NULL, NULL)) < 0){
        perror("Error accepting connection");
        exit(1);
    }
    printf("Found a Friend! You recieve first.\n");

    while(1){

        bzero(buffer, BUFFER_SIZE);
        valread = read(newsockfd, buffer, BUFFER_SIZE);
        if(valread < 0){
            perror("Error reading from socket");
            exit(1);
        }
        printf("Friend: %s", buffer);
        if(strncmp(buffer, "bye", 3) == 0){
            printf("Friend left the chat. Goodbye!\n");
            break;
        }
        bzero(buffer, BUFFER_SIZE);
        printf("You: ");
        fgets(buffer, BUFFER_SIZE, stdin);
        if(strncmp(buffer, "bye", 3) == 0){
            printf("Goodbye!\n");
            break;
        }
        if(write(newsockfd, buffer, BUFFER_SIZE) < 0){
            perror("Error writing to socket");
            exit(1);
        }
    }
    close(newsockfd);
    close(sockfd);

}

void client(int port, char* ip){
    if (port < 0 || port > 65535){
        printf("Invalid port number\n");
        exit(1);
    }

    int sockfd;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in serv_addr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Socket creation error\n");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, ip, &serv_addr.sin_addr)<=0) {
        printf("Invalid address/ Address not supported\n");
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("Connection Failed\n");
        exit(EXIT_FAILURE);
    }

    while(1) {
        printf("You: ");
        bzero(buffer, BUFFER_SIZE);
        fgets(buffer, BUFFER_SIZE, stdin);

        if (strlen(buffer) > BUFFER_SIZE - 1) {
            printf("Error: Message length exceeds 140 characters. Please enter a shorter message.\n");
            continue;
        }

        send(sockfd, buffer, strlen(buffer), 0);

        bzero(buffer, BUFFER_SIZE);
        int valread = read(sockfd, buffer, BUFFER_SIZE);
        if (valread < 0) {
            printf("Error reading from server\n");
            exit(EXIT_FAILURE);
        }

        printf("Server: %s", buffer);
    }

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
