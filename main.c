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

#define BUFFER_SIZE 140 // Maximum number of chars in chat message

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
    regfree(&regex);
}

void server(){
 // todo figure out if we are inputting our own ip and port or if we are using the default
 // 127.0.0.1 and 8080


}

void client(int port, char* ip){
    if (port < 0 || port > 65535){
        printf("Invalid port number\n");
        exit(1);
    }
    printf("port is :%d and the ip is: %s\n", port, ip);

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




