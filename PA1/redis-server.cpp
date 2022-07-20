#include <cstdio>
#include <stdio.h>
#include <memory.h>
#include <netdb.h>
// #include <cstring>
// #include <string.h>
#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include<vector>
#include<math.h>
#include "common.hpp"
// using namespace std;

void print_hex(const char *buf, int size, char *t_buf){
    int index;
    for(index = 0; index<size; index++){
        if(index%16 == 0) {printf("\n");}
        printf("0x%02X ", buf[index]);
        sprintf(t_buf, "0x%02X", buf[index]);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    struct sockaddr_in addr;
    struct sockaddr_in client_addr;
    
    int sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);


    printf("Redis Server Running...\n");
    if (sock == 0) {
        perror("Socket creation error");
        return EXIT_FAILURE;
    }
    int b;
    if (b = bind(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("Bind error");
        close(sock);
        return EXIT_FAILURE;
    }

    int l;
    if (l = listen(sock, 100/*length of connections queue*/) == -1) {
        perror("Listen error");
        close(sock);
        return EXIT_FAILURE;
    }
    int min = 0;
    int client_sock;
    // char buf2[1050];
    // char buf2[4100];
    char buf2[2097170];
    // char buf2[134217740];
    while(true){
        socklen_t socklen = sizeof addr;
        socklen_t client_socklen = sizeof client_addr;
        client_sock = accept(sock, (struct sockaddr*) &client_addr, &client_socklen); /* 2nd and 3rd argument may be NULL. */
        if (client_sock == -1) {
            perror("Accept error");
            close(sock);
            return EXIT_FAILURE;
        }
        
        int written = 0;
        // int left = 0;
        int padding = 0;
        while(true){
            min++;
            char *buf = (char *)malloc(sizeof(char)*1024);
            memset(buf, 0x00, BUFSIZE);  
            int temp = read(client_sock, buf, BUFSIZE-1);

            if(temp <= 0){
                break;
            }

                
            int argc = 0;
            std::string str=buf;
            int previous =0;
            int current=0;
            x.clear();
            current= str.find("\r\n");
            while(current!=std::string::npos){
                std::string substring=str.substr(previous,current-previous);
                x.push_back(substring);
                previous = current+1;
                current=str.find("\r\n",previous);
            }
            x.push_back(str.substr(previous,current-previous));
            argc = x.size();

            for(int i=0;i<x.size();i++){
                std::cout << i << x[i] << std::endl;
            }

            int index = 1;
            if (x[index].find("$")==1){
                index++;
                if (x[index].find("PING") == 1 || x[index].find("ping") == 1) {
                    std::cout << "inside ping" << std::endl;
                    index++;
                    if(x.size() > 4){
                        std::string str10 = x[index+1];
                        int len = str10.length();
                        sprintf(buf, "$%d\r%s\r\n", len-1, str10.c_str());
                        std::string l1 = buf;
                        if(l1.length() > strlen(buf)){
                            write(client_sock, buf, l1.length());
                        }else{
                            write(client_sock, buf, strlen(buf));
                        }
                    }else{
                        memcpy(buf, "+PONG\r\n", sizeof("+PONG\r\n"));
                        write(client_sock, buf, strlen(buf));
                    }
                } else if (x[index].find("GET") == 1 || x[index].find("get") == 1) {
                    std::cout << "inside get" << std::endl;
                    if (binary > 0){
                        if(small > 0){
                            std::cout << "binary!" << std::endl;
                            sprintf(buf2, "$%d\r\n", total);
                            memcpy(buf2+3+1+(int)log10(total), w_buf, total);
                            memcpy(buf2+3+1+(int)log10(total)+ total, "\r\n", strlen("\r\n"));
                            binary = 0;
                            left_  = 0;
                            write(client_sock, buf2, total+3+(int)log10(total)+1+3+1);
                        }else{
                            printf("get, binary > 0, small > 0\n");
                            write(client_sock, "$5\r\nhello\r\n", strlen("$5\r\nhello\r\n"));
                        }
                    }else{
                        std::string str4 = x[index+2];
                        if (m.count(str4) == 0){
                            memcpy(buf, "$-1\r\n", sizeof("$-1\r\n"));
                            write(client_sock, buf, strlen(buf));
                        }else{
                            std::string t3 = m[str4];
                            int len = t3.length()-1;
                            // t3.erase(0);
                            sprintf(buf, "$%d\r%s\r\n", len, t3.c_str());
                            std::string l2 = buf;
                            if(l2.length() > strlen(buf)){
                                write(client_sock, buf, l2.length());
                            }else{
                            write(client_sock, buf, strlen(buf));
                            }
                        }
                    }
                } else if (x[index].find("SET") != std::string::npos || x[index].find("set") != std::string::npos) {
                    std::cout << "inside set" << std::endl;
                    std::cout << "x[index] " << x[index] << std::endl;
                    if(temp > strlen(buf) && binary == 0){
                        
                        std::string fsize = x[5].c_str();
                        fsize.erase(0, 2);
                        total = std::stoi(fsize);
                        if (total < 3097152){
                            small += 1;
                        }
                        binary = 1;

                        if(small > 0){
                            printf("small is bigger than 0\n");
                            left_ = temp - previous;
                            std::cout << "copied bytes: " << left_ << std::endl;
                            memcpy(&w_buf, &buf[previous+1], left_-1);
                            padding += left_-1;
                            memcpy(buf, "+OK\r\n", sizeof("+OK\r\n"));
                            write(client_sock, buf, strlen(buf));
                            continue;
                        }else{
                            // std::vector<std::string> x_m;
                            // std::string str_m = &buf[23+(int)log10(total)+1+2];
                            // x_m.push_back(str_m);
                            // int saved = str_m.length();
                            // while(saved < temp - (23+(int)log10(total)+1+2)){
                            //     saved += 1;
                            //     str_m = &buf[saved];
                            //     x_m.push_back(str_m);
                            //     saved += str_m.length();
                            // }

                            // x_bin[x[4]] = x_m;
                            printf("here??\n");
                            memset(buf, 0x00, BUFSIZE);
                            memcpy(buf, "+OK\r\n", sizeof("+OK\r\n"));
                            write(client_sock, buf, strlen(buf));
                            continue;
                        }
                    }else if(binary > 0){
                        printf("apple\n");
                        if (small > 0){
                            memcpy(&w_buf[padding], buf, temp);
                            padding += temp;
                            binary += 1;
                        }else{
                            memcpy(&m_buf[padding], buf, temp);
                            padding += temp;
                            binary += 1; 
                        }
                    }
                    else{
                        printf("banana\n");
                        index += 2;
                        std::string str1 = x[index];
                        for(int i = index + 3; i < argc-1; i++){
                            if(x[i].find("$") == 0 || x[i].find("+") == 0  || x[i].find("-") == 0  || x[i].find(":") == 0  || x[i].find("*") == 0 ){
                                char result[100];
                                strcpy(result, x[i].c_str());
                                strcat((char *)x[index+2].c_str(), "\n");
                                strcat((char *)x[index+2].c_str(), result);
                            }else{break;}
                        }
                        std::string str2 = x[index+2].c_str();
                        m[str1] = str2;
                        memcpy(buf, "+OK\r\n", sizeof("+OK\r\n"));
                        std::string l3 = buf;
                        if(l3.length() > strlen(buf)){
                            write(client_sock, buf, l3.length());
                        }else{
                            write(client_sock, buf, strlen(buf));

                        }
                    }
                } else if (x[index].find("strlen") == 1 || x[index].find("STRLEN") == 1) {
                    std::cout << "inside strlen" << std::endl;
                    std::string str3 = x[index + 2];
                    if(m.count(str3) == 0){  //nonexisting 경우
                        memcpy(buf, ":0\r\n", sizeof(":0\r\n"));
                        std::string l4 = buf;
                        if(l4.length() > strlen(buf)){
                            write(client_sock, buf, l4.length());
                        }else{
                        write(client_sock, buf, strlen(buf));
                        }
                    }else{
                        std::string t2 = m[str3];
                        int len = t2.length();
                        sprintf(buf, ":%d\r\n", len-1);
                        std::string l5 = buf;
                        if(l5.length() > strlen(buf)){
                            write(client_sock, buf, l5.length());
                        }else{
                        write(client_sock, buf, strlen(buf));
                        }
                    }
                } else if (x[index].find("del") == 1 || x[index].find("DEL") == 1) {
                    std::cout << "inside del" << std::endl;
                    int cnt = 0;
                    for(int i = index + 2; i < x.size()-1; i+=2){
                        std::string t_str = x[i];
                        if(m.count(t_str) > 0){
                            cnt++;
                            // for(int k = 0;k<m.count(t_str);k++){
                                std::map<std::string,std::string>::iterator it;
                                it=m.find(t_str);
                                m.erase (it);
                            // }
                        }else{
                            continue;
                        }
                    }
                    sprintf(buf, ":%d\r\n", cnt);
                    std::string l6 = buf;
                    if(l6.length() > strlen(buf)){
                        write(client_sock, buf, l6.length());
                    }else{
                        write(client_sock, buf, strlen(buf));
                    }
                } else if (x[index].find("EXISTS") == 1 || x[index].find("exists") == 1) {
                    int cnt = 0;
                    for(int i = index + 2; i < x.size()-1; i+=2){
                        std::string t_str = x[i];
                        if(m.count(t_str) > 0){
                            cnt++;
                        }else{
                            continue;
                        }
                    }
                    sprintf(buf, ":%d\r\n", cnt);
                    std::string l7 = buf;
                    if(l7.length() > strlen(buf)){
                        write(client_sock, buf, l7.length());
                    }else{
                        write(client_sock, buf, strlen(buf));
                    }
                }else if (x[index].find("COMMAND") == 1) {
                    std::cout << "inside command" << std::endl;
                    memcpy(buf, "+OK\r\n", sizeof("+OK\r\n"));
                    write(client_sock, buf, strlen(buf));
                }
            }
            else{
                if(small > 0){
                memcpy(&w_buf[padding], buf, temp);
                padding += temp;
                binary += 1;
                }else{
                    std::cout << "inside else" << std::endl;
                    // memcpy(&m_buf[padding], buf, temp);
                    // std::cout << "padding: " << padding << std::endl;
                    // std::cout << "copied bytes: " << temp-1 << std::endl;
                    // padding += temp;
                    // binary += 1;
                    memcpy(buf, "+OK\r\n", sizeof("+OK\r\n"));
                    write(client_sock, buf, strlen(buf));
                }
            }
            free(buf);
        }
    }
    close(sock);   
    return 0;
}