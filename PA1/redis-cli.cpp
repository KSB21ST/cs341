#include <cstdio>
#include <stdio.h>
#include <memory.h>
#include <netdb.h>
#include <iostream>
#include <map>
#include <string>
#include <sstream>
#include<vector>
#include<math.h>
#include "common.hpp"
using namespace std;

// int total = 0;

int parse_line(string command, int sock, char *buf){
    // cout << "inside command: " << command << endl;
    string t_str;
    int previous =0;
    int current=0;
    // char buf[1024];
    current= command.find(' ');
    string arg1=command.substr(previous,current);
if(arg1.find("PING") != string::npos || arg1.find("ping") != string::npos){
        int left = command.length() - 7;
        if(left > 0){
            string arg2 = command.substr(6, left);
            sprintf(buf, "*2\r\n$4\r\nPING\r\n$%d\r\n%s\r\n", left, arg2.c_str());
        }else{
            char *a = "*1\r\n$4\r\nPING\r\n";
            sprintf(buf, "*1\r\n$4\r\nPING\r\n", strlen("*1\r\n$4\r\nPING\r\n"));
        }
        return 0;
    }else if(arg1.find("GET") != string::npos || arg1.find("get") != string::npos){
        previous =0;
        current=0;
        vector<string> x;
        x.clear();
   
        current= command.find(' ');
        while(current!= string::npos){
            string substring=command.substr(previous,current-previous);
            x.push_back(substring);
            previous = current+1;
            current=command.find(' ', previous);
        }
        x.push_back(command.substr(previous,current-previous));
        
        memset(buf, 0x00, BUFSIZE);
        sprintf(buf, "*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n", x[1].length(), x[1].c_str());
    }else if(arg1.find("SET") != string::npos || arg1.find("set") != string::npos){
        previous =0;
        current=0;
        vector<string> x;
        x.clear();
   
        current= command.find(' ');
        while(current!= string::npos){
            string substring=command.substr(previous,current-previous);
            x.push_back(substring);
            previous = current+1;
            current=command.find(' ', previous);
        }
        x.push_back(command.substr(previous,current-previous));
        
        x[2].erase(0, 1);
        x[x.size()-1].erase(x[x.size()-1].length()-1);
        string arg_s = x[2];
        for(int i=3;i<x.size();i++){ 
            arg_s += " " + x[i];
        }
        int p = 0;
        int c = 0;
        int cnt = 0;
        string tmp = "";
        c = arg_s.find("\\");
        while(c!= string::npos){
            cnt++;
            tmp += arg_s.substr(p, c-p) + "\n";
            p = c + 2; // or 2?
            c = arg_s.find("\\", p);
        }
        tmp += arg_s.substr(p);

        int arg_s_len = arg_s.length();
        
        arg_s_len -= cnt;

        sprintf(buf, "*3\r\n$3\r\nSET\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", x[1].length(), x[1].c_str(), arg_s_len, tmp.c_str());
        return 2;
    }else if(arg1.find("STRLEN") != string::npos || arg1.find("strlen") != string::npos ){
        previous =0;
        current=0;
        vector<string> x;
        x.clear();
   
        current= command.find(' ');
        while(current!= string::npos){
            string substring=command.substr(previous,current-previous);
            x.push_back(substring);
            previous = current+1;
            current=command.find(' ', previous);
        }
        x.push_back(command.substr(previous,current-previous));
        
        memset(buf, 0x00, BUFSIZE);
        sprintf(buf, "*2\r\n$6\r\nSTRLEN\r\n$%d\r\n%s\r\n", x[1].length(), x[1].c_str());
        return 3;
    }else if(arg1.find("DEL") != string::npos || arg1.find("del") != string::npos){
        previous =0;
        current=0;
        vector<string> x;
        x.clear();
   
        current= command.find(' ');
        while(current!= string::npos){
            string substring=command.substr(previous,current-previous);
            x.push_back(substring);
            previous = current+1;
            current=command.find(' ', previous);
        }
        x.push_back(command.substr(previous,string::npos));
        
        memset(buf, 0x00, BUFSIZE);
        string n = "*" + to_string(x.size()) + "\r\n" + "$" 
        + "3" + "\r\n" + "DEL"+ "\r\n" + "$" 
        + to_string(x[1].length()) + "\r\n" + x[1] + "\r\n";
        for(int i=2;i<x.size();i++){
            n += "$" + to_string(x[i].length()) + "\r\n" + x[i] + "\r\n";
        }
        sprintf(buf, n.c_str(), strlen(n.c_str()));
        return 4;
    }else if(arg1.find("EXISTS") != string::npos || arg1.find("exists") != string::npos){
        previous =0;
        current=0;
        vector<string> x;
        x.clear();
   
        current= command.find(' ');
        while(current!= string::npos){
            string substring=command.substr(previous,current-previous);
            x.push_back(substring);
            previous = current+1;
            current=command.find(' ', previous);
        }
        x.push_back(command.substr(previous,string::npos));
        
        memset(buf, 0x00, BUFSIZE);
        string n = "*" + to_string(x.size()) + "\r\n" + "$" 
        + "6" + "\r\n" + "EXISTS"+ "\r\n" + "$" 
        + to_string(x[1].length()) + "\r\n" + x[1] + "\r\n";
        for(int i=2;i<x.size();i++){
            n += "$" + to_string(x[i].length()) + "\r\n" + x[i] + "\r\n";
        }
        sprintf(buf, n.c_str(), strlen(n.c_str()));
        return 5;
    }
}

int parse_line_r(string command, int sock){
    string t_str;
    int previous =0;
    int current=0;
    char buf[1024];
    current= command.find("\r\n");
    string arg1=command.substr(previous, current);
    if(arg1.find('+') != string::npos || arg1.find(':') != string::npos){
        arg1.erase(0, 1);
        printf("%s\n", arg1.c_str());
        return 0;
    }else if(arg1.find('$') != string::npos){
        arg1.erase(0, 1);
        int len = stoi(arg1);
        return len;
    }
    return 0;

}



int main(int argc, char *argv[])
{
    struct hostent *he;
    struct sockaddr_in addr;
    if((he = gethostbyname(argv[3])) == NULL) {
        fprintf(stderr, "%s는 등록되지 않은 서버명입니다.\n", argv[3]);
        return -1; 
    }

    int sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    memset(&addr, 0x00, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr.s_addr, he->h_addr, he->h_length);
    addr.sin_port = htons(SERVER_PORT);
    // addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (sock == -1) {
        perror("Socket creation error");
        return EXIT_FAILURE;
    }

    if (connect(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("Connection error");
        close(sock);
        return EXIT_FAILURE;
    }

    char *buf = (char *)malloc(sizeof(char)*1024);
    while(sw){
        int remain = strlen(buf);
        int temp = 0;
        temp = read(0, &buf[remain], BUFSIZE-1-remain); // read from txt file... have to parse
        if(temp == BUFSIZE-1-remain){
            sw = 1;
        }else{
            sw = 0;
        }

        string str=buf;

        if(remain + temp != str.length()){ // there is a '\0'
            b_sw = 1;
            // cout << temp << str.length()<<endl;
        }
        int previous =0;
        int current=0;
        vector<string> x;
        x.clear();
        current= str.find("\n");
        while(current!=std::string::npos){
            std::string substring=str.substr(previous,current-previous);
            x.push_back(substring);
            previous = current + 1;
            current=str.find("\n",previous);
        }
        int n_cmd = -1;
        char t_buf[1024];
        x.push_back(str.substr(previous,str.length()));

            parse_line(x[0], sock, t_buf); 
            string arguments = t_buf;
            for(int i1=1;i1<x.size();i1++){
                // cout << x[i1] << endl;
                if((i1 + 1) == x.size() && sw){
                    continue;
                }
                parse_line(x[i1], sock, t_buf); 
                string temp_ = t_buf;
                arguments += "\n" + temp_;
            }

            // cout << arguments << "\n" << endl;

            int t_w = write(sock, arguments.c_str(), strlen(arguments.c_str()));
            int temp2 = 0;
            memset(buf, 0x00, BUFSIZE);

            temp2 = read(sock, buf, BUFSIZE-1);

            // if(temp2 >= BUFSIZE-1){
            //     b_sw = 1;
            // }else{
            //     printf("b_sw is not turning on : %d\n", temp2);
            //     printf("\'\'\'%s\'\'\'", buf);
            // }
            // cout << "\n" << "after read: " << buf << endl;
            std::string str_r=buf;
            int previous_r = 0;
            int current_r = 0;
            vector<string> y;
            y.clear();
            current_r= str_r.find("\n");
            while(current_r!=std::string::npos){
                std::string substring=str_r.substr(previous_r,current_r-previous_r);
                std::string subsub = substring.substr(substring.length()-1, 1);
                if(strcmp(subsub.c_str(), "a") != 0){
                    substring.erase(substring.length() -1);
                }
                y.push_back(substring);
                previous_r = current_r + 1;
                current_r=str_r.find("\n",previous_r);
            }
            y.push_back(str_r.substr(previous_r,str_r.length()));
            int n_cmd_r = -2;

            for(int i1=0;i1<y.size();i1++){
                n_cmd_r = parse_line_r(y[i1], sock); 
                if(n_cmd_r >= 1023){
                    b_sw = 1;
                    break;
                }else{
                    // printf("not a binary....\n");
                }
                if(n_cmd_r > 0){
                    i1++;
                    int index = i1 + 1;
                    while(y[i1].length() < n_cmd_r && (index+1) < y.size()){
                        y[i1] += "\n" + y[index];
                        index++;
                    }

                    string tmp = y[i1].substr(0, n_cmd_r);
                    
                    printf("%s\n", tmp.c_str());

                    i1 = index - 1;
                    
                }else if(n_cmd_r == -1){
                    printf("\n");
                }
                n_cmd_r = -2;
            }
            if(b_sw){
                total = 0;
                memcpy(&w_buf[total], &buf[(int)log10(n_cmd_r)+1+3], temp2-(int)log10(n_cmd_r)-1-3);
                total += temp2-(int)log10(n_cmd_r)-1-3;
                int ofs = (int)log10(n_cmd_r)+1+3;

                printf("%s", &buf[ofs]);
                int printed = strlen(&buf[0]);
                while(printed < temp2){
                    printf("%c", 0);
                    printed += 1;
                    printf("%s", &buf[printed]);
                    printed += strlen(&buf[printed]);
                }

                int backup = n_cmd_r;
                n_cmd_r -= total;
            

                while(n_cmd_r > 0){
                    memset(buf, 0x00, BUFSIZE);
                    temp2 = read(sock, buf, BUFSIZE-1);
                    n_cmd_r -= temp2;
                    if (n_cmd_r < 0){ //EOF
                        int printed = strlen(buf);
                        if(printed == temp2){
                            string parse = buf;
                            parse = parse.substr(0, parse.length()-2);
                            memset(buf, 0x00, BUFSIZE);
                            memcpy(buf, parse.c_str(), parse.length());
                            // buf[strlen(buf)-2] = '\0';
                            printf("%s\n", buf);
                            break;
                        }
                        printf("%s", &buf[0]);
                        while(true){
                            printf("%c", 0);
                            printed += 1;
                            if (printed + strlen(&buf[printed]) >= temp2){
                                string parse = &buf[printed];
                                parse = parse.substr(0, parse.length()-2);
                                memset(buf, 0x00, BUFSIZE);
                                memcpy(buf, parse.c_str(), parse.length());
                                // buf[strlen(buf)-2] = '\0';
                                printf("%s\n", buf);
                                break;
                            }
                            printf("%s", &buf[printed]);
                            printed += strlen(&buf[printed]);
                        }
                        break;
                    }
                    printf("%s", &buf[0]);
                    int printed = strlen(buf);
                    while(printed < temp2){
                        printf("%c", 0);
                        printed += 1;
                        if(printed >= temp2){
                            break;
                        }
                        printf("%s", &buf[printed]);
                        printed += strlen(&buf[printed]);
                    }
                    total += printed;
                }

                break;
            }else{
                // printf("it's not binary!!");
            }

        if(sw){
            memset(buf, 0x00, BUFSIZE);
            memcpy(buf, x[x.size()-1].c_str(), x[x.size()-1].length()); //마지막거 옮기기
        }
    }
    free(buf);
    close(sock);
    return 0;
}