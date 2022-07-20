#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <iostream>
#include <map>
#include <unistd.h>
#include<vector>

#define DESIRED_ADDRESS "127.0.0.1"
#define SERVER_PORT 6379
#define BUFSIZE 1024
// #define BUFSIZE 512

std::map<std::string, std::string> m;
std::vector<std::string> x;

std::map<std::string, std::vector<std::string> > x_bin;
// char w_buf[134217718]; //134217733
//2097152  //2097164
// char w_buf[4096];
char w_buf[2097152];
char c_buf[2097152];
// char w_buf[134217718];
char *m_buf;
int binary= 0;
int total = 0;
int left_ = 0;
int small = 0;
int sw = 1;
int b_sw = 0;