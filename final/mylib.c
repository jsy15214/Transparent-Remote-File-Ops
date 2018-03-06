/**
The client side code. The client packs parameter and sent rpcs to the server
side and then waits for reply.
*/

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <err.h>
#include <errno.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "../include/dirtree.h"

#define MAXMSGLEN 100
#define OPENMSG 0
#define CLOSEMSG 1
#define READMSG 2
#define WRITEMSG 3
#define LSEEKMSG 4
#define STATMSG 5
#define UNLINKMSG 6
#define GETDIRENTRIESMSG 7
#define GETDIRTREEMSG 8

// The following line declares a function pointer with the same prototype as the open function.  
int (*orig_open)(const char *pathname, int flags, ...);  // mode_t mode is needed when flags includes O_CREAT
int (*orig_close)(int fildes);
ssize_t (*orig_read)(int fildes, void *buf, size_t nbyte);
ssize_t (*orig_write)(int fildes, const void *buf, size_t nbyte);
off_t (*orig_lseek)(int fildes, off_t offset, int whence);
int (*orig_stat)(int ver,const char *restrict_path, struct stat *restrict_buf);
int (*orig_unlink)(const char *path);
ssize_t (*orig_getdirentries)(int fd, char *buf, size_t nbytes , off_t * basep);
struct dirtreenode* (*orig_getdirtree)(const char *path);
void (*orig_freedirtree)(struct dirtreenode* dt);

//socket number
int sockfd;
//buffer to store entire pathname for getdirtree
char *resbuf;

//protocol header
typedef struct {
    int operator;
    size_t stub_size;
} general_stub;

//protocol content
typedef struct {
    int a;
    int b;
    int c;
    off_t offset;
    char str[];
} operator_stub;

/**
Takes serialized message, send the request
and return the actual return value of the operation
performed on the server side.
*/
int sendRequest(char *reqst, int length) {
	char buf[MAXMSGLEN+1];
	int rv;

	// send message to server
    send(sockfd, reqst, length, 0);  // send message; should check return value
    
    // get message back
    rv = recv(sockfd, buf, sizeof(general_stub), 0);   // get message
    if (rv<0) err(1,0);         // in case something went wrong

    //make header
    general_stub *g_resp = malloc(sizeof(general_stub));
    memcpy(g_resp, buf, sizeof(general_stub));
    
    //deserialize ack
    char *op_respmsg = malloc(g_resp -> stub_size);
    rv = recv(sockfd, op_respmsg, g_resp -> stub_size, 0);
    free(g_resp);

    operator_stub *op_resp = (operator_stub *)op_respmsg;
    errno = op_resp -> b;
    int res = op_resp -> a;
    free(op_resp);
    
    return res;
    //printf("client got messge: %s\n", buf);
}

/**
Takes serialized message, send the request
and return the actual ack without de-serializing.
*/
operator_stub *sendBufRequest(char *reqst, int length) {
    char buf[MAXMSGLEN+1];
    int rv, rv2;
    // send message to server
    send(sockfd, reqst, length, 0);  // send message; should check return value
    
    // get message back
    rv = recv(sockfd, buf, sizeof(general_stub), 0);   // get message
    if (rv<0) err(1,0);         // in case something went wrong

    //deserialize ack
    general_stub *g_resp = malloc(sizeof(general_stub));
    memcpy(g_resp, buf, sizeof(general_stub));
    
    //deserialize ack
    char *op_respmsg = malloc(g_resp -> stub_size);
    int num_byte = 0;
    while (num_byte < g_resp -> stub_size) {
        rv2 = recv(sockfd, op_respmsg + num_byte, g_resp -> stub_size, 0);
        num_byte += rv2;
    }
    free(g_resp);
    
    return (operator_stub *)op_respmsg;
}

/**
Given the header and the content packet, pack them to a
string to be sent to server.
*/
char *serialize(general_stub *g_reqst, operator_stub *op_reqst) {
    char *reqst = malloc(sizeof(general_stub) + g_reqst -> stub_size);
    memcpy(reqst, g_reqst, sizeof(general_stub));
    memcpy(reqst + sizeof(general_stub), op_reqst, g_reqst -> stub_size);
    return reqst;
}

int open(const char *pathname, int flags, ...) {
	mode_t m=0;
	if (flags & O_CREAT) {
		va_list a;
		va_start(a, flags);
		m = va_arg(a, mode_t);
		va_end(a);
	}

    //pack content
    int stub_size = sizeof(operator_stub) + strlen(pathname) + 1;
    operator_stub *op_reqst = malloc(stub_size);
    op_reqst -> a = flags;
    op_reqst -> b = m;
    strncpy(op_reqst -> str, pathname, strlen(pathname) + 1);

    //pack header
    general_stub *g_reqst = malloc(sizeof(general_stub));
    g_reqst -> operator = OPENMSG;
    g_reqst -> stub_size = stub_size;

    //serialize
    char *reqst = serialize(g_reqst, op_reqst);
    free(op_reqst);
    free(g_reqst);

    //sent request and wait for response
	int res = sendRequest(reqst, sizeof(general_stub) + stub_size);
    free(reqst);

	return res;
}

int close(int fildes){
    //pack content
    operator_stub *op_reqst = malloc(sizeof(operator_stub));
    op_reqst -> a = fildes;

    //pack header
    general_stub *g_reqst = malloc(sizeof(general_stub));
    g_reqst -> operator = CLOSEMSG;
    g_reqst -> stub_size = sizeof(operator_stub);

    //serialize
    char *reqst = serialize(g_reqst, op_reqst);
    free(op_reqst);
    free(g_reqst);

    //sent request and wait for response
    int res = sendRequest(reqst, sizeof(general_stub) + sizeof(operator_stub));
    free(reqst);

    return res;
}

ssize_t read(int fildes, void *buf, size_t nbyte){
    //pack content
    int stub_size = sizeof(operator_stub);
    operator_stub *op_reqst = malloc(stub_size);
    op_reqst -> a = fildes;
    op_reqst -> b = nbyte;

    //pack header
    general_stub *g_reqst = malloc(sizeof(general_stub));
    g_reqst -> operator = READMSG;
    g_reqst -> stub_size = stub_size;

    //serialize
    char *reqst = serialize(g_reqst, op_reqst);
    free(op_reqst);
    free(g_reqst);

    //sent request and wait for response, got reply and de-serialize
    operator_stub *bufres = 
    sendBufRequest(reqst, sizeof(general_stub) + stub_size);
    free(reqst);
    int res = bufres -> a;
    errno = bufres -> b;
    memcpy(buf, (void *)bufres->str, nbyte);
    free(bufres);

    return res;
}

ssize_t write(int fildes, const void *buf, size_t nbyte){
    //pack content
    int stub_size = sizeof(operator_stub) + nbyte + 1;
    operator_stub *op_reqst = malloc(stub_size);
    op_reqst -> a = fildes;
    op_reqst -> b = nbyte;
    memcpy(op_reqst -> str, buf, nbyte);

     //pack header
    general_stub *g_reqst = malloc(sizeof(general_stub));
    g_reqst -> operator = WRITEMSG;
    g_reqst -> stub_size = stub_size;

    //serialize
    char *reqst = serialize(g_reqst, op_reqst);
    free(op_reqst);
    free(g_reqst);

    //sent request and wait for response
    int res = sendRequest(reqst, sizeof(general_stub) + stub_size);
    free(reqst);

    return res;
}

off_t lseek(int fildes, off_t offset, int whence){
    //pack content
    int stub_size = sizeof(operator_stub);
    operator_stub *op_reqst = malloc(stub_size);
    op_reqst -> a = fildes;
    op_reqst -> b = offset;
    op_reqst -> c = whence;

    //pack header
    general_stub *g_reqst = malloc(sizeof(general_stub));
    g_reqst -> operator = LSEEKMSG;
    g_reqst -> stub_size = stub_size;

    //serialize
    char *reqst = serialize(g_reqst, op_reqst);
    free(op_reqst);
    free(g_reqst);

    //sent request and wait for response
    int res = sendRequest(reqst, sizeof(general_stub) + stub_size);
    free(reqst);

    return res;
}

int __xstat(int ver,const char *restrict_path, struct stat *restrict_buf){
    //pack content
    int stub_size = sizeof(operator_stub) 
    + strlen(restrict_path) + sizeof(struct stat) + 1;
    operator_stub *op_reqst = malloc(stub_size);
    op_reqst -> a = ver;
    op_reqst -> b = strlen(restrict_path) + 1;
    memcpy(op_reqst -> str, restrict_path, op_reqst -> b);
    memcpy(op_reqst -> str + op_reqst -> b, restrict_buf, sizeof(struct stat));

    //pack header
    general_stub *g_reqst = malloc(sizeof(general_stub));
    g_reqst -> operator = STATMSG;
    g_reqst -> stub_size = stub_size;

    //serialize
    char *reqst = serialize(g_reqst, op_reqst);
    free(op_reqst);
    free(g_reqst);

    //sent request and wait for response
    int res = sendRequest(reqst, sizeof(general_stub) + sizeof(operator_stub));
    free(reqst);

    return res;
}

int unlink(const char *path){
    //pack content
    int stub_size = sizeof(operator_stub) + strlen(path) + 1;
    operator_stub *op_reqst = malloc(stub_size);
    memcpy(op_reqst -> str, path, strlen(path) + 1);

    //pack header
    general_stub *g_reqst = malloc(sizeof(general_stub));
    g_reqst -> operator = UNLINKMSG;
    g_reqst -> stub_size = stub_size;

    //serialize
    char *reqst = serialize(g_reqst, op_reqst);
    free(op_reqst);
    free(g_reqst);

    //sent request and wait for response
    int res = sendRequest(reqst, sizeof(general_stub) + stub_size);
    free(reqst);

    return res;
}

ssize_t getdirentries(int fd, char *buf, size_t nbytes , off_t * basep){
    //pack content
    int stub_size = sizeof(operator_stub);
    operator_stub *op_reqst = malloc(stub_size);
    op_reqst -> a = fd;
    op_reqst -> b = nbytes;
    op_reqst -> offset = *basep;

    //pack header
    general_stub *g_reqst = malloc(sizeof(general_stub));
    g_reqst -> operator = GETDIRENTRIESMSG;
    g_reqst -> stub_size = stub_size;

    //serialize
    char *reqst = serialize(g_reqst, op_reqst);
    free(op_reqst);
    free(g_reqst);

    //sent request and wait for response, got reply and de-serialize
    operator_stub *bufres = 
    sendBufRequest(reqst, sizeof(general_stub) + stub_size);
    free(reqst);
    ssize_t res = bufres -> a;
    errno = bufres -> b;
    *basep = bufres -> offset;
    memcpy(buf, bufres -> str, nbytes);
    free(bufres);
    return res;
}

/**
Takes the flag indicating whether the current nodes is a root.
Return the root of the dir-tree constructed.
*/
struct dirtreenode* convert(int isRoot) {
    char *name;
    int i;

    //set root
    struct dirtreenode* dt = malloc(sizeof(struct dirtreenode));

    //set root name
    if (isRoot > 0) {
        name = strtok(resbuf, "\n");
    } else {
        name = strtok(NULL, "\n");
    } 
    dt -> name = name;

    //set number of subdirectories
    int num_subdirs = atoi(strtok(NULL, "\n"));
    dt -> num_subdirs = num_subdirs;

    //recursively construct sub-directories
    if (num_subdirs > 0) {
        dt -> subdirs = malloc(num_subdirs * sizeof(struct dirtreenode));
        for (i = 0; i < num_subdirs; i ++) {
            dt -> subdirs[i] = convert(0);
        }
    } else {
        dt -> subdirs = NULL;
    }
    return dt;
}

struct dirtreenode* getdirtree(const char *path){
    //pack content
    int stub_size = sizeof(operator_stub) + strlen(path) + 1;
    operator_stub *op_reqst = malloc(stub_size);
    memcpy(op_reqst -> str, path, strlen(path) + 1);

    //pack header
    general_stub *g_reqst = malloc(sizeof(general_stub));
    g_reqst -> operator = GETDIRTREEMSG;
    g_reqst -> stub_size = stub_size;

    //serialize
    char *reqst = serialize(g_reqst, op_reqst);
    free(op_reqst);
    free(g_reqst);

    //sent request and wait for response, got reply and de-serialize
    operator_stub *bufres = 
    sendBufRequest(reqst, sizeof(general_stub) + stub_size);
    free(reqst);
    errno = bufres -> b;
    resbuf = bufres -> str;

    //construct the tree based on returned buffer
    struct dirtreenode* res = convert(1);
    free(bufres -> str);
    free(bufres);
    return res;
}

void freedirtree(struct dirtreenode* dt){
    orig_freedirtree(dt);
}

// This function is automatically called when program is started
void _init(void) {
	// set function pointer orig_open to point to the original open function
	orig_open = dlsym(RTLD_NEXT, "open");
	orig_close = dlsym(RTLD_NEXT, "close");
	orig_read = dlsym(RTLD_NEXT, "read");
	orig_write = dlsym(RTLD_NEXT, "write");
	orig_lseek = dlsym(RTLD_NEXT, "lseek");
	orig_stat = dlsym(RTLD_NEXT, "__xstat");
	orig_unlink = dlsym(RTLD_NEXT, "unlink");
	orig_getdirentries = dlsym(RTLD_NEXT, "getdirentries");
	orig_getdirtree = dlsym(RTLD_NEXT, "getdirtree");
	orig_freedirtree = dlsym(RTLD_NEXT, "freedirtree");

	char *serverip;
    char *serverport;
    unsigned short port;
    int rv;
    struct sockaddr_in srv;
    
    // Get environment variable indicating the ip address of the server
    serverip = getenv("server15440");
    if (!serverip) {
        serverip = "127.0.0.1";
    }
    
    // Get environment variable indicating the port of the server
    serverport = getenv("serverport15440");
    if (serverport) fprintf(stderr, "Got environment variable serverport15440: %s\n", serverport);
    else {
        fprintf(stderr, "Environment variable serverport15440 not found.  Using 15440\n");
        serverport = "15440";
    }
    port = (unsigned short)atoi(serverport);
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);   // TCP/IP socket
    if (sockfd<0) err(1, 0);            // in case of error
    
    // setup address structure to point to server
    memset(&srv, 0, sizeof(srv));           // clear it first
    srv.sin_family = AF_INET;           // IP family
    srv.sin_addr.s_addr = inet_addr(serverip);  // IP address of server
    srv.sin_port = htons(port);         // server port
 
 	// actually connect to the server
    rv = connect(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
    if (rv<0) err(1,0);

    fprintf(stderr, "Init mylib\n");
}

void _fini(void) {
	// close socket
	orig_close(sockfd);
}