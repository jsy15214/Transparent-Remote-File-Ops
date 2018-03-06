/**
The server side code. The server receives rpcs, deserializes the packets and
use the parameters sent by the client to handle open, close, read, write, 
lseek, stat, unlink, getdirentries and getdirtree.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <math.h>
#include "../include/dirtree.h"

#define OPENMSG 0
#define CLOSEMSG 1
#define READMSG 2
#define WRITEMSG 3
#define LSEEKMSG 4
#define STATMSG 5
#define UNLINKMSG 6
#define GETDIRENTRIESMSG 7
#define GETDIRTREEMSG 8
#define MAXMSGLEN 100

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

//buffer to store entire pathname for getdirtree
char *resbuf;

/**
Takes the operation indicator, the return value after performing actual operation, 
pack response stub and send the response to the client.
*/
void sendResponse(int sessfd, int op_num, int res) {
	//pack content
	operator_stub *op_resp = malloc(sizeof(operator_stub));
	op_resp -> a = res;
	op_resp -> b = errno;

	//pack header
	general_stub *g_resp = malloc(sizeof(general_stub));
	g_resp -> operator = op_num;
	g_resp -> stub_size = sizeof(operator_stub);

	//write to string
	size_t resp_length = sizeof(general_stub) + sizeof(operator_stub) + 1;
	char *resp = malloc(resp_length);
	memcpy(resp, g_resp, sizeof(general_stub));
	memcpy(resp + sizeof(general_stub), op_resp, sizeof(operator_stub));

	free(op_resp);
	free(g_resp);

	//send reply
	send(sessfd, resp, resp_length, 0);
	free(resp);
}

/**
Takes the operation indicator, the content packet, 
pack response stub and send the response to the client.
*/
void sendBufResponse(int sessfd, int op_num, 
	operator_stub *op_resp, int op_resp_size) {
	//pack header
	general_stub *g_resp = malloc(sizeof(general_stub));
	g_resp -> operator = op_num;
	g_resp -> stub_size = op_resp_size;

    //write to string
	size_t resp_length = sizeof(general_stub) + op_resp_size + 1;
	char *resp = malloc(resp_length);
	memcpy(resp, g_resp, sizeof(general_stub));
	memcpy(resp + sizeof(general_stub), op_resp, op_resp_size);

	free(op_resp);
	free(g_resp);

	//send reply
	send(sessfd, resp, resp_length, 0);
	free(resp);
}

void handle_open(int sessfd, operator_stub *vars) {
	const char* pathname = vars -> str;
	int res = open(pathname, vars -> a, vars -> b);
	sendResponse(sessfd, OPENMSG, res);
}

void handle_close(int sessfd, operator_stub *vars) {
	int res = close(vars -> a);
	sendResponse(sessfd, CLOSEMSG, res);
}

void handle_read(int sessfd, operator_stub *vars) {
	int num_byte = vars -> b;
	operator_stub *op_resp = malloc(sizeof(operator_stub) + num_byte);
	int res = read(vars -> a, (void *)op_resp -> str, num_byte);

	//pack content
	op_resp -> a = res;
	op_resp -> b = errno;

	sendBufResponse(sessfd, READMSG, op_resp, sizeof(operator_stub)+ num_byte);
}

void handle_write(int sessfd, operator_stub *vars) {
	int res = write(vars -> a, vars -> str, vars -> b);
	sendResponse(sessfd, WRITEMSG, res);
}

void handle_lseek(int sessfd, operator_stub *vars) {
	int res = lseek(vars -> a, vars -> b, vars -> c);
	sendResponse(sessfd, LSEEKMSG, res);
}

void handle_stat(int sessfd, operator_stub *vars) {
	int num_byte = vars -> b;
	char *pathname = malloc(num_byte);
	memcpy(pathname, vars -> str, num_byte);
	const char *pn = pathname;
	int res = __xstat(vars -> a, pn, (struct stat *)(vars -> str + num_byte));
	free(pathname);

	sendResponse(sessfd, STATMSG, res);
}

void handle_unlink(int sessfd, operator_stub *vars) {
	const void *pathname = vars -> str;
	int res = unlink(pathname);
	sendResponse(sessfd, UNLINKMSG, res);
}

void handle_getdirentries(int sessfd, operator_stub *vars) {
	int num_byte = vars -> b;
	char *pathname = malloc(num_byte);
	off_t *offset = &(vars -> offset);
	int res = getdirentries(vars -> a, pathname, num_byte, offset);

	//pack response content
	operator_stub *op_resp = malloc(sizeof(operator_stub) + num_byte + 1);
	op_resp -> a = res;
	op_resp -> b = errno;
	op_resp -> offset = *offset;
	memcpy(op_resp -> str, pathname, num_byte + 1);
	free(pathname);

    //pack header and send response
	sendBufResponse(sessfd, 
		GETDIRENTRIESMSG, op_resp, sizeof(operator_stub) + num_byte + 1);
}

/**
Takes the root of the tree, write the tree into a buffer
*/
void convert(struct dirtreenode *dt) {
	if (dt == NULL) {
		return;
	}

	//write the name of number of subdirectories into the buffer
	int i;
	int curbuf_length = strlen(dt -> name) + 4;
	if (dt -> num_subdirs > 9) {
		curbuf_length += (int)(log10(dt -> num_subdirs));
	}
	char *curbuf = malloc(curbuf_length);
	sprintf(curbuf, "%s\n%d\n", dt -> name, dt -> num_subdirs);

	strcat(resbuf, curbuf);

	//recursively write the subdirectories into the buffer
	if (dt -> num_subdirs > 0) {
		for (i = 0; i < dt -> num_subdirs; i ++) {
			convert(dt -> subdirs[i]);
		}
	}
}

void handle_getdirtree(int sessfd, operator_stub *vars) {
	//de-serialize request packet and perform getdirtree()
	char *pathname = vars -> str;
	const char *pn = pathname;
	struct dirtreenode *dt = getdirtree(pn);

	//write tree into the buffer
	resbuf = malloc(MAXMSGLEN - 10);
	resbuf[0] = '\0';
	convert(dt);

	//pack response content
	int nbytes = strlen(resbuf);
	operator_stub *op_resp = malloc(sizeof(operator_stub) + nbytes + 1);
	op_resp -> b = errno;
	memcpy(op_resp -> str, resbuf, nbytes + 1);
	free(resbuf);

	//send response
	sendBufResponse(sessfd, 
		GETDIRTREEMSG, op_resp, sizeof(operator_stub) + nbytes + 1);
}

int main(int argc, char**argv) {
	char *serverport;
	unsigned short port;
	int sockfd, sessfd, rv, i, rv2;
	struct sockaddr_in srv, cli;
	socklen_t sa_size;
	
	// Get environment variable indicating the port of the server
	serverport = getenv("serverport15440");
	if (serverport) port = (unsigned short)atoi(serverport);
	else port=15440;
	
	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);	// TCP/IP socket
	if (sockfd<0) err(1, 0);			// in case of error
	
	// setup address structure to indicate server port
	memset(&srv, 0, sizeof(srv));			// clear it first
	srv.sin_family = AF_INET;			// IP family
	srv.sin_addr.s_addr = htonl(INADDR_ANY);	// don't care IP address
	srv.sin_port = htons(port);			// server port

	// bind to our port
	rv = bind(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
	if (rv<0) err(1,0);
	
	// start listening for connections
	rv = listen(sockfd, 5);
	if (rv<0) err(1,0);
	
	int general_stub_length = sizeof(general_stub);

	// main server loop, handle clients one at a time, quit after 10 clients
	while(1) {
		// wait for next client, get session socket
		sa_size = sizeof(struct sockaddr_in);
		sessfd = accept(sockfd, (struct sockaddr *)&cli, &sa_size);
		if (sessfd<0) err(1,0);

		general_stub *stub = malloc(general_stub_length);

		// get messages and send replies to this client, until it goes away
		// first, read general stub
		while ( (rv2=recv(sessfd, stub, general_stub_length, 0)) > 0) {
			//create operation stub
			size_t stub_size = stub -> stub_size;
			char *buf = malloc(stub_size);

			size_t byte_read = 0;
			while (byte_read < stub_size) {
				//then, read operation stub
				rv2 = recv(sessfd, buf + byte_read, stub_size, 0);
				byte_read += rv2;
			}
			int operator = stub -> operator;
			if (operator == LSEEKMSG) {
				operator_stub *vars = (operator_stub *) buf;
				handle_lseek(sessfd, vars);
			} else if (operator == OPENMSG){
				operator_stub *vars = (operator_stub*) buf;
				handle_open(sessfd, vars);
			} else if (operator == CLOSEMSG){
				operator_stub *vars = (operator_stub*) buf;
				handle_close(sessfd, vars);
			} else if (operator == READMSG){
				operator_stub *vars = (operator_stub*) buf;
				handle_read(sessfd, vars);
			} else if (operator == WRITEMSG){
				operator_stub *vars = (operator_stub*) buf;
				handle_write(sessfd, vars);
			} else if (operator == STATMSG){
				operator_stub *vars = (operator_stub*) buf;
				handle_stat(sessfd, vars);
			} else if (operator == UNLINKMSG){
				operator_stub *vars = (operator_stub*) buf;
				handle_unlink(sessfd, vars);
			} else if (operator == GETDIRENTRIESMSG){
				operator_stub *vars = (operator_stub*) buf;
				handle_getdirentries(sessfd, vars);
			} else if (operator == GETDIRTREEMSG){
				operator_stub *vars = (operator_stub*) buf;
				handle_getdirtree(sessfd, vars);
			} else {
				fprintf(stderr, "invalid operation");
			}

			free(buf);
		}

		free(stub);

		// either client closed connection, or error
		if (rv<0) err(1,0);
		close(sessfd);
	}
	
	//printf("server shutting down cleanly\n");
	// close socket
	close(sockfd);

	return 0;
}

