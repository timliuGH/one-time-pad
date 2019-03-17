/* This program should run in the background as a daemon as a server for
 * the client program otp_enc. It encrypts a message using a key, both sent
 * by the client, and returns the encrypted message.
 * USAGE: otp_enc_d port &
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#define RECV_BUFF_SIZE 1001
#define RECV_AMT 1000
#define MSG_SIZE 140000

/* Error function used for reporting issues */
void error(const char *msg) { perror(msg); exit(1); } 

int main(int argc, char *argv[])
{
	int listenSocketFD, newConnectionFD, portNumber, charsRead;
	socklen_t sizeOfClientInfo;
	char recvBuff[RECV_BUFF_SIZE];  /* Holds currently read data from client */
    char wholeMsg[MSG_SIZE];        /* Holds entire data from client */
    char *key;                      /* Holds cipher key */
    char *encrypted;                /* Holds encrypted message */
	struct sockaddr_in serverAddress, clientAddress;

    /* Check for usage and arguments */
	if (argc < 2)
    { 
        fprintf(stderr,"USAGE: %s port\n", argv[0]); 
        exit(1); 
    } 
	/* Set up the address struct for this process (the server) */
    /* Clear out the address struct */
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); 
    /* Get the port number, convert to an integer from a string */
	portNumber = atoi(argv[1]); 
    /* Create a network-capable socket */
	serverAddress.sin_family = AF_INET; 
    /* Store the port number */
	serverAddress.sin_port = htons(portNumber); 
    /* Any address if allowed for connection to this process */
	serverAddress.sin_addr.s_addr = INADDR_ANY; 

	/* Set up the socket */
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); /* Create the socket */
	if (listenSocketFD < 0) error("ERROR opening socket");

	/* Enable the socket to begin listening */
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) /* Connect socket to port */
		error("ERROR on binding");

    /* Flip the socket on - it can now receive up to 5 connections */
	listen(listenSocketFD, 5); 

    while (1) /* Continuously accept connections */
    {
        /* Accept a connection or block until one connects */
        /* Get size of address for the client that will connect */
        sizeOfClientInfo = sizeof(clientAddress); 

        /* Accept a connection */
        newConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); 
        if (newConnectionFD < 0) error("ERROR on accept");

        pid_t spawnpid = -5;        /* Hold pid of child process */
        int childExitStatus = -5;   /* For waitpid; holds exit status */
        spawnpid = fork();          /* Fork process to handle encryption */
        switch (spawnpid)
        {
            case -1:
                error("fork failed");
                break;
            case 0:
                /* Get entire message from otc_enc (ends in '.') */
                memset(wholeMsg, '\0', sizeof(wholeMsg));
                while (strstr(wholeMsg, ".") == NULL)
                {
                    /* Read new data from client */
                    memset(recvBuff, '\0', sizeof(recvBuff));
                    charsRead = recv(newConnectionFD, recvBuff, RECV_AMT, 0);
                    if (charsRead < 0) error("ERROR reading from socket");

                    /* Add newly read data to wholeMsg */
                    strcat(wholeMsg, recvBuff);
                }
                /* Check client is sending plaintext (starts with '@') */
                if (wholeMsg[0] != '@')
                {
                    /* Send "@." back to client as a rejection */
                    encrypted = malloc(2 * sizeof(char));
                    encrypted[0] = '@';
                    encrypted[1] = '.';
                    charsRead = send(newConnectionFD, encrypted, 2, 0);
                    if (charsRead != 2) error("ERROR writing to socket");

                    /* Free allocated memory to hold strings */
                    free(encrypted);

                    /* Close socket connected to client */
                    close(newConnectionFD);

                    /* Terminate forked process */
                    raise(SIGTERM);
                }
                /* Save size of wholeMsg */
                int clientInput = strlen(wholeMsg);

                /* Find location of \n between plaintext and key */
                int c = 0;
                while (wholeMsg[c] != '\n')
                    ++c;

                /* Allocate memory to store key */
                key = malloc(sizeof(char) * clientInput);
                if (key == 0) error("malloc failed");
                memset(key, '\0', clientInput);

                /* Iterate over chars past \n to get the key */
                int i = 0;
                while (c < clientInput - 2) /* Account for '@' and '.' */
                {
                    ++c;
                    key[i] = wholeMsg[c];
                    ++i;
                }
                /* Remove first \n from client message to get plaintext */
                wholeMsg[strcspn(wholeMsg, "\n")] = '\0';

                /* Save the length of plaintext */
                int len = strlen(wholeMsg);

                /* Start encryption: 'A' = 0, 'B' = 1 ... ' ' = 26 */
                /* Allocate memory to hold encrypted message */
                encrypted = malloc(clientInput * sizeof(char));
                if (encrypted == 0) error("malloc failed");
                memset(encrypted, '\0', clientInput);

                /* Iterate over length of plaintext after first char '@' */
                for (i = 1; i < len; ++i)
                {
                    /* Get ASCII value of char from plaintext */
                    int bufferVal = wholeMsg[i];

                    /* If char is ' ', set value to 91 (1 past 'Z') */
                    if (bufferVal == 32)
                        bufferVal = 91;

                    /* Get ASCII value of char from key */
                    int keyVal = key[i-1];

                    /* If char is ' ', set value to 91 (1 past 'Z') */
                    if (keyVal == 32)
                        keyVal = 91;

                    /* Sum ASCII values and subtract ASCII value of two 
                     * 'A's to get base value 0 to 26 */
                    int num = bufferVal + keyVal - (2 * 'A');

                    /* Get encrypted char via modular addition */
                    encrypted[i-1] = (num % 27) + 'A';

                    /* Check if char should be ' ' */
                    if (encrypted[i-1] == 91)
                        encrypted[i-1] = ' ';
                }
                /* Add '.' to end of encrypted to denote end of message */
                encrypted[i-1] = '.';

                /* Send encrypted message back to client */
                int strlenEncrypted = strlen(encrypted);
                int totalSent = 0;
                while (totalSent < strlenEncrypted) /* Ensure whole msg sent */
                {
                    charsRead = send(newConnectionFD, encrypted, len, 0);
                    if (charsRead < 0) error("ERROR writing to socket");
                    
                    /* Update how much was sent in total */
                    totalSent += charsRead;
                }
                /* Free allocated memory to hold strings */
                free(key);
                free(encrypted);

                /* Close socket connected to client */
                close(newConnectionFD);

                /* Terminate forked process */
                raise(SIGTERM);
                break;
            default:
                waitpid(spawnpid, &childExitStatus, 0);
                break;
        }
    }
    /* Close listening socket */
    close(listenSocketFD);

	return 0; 
}
