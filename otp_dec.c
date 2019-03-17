/* This program acts as a client for the otp_dec_d server and requests
 * decryption of a passed-in message via a passed-in key.
 * USAGE: otp_dec ciphertext key port_for_otp_dec_d
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define ARR_SIZE 70001
#define MSG_SIZE 140000
#define READ_SIZE 1000

/* Error function used for reporting issues */
void error(const char *msg) { perror(msg); exit(0); } 

int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
    char ciphertext[ARR_SIZE];  /* Holds ciphertext from ciphertext file */
    char key[ARR_SIZE];         /* Holds cipher key from key file */
    char wholeMsg[MSG_SIZE];    /* Holds ciphertext + key */
    int wholeMsgIndex = 0;      /* Tracks wholeMsg array index */
	char recvBuff[ARR_SIZE];    /* Holds currently read data from server */
    char decrypted[ARR_SIZE];   /* Holds decrypted message from server */
    
    /* Check for usage and arguments */
	if (argc < 4) 
    { 
        fprintf(stderr,"USAGE: %s ciphertext key port\n", argv[0]); 
        exit(0); 
    } 
    /* Clear out wholeMsg and store '#' to denote start of ciphertext */
    memset(wholeMsg, '\0', sizeof(wholeMsg));
    wholeMsg[wholeMsgIndex] = '#';
    ++wholeMsgIndex;

    /* Access ciphertext file */
    int ciphertextFD;
    ciphertextFD = open(argv[1], O_RDONLY);
    if (ciphertextFD < 0) error("could not open ciphertext file");

    /* Clear out ciphertext buffer to save ciphertext file data */
	memset(ciphertext, '\0', sizeof(ciphertext)); 
    charsRead = read(ciphertextFD, ciphertext, sizeof(ciphertext));


    /* Iterate over ciphertext up to \n at end of string */
    int len = strlen(ciphertext) - 1; /* Get length minus \n char */
    int c;
    for (c = 0; c < len; ++c)
    {
        int val = ciphertext[c]; /* Get ASCII value of char */
        if (val != 32)           /* Check if char is space ' ' */
        {
            if (val < 65 || val > 90) /* Check if char is not A-Z */
            {
                fprintf(stderr, "otp_dec error: input '%s' contains bad "
                        "characters\n", argv[1]);
                exit(1);
            }
        }
        /* Store ciphertext data into wholeMsg */
        wholeMsg[wholeMsgIndex] = ciphertext[c];
        ++wholeMsgIndex;
    }
    /* Store \n at end of ciphertext in wholeMsg to separate from key */
    wholeMsg[wholeMsgIndex] = ciphertext[c];
    ++wholeMsgIndex;

    /* Access key file */
    int keyFD;
    keyFD = open(argv[2], O_RDONLY);
    if (keyFD < 0) error("could not open key file");

    /* Clear out key buffer to save key file data */
	memset(key, '\0', sizeof(key)); 
    charsRead = read(keyFD, key, sizeof(key));

    /* Remove \n at end of key */
    key[strcspn(key, "\n")] = '\0';

    /* Iterate over key */
    len = strlen(key);
    for (c = 0; c < len; ++c)
    {
        int val = key[c];   /* Get ASCII value of char */
        if (val != 32)      /* Check if char is space ' ' */
        {
            if (val < 65 || val > 90) /* Check if char is not A-Z */
            {
                fprintf(stderr, "otp_dec error: input '%s' contains bad "
                        " characters\n", argv[2]);
                exit(1);
            }
        }
        /* Store key data into wholeMsg */
        wholeMsg[wholeMsgIndex] = key[c];
        ++wholeMsgIndex;
    }
    /* Store '.' at end of wholeMsg to indicate end of message */
    wholeMsg[wholeMsgIndex] = '.';
    ++wholeMsgIndex;

	/* Set up the server address struct */
    /* Clear out the address struct */
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); 
    /* Get the port number and convert to an integer from a string */
	portNumber = atoi(argv[3]); 
    /* Create a network-capable socket */
	serverAddress.sin_family = AF_INET; 
    /* Store the port number */
	serverAddress.sin_port = htons(portNumber); 
    /* Convert the machine name into a special form of address */
	serverHostInfo = gethostbyname("localhost"); 
	if (serverHostInfo == NULL) 
    { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(0); }
    /* Copy in the address */
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length); 

	/* Set up the socket */
	socketFD = socket(AF_INET, SOCK_STREAM, 0); /* Create the socket */
	if (socketFD < 0) error("CLIENT: ERROR opening socket");
	
	/* Connect to server */
    /* Connect socket to address */ 
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) 
		error("CLIENT: ERROR connecting");
    
    /* Send wholeMsg to server */
    int strlenWholeMsg = strlen(wholeMsg);
    int totalSent = 0;
    while (totalSent < strlenWholeMsg) /* Ensure whole message is sent */
    {
        charsWritten = send(socketFD, wholeMsg, strlenWholeMsg, 0);
        if (charsWritten < 0) error("CLIENT: ERROR writing to socket");

        /* Update how much was sent in total */
        totalSent += charsWritten;
    }
	/* Get back decrypted message from server */
    /* Clear out decrypted array to hold decrypted message from server */
    memset(decrypted, '\0', sizeof(decrypted));

    /* Read from server until reach end of message denoted by '.' */
    while (strstr(decrypted, ".") == NULL)
    {
        /* Clear out recvBuff to read from server */
        memset(recvBuff, '\0', sizeof(recvBuff)); 
        charsRead = recv(socketFD, recvBuff, READ_SIZE, 0); 
        if (charsRead < 0) error("CLIENT: ERROR reading from socket");

        /* Add newly read data to decrypted array */
        strcat(decrypted, recvBuff);
    }
    /* Check if server rejected connection by sending back '@' */
    if (decrypted[0] == '@')
    {
        fprintf(stderr, "Error: could not contact otp_dec_d on port %d\n",
                atoi(argv[3]));
        /* Close input files */
        close(ciphertextFD);
        close(keyFD);

        close(socketFD); /* Close the socket */
        exit(2);
    }
    else
    {
        /* Remove ending '.' from message */
        decrypted[strcspn(decrypted, ".")] = '\0';

        /* Output decrypted message */
        printf("%s\n", decrypted);
    }
    /* Close input files */
    close(ciphertextFD);
    close(keyFD);

	close(socketFD); /* Close the socket */
	return 0;
}
