/* This program outputs a key of length specified by user
 * USAGE: keygen keyLength
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[])
{
    /* Check for proper usage */
    if (argc != 2)
    {
        fprintf(stderr, "USAGE: %s keylength\n", argv[0]);
        exit(1);
    }
    /* Set seed for random number generator */
    srand(time(NULL));

    /* Save requested key length, converted from string to int */
    int keyLength = atoi(argv[1]);

    /* Get keyLength number of random chars */
    int i;
    for (i = 0; i < keyLength; ++i)
    {
        /* Get a random number from 0 to 26 */
        int randNum = (rand() % 27); 

        /* Get corresponding ASCII value */
        if (randNum <= 25)
            randNum += 'A';

        /* This encryption method sets ' ' to a value of 26 */
        else if (randNum == 26)
            randNum = 32;      /* ASCII value for ' ' is 32 */

        /* Print char associated with ASCII value */
        printf("%c", randNum);
    }
    /* End output with newline */
    printf("\n");

    return 0;
}
