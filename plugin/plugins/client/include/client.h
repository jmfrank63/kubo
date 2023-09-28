#ifndef CLIENT_H
#define CLIENT_H

#include <stddef.h>

typedef struct
{
    char *data;
    char *error;
} Result;

Result *start_client(const char *peerID);

#endif // CLIENT_H
