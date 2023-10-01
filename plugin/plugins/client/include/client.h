#ifndef CLIENT_H
#define CLIENT_H

#include <stddef.h>

typedef struct
{
    char *data;
    char *error;
} Result;

Result *start_client(const char *peerID);
void close_client(void);

#endif // CLIENT_H
