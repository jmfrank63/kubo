#ifndef SERVER_H
#define SERVER_H

#include <stddef.h>

typedef struct
{
    char *data;
    char *error;
} Result;

Result *start_server(const char *peerID);

#endif // SERVER_H
