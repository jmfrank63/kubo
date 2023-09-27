#ifndef CLIENT_H
#define CLIENT_H

#include <stddef.h>

typedef struct
{
    char *data;
    char *error;
} Result;

Result *start_client(const char *peerID);
void free_cstring(char *ptr);

#endif // CLIENT_H
