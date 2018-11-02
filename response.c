#include "response.h"

void send_ripng_response()
{
    struct ripheader header;
    header.command = 2;
    header.version = 1;
}