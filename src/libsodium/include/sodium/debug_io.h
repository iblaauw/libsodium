#ifndef __DEBUG_IO_H__
#define __DEBUG_IO_H__

#include <stdint.h>

int wr_debug(uint32_t key);

long rd_debug(void);

#endif // __DEBUG_IO_H__
