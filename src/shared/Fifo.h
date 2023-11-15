#ifndef SHARED_fifo_H
#define SHARED_fifo_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../inc/types.h"

//#define FIFO_ENTRY_HEADER_SIZE_32 (12)
//#define FIFO_ENTRY_HEADER_SIZE_64 (24)

typedef struct FifoEntry {
   struct FifoEntry* next;
   //struct FifoEntry* last;
   size_t size;
   unsigned char value[1];
} FifoEntry, * PFifoEntry;

typedef struct Fifo {
    struct FifoEntry* front;
    struct FifoEntry* head;
    size_t size;
    size_t entry_header_size;
} Fifo, *PFifo;

bool Fifo_init(PFifo fifo);

bool Fifo_destroy(PFifo fifo);

size_t Fifo_push(PFifo fifo, const void* entry, size_t entry_size);

bool Fifo_empty(PFifo fifo);

size_t Fifo_size(PFifo fifo);

PFifoEntry Fifo_front(PFifo fifo);

bool Fifo_pop_front(PFifo fifo);

#endif
