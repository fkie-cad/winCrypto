#include <errno.h>
#include <stdio.h>

#include "Fifo.h"
#include "print.h"




bool Fifo_init(PFifo fifo)
{
    DPrint("Fifo_init\n");
    fifo->front = NULL;
    fifo->head = NULL;
    fifo->size = 0;
    fifo->entry_header_size = 2 * sizeof(size_t);

    return true;
}

bool Fifo_destroy(PFifo fifo)
{
    DPrint("Fifo_destroy\n");
    PFifoEntry act = fifo->front;
    PFifoEntry tmp = NULL;
    
    while ( act != NULL )
    {
        tmp = act;
        act = act->next;
        free(tmp);
    }
    
    memset(fifo, 0, sizeof(fifo));

    return true;
}

size_t Fifo_push(PFifo fifo, const void* value, size_t value_size)
{
    DPrint("Fifo_push\n");
    errno = 0;
    PFifoEntry entry = (void*)malloc(fifo->entry_header_size+value_size);
    int errsv = errno;
    if (!entry)
    {
        printf("ERROR (0x%x): malloc failed\n", errsv);
        return 0;
    }
    //memset(value, 0, value_size);
    memcpy(&(entry->value)[0], value, value_size);
    
    entry->size = value_size;
    entry->next = NULL;
        
    if ( fifo->size == 0 )
    {
        fifo->front = entry;

        //fifo->front->last = NULL;
    }
    else
    {
        fifo->head->next = entry;
        //entry->last = fifo->head;
    }
    
    fifo->head = entry;
    
    fifo->size++;

    return fifo->size;
}

bool Fifo_empty(PFifo fifo)
{
    return fifo->size == 0;
}

size_t Fifo_size(PFifo fifo)
{
    return fifo->size;
}

PFifoEntry Fifo_front(PFifo fifo)
{
    if (fifo->size == 0)
        return NULL;

    return fifo->front;
}

bool Fifo_pop_front(PFifo fifo)
{
    DPrint("Fifo_pop_front\n");
    PFifoEntry f;
    if (fifo->size == 0)
    {
        DPrint(" - size is 0\n");
        return false;
    }

    f = fifo->front;
    fifo->front = f->next;
    //if ( f->next != NULL)
        //f->next->last = NULL;

    free(f);

    fifo->size--;
    
    return true;
}
