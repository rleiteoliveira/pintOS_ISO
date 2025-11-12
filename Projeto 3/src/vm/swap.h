#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"

//Inicializa o sistema de swap
void swap_init(void);

//Traz uma página do disco de swap para a memória
void swap_in(block_sector_t swap_index, void *frame);

block_sector_t swap_out(void *frame);

//Libera um slot de swap
void swap_free(block_sector_t swap_index);

#endif /* vm/swap.h */