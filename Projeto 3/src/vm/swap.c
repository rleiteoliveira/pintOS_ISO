#include "vm/swap.h"
#include <bitmap.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <stdio.h>

static struct block *swap_block;
static struct bitmap *swap_bitmap;
static struct lock swap_lock;

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

//Inicializa o sistema de swap
void swap_init(void)
{
  swap_block = block_get_role(BLOCK_SWAP);
  if (swap_block == NULL)
  {
    printf("Swap: Dispositivo de swap não encontrado.\n");
    swap_bitmap = NULL;
    return;
  }

  size_t swap_slots = block_size(swap_block) / SECTORS_PER_PAGE;
  swap_bitmap = bitmap_create(swap_slots);
  if (swap_bitmap == NULL)
  {
    PANIC("Swap: Falha ao criar bitmap de swap.");
  }

  //Inicializar o lock
  lock_init(&swap_lock);
}

//Escreve um 'frame' no disco de swap
block_sector_t
swap_out(void *frame)
{
  ASSERT(swap_bitmap != NULL); // Garante que o swap foi inicializado

  lock_acquire(&swap_lock);

  //Procura por 1 slot que esteja livre
  size_t slot_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);

  if (slot_index == BITMAP_ERROR)
  {
    lock_release(&swap_lock);
    PANIC("Swap: Disco de swap cheio!");
  }

  //Calcular o setor de disco inicial para este slot
  block_sector_t sector_index = slot_index * SECTORS_PER_PAGE;

  for (int i = 0; i < SECTORS_PER_PAGE; i++)
  {
    void *source_addr = (uint8_t *)frame + (i * BLOCK_SECTOR_SIZE);
    block_sector_t target_sector = sector_index + i;

    block_write(swap_block, target_sector, source_addr); // [cite: 2101-2105]
  }

  lock_release(&swap_lock);

  return sector_index;
}

//Traz uma página do disco de swap de volta para a memória (frame)
void swap_in(block_sector_t swap_index, void *frame)
{
  ASSERT(swap_bitmap != NULL);

  lock_acquire(&swap_lock);

  size_t slot_index = swap_index / SECTORS_PER_PAGE;
  if (!bitmap_test(swap_bitmap, slot_index))
  {
    lock_release(&swap_lock);
    PANIC("Swap: Tentativa de ler de um slot de swap livre.");
  }

  for (int i = 0; i < SECTORS_PER_PAGE; i++)
  {
    void *target_addr = (uint8_t *)frame + (i * BLOCK_SECTOR_SIZE);
    block_sector_t source_sector = swap_index + i;

    block_read(swap_block, source_sector, target_addr);
  }

  //Marcar o slot como livre novamente no bitmap
  bitmap_reset(swap_bitmap, slot_index);

  lock_release(&swap_lock);
}

//Libera um slot de swap
void swap_free(block_sector_t swap_index)
{
  ASSERT(swap_bitmap != NULL);

  lock_acquire(&swap_lock);

  size_t slot_index = swap_index / SECTORS_PER_PAGE;

  if (bitmap_test(swap_bitmap, slot_index))
  {
    bitmap_reset(swap_bitmap, slot_index);
  }

  lock_release(&swap_lock);
}