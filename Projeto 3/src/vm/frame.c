#include "vm/frame.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include <list.h>
#include <string.h>
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "userprog/syscall.h"

static struct list frame_table;
static struct lock frame_lock;

static void *frame_evict(void);
static struct frame_entry *find_frame_entry(void *kpage);

void frame_table_init(void)
{
  list_init(&frame_table);
  lock_init(&frame_lock);
}

//Aloca um novo frame da memória física
void *
frame_alloc(bool zero)
{
  void *frame = NULL;

  if (zero)
    frame = palloc_get_page(PAL_USER | PAL_ZERO);
  else
    frame = palloc_get_page(PAL_USER);

  if (frame == NULL)
  {
    //Memória está cheia, precisamos evictar uma página
    frame = frame_evict();

    if (frame == NULL)
      PANIC("frame_alloc: Falha ao fazer eviction");

    if (zero)
      memset(frame, 0, PGSIZE);
  }

  struct frame_entry *entry = malloc(sizeof(struct frame_entry));
  if (entry == NULL)
  {
    //Se falharmos aqui, libera o frame que acabamos de alocar/evictar
    palloc_free_page(frame);
    return NULL;
  }

  entry->frame = frame;
  entry->owner = thread_current();
  entry->spt_e = NULL;
  entry->pinned = false;

  lock_acquire(&frame_lock);
  list_push_back(&frame_table, &entry->elem);
  lock_release(&frame_lock);

  return frame;
}

//Libera um frame
void frame_free(void *frame)
{
  lock_acquire(&frame_lock);

  //Acha a entrada na lista e a remove
  struct list_elem *e;
  for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
  {
    struct frame_entry *entry = list_entry(e, struct frame_entry, elem);
    if (entry->frame == frame)
    {
      list_remove(&entry->elem);
      free(entry);
      palloc_free_page(frame);
      break;
    }
  }

  lock_release(&frame_lock);
}

void frame_set_spt_entry(void *frame, struct spt_entry *spt_e)
{
  lock_acquire(&frame_lock);

  struct frame_entry *entry = find_frame_entry(frame);
  if (entry != NULL)
  {
    entry->spt_e = spt_e;
  }

  lock_release(&frame_lock);
}

//"Pina" um frame, impedindo que ele seja evictado
void frame_pin(void *kpage)
{
  lock_acquire(&frame_lock);
  struct frame_entry *entry = find_frame_entry(kpage);
  if (entry)
    entry->pinned = true;
  lock_release(&frame_lock);
}

//"Despina" um frame, permitindo que ele seja evictado
void frame_unpin(void *kpage)
{
  lock_acquire(&frame_lock);
  struct frame_entry *entry = find_frame_entry(kpage);
  if (entry)
    entry->pinned = false;
  lock_release(&frame_lock);
}

//Encontra um frame_entry
static struct frame_entry *
find_frame_entry(void *kpage)
{
  struct list_elem *e;
  for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
  {
    struct frame_entry *entry = list_entry(e, struct frame_entry, elem);
    if (entry->frame == kpage)
      return entry;
  }
  return NULL;
}

//Algoritmo de Eviction (Substituição)
static void *
frame_evict(void)
{
  lock_acquire(&frame_lock);

  //FIFO - First-In, First-Out (pula frames "pinados")
  struct list_elem *e;
  struct frame_entry *victim = NULL;

  for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
  {
    victim = list_entry(e, struct frame_entry, elem);
    if (!victim->pinned)
    {
      list_remove(&victim->elem);
      break;
    }
    victim = NULL; // Reseta se estava pinado
  }

  if (victim == NULL)
    PANIC("Eviction falhou: Nenhuma página livre (todas pinadas?)");

  lock_release(&frame_lock);

  ASSERT(victim->spt_e != NULL); // O frame DEVE estar ligado a uma SPT
  ASSERT(victim->owner != NULL);
  ASSERT(victim->owner->pagedir != NULL);

  struct spt_entry *spt_e = victim->spt_e;

  bool is_dirty = pagedir_is_dirty(victim->owner->pagedir, spt_e->upage);

  if (spt_e->type == PAGE_ANON)
  {
    block_sector_t swap_index = swap_out(victim->frame);
    spt_e->status = IN_SWAP;
    spt_e->swap_index = swap_index;
  }
  else if (spt_e->type == PAGE_FILE)
  {
    if (is_dirty)
    {
      lock_acquire(&filesys_lock);
      file_write_at(spt_e->file, victim->frame,
                    spt_e->read_bytes, spt_e->file_offset);
      lock_release(&filesys_lock);

      //LIMPA O DIRTY BIT
      pagedir_set_dirty(victim->owner->pagedir, spt_e->upage, false);
    }
    spt_e->status = IN_FILESYS;
  }

  spt_e->kpage = NULL;

  //Limpa o mapeamento da Page Table de hardware (MMU)
  pagedir_clear_page(victim->owner->pagedir, spt_e->upage);

  void *frame = victim->frame;
  free(victim);

  return frame;
}