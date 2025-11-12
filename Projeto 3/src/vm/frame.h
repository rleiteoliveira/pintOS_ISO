#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/thread.h"
#include <list.h>

struct spt_entry;
struct frame_entry
{
  void *frame;
  struct thread *owner;
  struct spt_entry *spt_e;
  bool pinned;
  struct list_elem elem;
};

void frame_table_init(void);
void *frame_alloc(bool zero);
void frame_free(void *frame);

//Liga um frame à sua entrada da SPT
void frame_set_spt_entry(void *frame, struct spt_entry *spt_e);

//Funções de Pinning (para evitar deadlocks)
void frame_pin(void *kpage);
void frame_unpin(void *kpage);

#endif /* vm/frame.h */