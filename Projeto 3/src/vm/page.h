#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "lib/kernel/hash.h"
#include "threads/vaddr.h"
#include "devices/block.h"
#include "vm/swap.h"
#include "filesys/file.h"

#define MAX_STACK_SIZE (1 << 23)

/* Status da Página Virtual */
enum page_status
{
  IN_MEMORY,
  IN_SWAP,
  IN_FILESYS
};

enum page_type
{
  PAGE_ANON,
  PAGE_FILE
};

/* Entrada da Tabela de Páginas Suplementar (SPT Entry) */
struct spt_entry
{
  void *upage;
  void *kpage;

  enum page_status status;
  bool writable;

  enum page_type type;

  block_sector_t swap_index;

  struct file *file;
  off_t file_offset;
  size_t read_bytes;

  struct hash_elem elem; /* Elemento da Hash Table */
};

void spt_init(struct hash *spt);
void spt_destroy(struct hash *spt);

struct spt_entry *spt_find_page(struct hash *spt, void *upage);

bool vm_handle_page_fault(void *fault_addr, bool not_present, bool write, bool user, void *esp);


bool vm_alloc_and_install_page(void *upage, bool writable);

bool vm_free_page(void *upage);

void *spt_get_kpage(struct hash *spt, void *upage);

bool vm_pin_page(void *upage);
void vm_unpin_page(void *upage);

bool vm_load_from_file(struct spt_entry *spt_e);

/* Funções helpers para a Tabela Hash */
unsigned spt_hash_func(const struct hash_elem *e, void *aux);
bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux);

#endif /* vm/page.h */