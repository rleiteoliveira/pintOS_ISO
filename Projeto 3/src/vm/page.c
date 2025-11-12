#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include <stdio.h>
#include <string.h>
#include "filesys/filesys.h"
#include "userprog/syscall.h"

// Limite máximo da pilha
//#define MAX_STACK_SIZE (1 << 23)

static bool vm_swap_in(struct spt_entry *spt_e);
static void spt_destroy_entry(struct hash_elem *e, void *aux UNUSED);

//Helper para alocar, mapear E registrar uma página. Usado APENAS por setup_stack e stack_growth.
bool vm_alloc_and_install_page(void *upage, bool writable)
{
  //Alocar um frame
  void *frame = frame_alloc(true); // true = zerar o frame
  if (frame == NULL)
    return false; // Falhou (sem memória ou falha no eviction)

  //Mapear a página virtual (upage) para o frame físico
  if (!install_page(upage, frame, writable))
  {
    frame_free(frame);
    return false; // Falha ao mapear
  }

  //Registrar a nova página na SPT
  struct spt_entry *spt_e = malloc(sizeof(struct spt_entry));
  if (spt_e == NULL)
  {
    // Desfaz o mapeamento e libera o frame
    pagedir_clear_page(thread_current()->pagedir, upage);
    frame_free(frame);
    return false; // Sem memória para a entrada da SPT
  }

  spt_e->upage = upage;
  spt_e->kpage = frame;
  spt_e->status = IN_MEMORY;
  spt_e->writable = writable;
  spt_e->type = PAGE_ANON;


  // Adiciona na SPT da thread atual
  struct hash *spt = &thread_current()->spt;
  if (hash_insert(spt, &spt_e->elem) != NULL)
  {
    free(spt_e);
    pagedir_clear_page(thread_current()->pagedir, upage);
    frame_free(frame);
    return false;
  }

  // Liga o frame à sua entrada SPT
  frame_set_spt_entry(frame, spt_e);

  return true;
}

bool vm_handle_page_fault(void *fault_addr, bool not_present, bool write, bool user, void *esp)
{
  //Se não foi 'not_present', é uma violação de escrita
  if (!not_present)
    return false;

  //Se não foi 'user', foi falha do kernel
  if (!user)
    return false;

  if (fault_addr == NULL || !is_user_vaddr(fault_addr))
    return false;

  void *upage = pg_round_down(fault_addr);
  struct hash *spt = &thread_current()->spt;

  struct spt_entry *spt_e = spt_find_page(spt, upage);

  if (spt_e != NULL)
  {
    if (write && !spt_e->writable)
      return false;

    if (spt_e->status == IN_SWAP)
    {
      //Está no swap
      return vm_swap_in(spt_e);
    }
    else if (spt_e->status == IN_FILESYS)
    {
      //Está no arquivo
      return vm_load_from_file(spt_e);
    }
    else if (spt_e->status == IN_MEMORY && spt_e->kpage == NULL && spt_e->type == PAGE_ANON)
    {
      void *frame = frame_alloc(true);
      if (frame == NULL)
        return false;

      if (!install_page(spt_e->upage, frame, spt_e->writable))
      {
        frame_free(frame);
        return false;
      }

      spt_e->kpage = frame;
      frame_set_spt_entry(frame, spt_e);
      return true;
    }
    else
    {
      return false;
    }
  }

  bool is_stack_growth = (fault_addr >= esp - 32) || (fault_addr >= esp);

  if (is_stack_growth && (PHYS_BASE - upage) <= MAX_STACK_SIZE)
  {
    return vm_alloc_and_install_page(upage, true);
  }

  return false;
}

bool vm_free_page(void *upage)
{
  struct thread *t = thread_current();
  struct hash *spt = &t->spt;

  struct spt_entry *spt_e = spt_find_page(spt, upage);
  if (spt_e == NULL)
    return false; // Página não existe

  //Remover da tabela hash
  hash_delete(spt, &spt_e->elem);
  if (spt_e->status == IN_MEMORY)
  {
    pagedir_clear_page(t->pagedir, spt_e->upage);
    frame_free(spt_e->kpage);
  }
  else if (spt_e->status == IN_SWAP)
  {
    //Libera o slot de swap
    swap_free(spt_e->swap_index);
  }

  free(spt_e);
  return true;
}

void spt_init(struct hash *spt)
{
  hash_init(spt, spt_hash_func, spt_less_func, NULL);
}

//Helper para destruir uma entrada da hash
static void
spt_destroy_entry(struct hash_elem *e, void *aux UNUSED)
{
  struct spt_entry *spt_e = hash_entry(e, struct spt_entry, elem);

  if (spt_e->status == IN_MEMORY)
  {
    //Limpa da page table e libera o frame
    pagedir_clear_page(thread_current()->pagedir, spt_e->upage);
    frame_free(spt_e->kpage);
  }
  else if (spt_e->status == IN_SWAP)
  {
    //Libera o slot de swap
    swap_free(spt_e->swap_index);
  }

  free(spt_e);
}

void spt_destroy(struct hash *spt)
{
  hash_destroy(spt, spt_destroy_entry);
}

//Retorna um hash para a página no endereço
unsigned
spt_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
  const struct spt_entry *spt_e = hash_entry(e, struct spt_entry, elem);
  return hash_bytes(&spt_e->upage, sizeof spt_e->upage);
}

//Retorna true se a página A precede a página B
bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct spt_entry *a_spt_e = hash_entry(a, struct spt_entry, elem);
  const struct spt_entry *b_spt_e = hash_entry(b, struct spt_entry, elem);
  return a_spt_e->upage < b_spt_e->upage;
}

//Procura uma página na SPT dado o endereço virtual (upage)
struct spt_entry *
spt_find_page(struct hash *spt, void *upage)
{
  struct spt_entry temp_entry;
  temp_entry.upage = upage;

  struct hash_elem *e = hash_find(spt, &temp_entry.elem);
  if (e == NULL)
    return NULL; // Não encontrou

  return hash_entry(e, struct spt_entry, elem);
}

//Retorna o kpage (frame) de uma página na SPT
void *
spt_get_kpage(struct hash *spt, void *upage)
{
  struct spt_entry *spt_e = spt_find_page(spt, upage);
  if (spt_e == NULL || spt_e->status != IN_MEMORY)
    return NULL;

  return spt_e->kpage;
}

//Traz uma página do swap para um frame e a mapeia
static bool
vm_swap_in(struct spt_entry *spt_e)
{
  void *frame = frame_alloc(false); // false = não zerar
  if (frame == NULL)
    return false; // Falha ao alocar/evictar

  //Trazer os dados do swap para o frame
  swap_in(spt_e->swap_index, frame);

  if (!install_page(spt_e->upage, frame, spt_e->writable))
  {
    frame_free(frame);
    return false;
  }

  //Atualizar a SPT
  spt_e->status = IN_MEMORY;
  spt_e->kpage = frame;

  //Ligar o frame à SPT
  frame_set_spt_entry(frame, spt_e);

  return true;
}

//Carrega uma página do sistema de arquivos para um frame
bool vm_load_from_file(struct spt_entry *spt_e)
{
  void *frame = frame_alloc(true);
  if (frame == NULL)
    return false;

  spt_e->kpage = frame;
  frame_pin(frame);

  lock_acquire(&filesys_lock); // Garante que o arquivo não será modificado

  //Posiciona o leitor no offset correto do arquivo
  file_seek(spt_e->file, spt_e->file_offset);

  //Lê os bytes do arquivo para o frame
  int bytes_read = file_read(spt_e->file, frame, spt_e->read_bytes);

  lock_release(&filesys_lock);

  if (bytes_read != (int)spt_e->read_bytes)
  {
    frame_unpin(frame); // Despina antes de liberar
    frame_free(frame);
    return false;
  }

  if (!install_page(spt_e->upage, frame, spt_e->writable))
  {
    frame_unpin(frame);
    frame_free(frame);
    return false;
  }

  spt_e->status = IN_MEMORY;
  frame_set_spt_entry(frame, spt_e);
  frame_unpin(frame);

  return true;
}

bool vm_pin_page(void *upage)
{
  struct hash *spt = &thread_current()->spt;
  struct spt_entry *spt_e = spt_find_page(spt, upage);

  if (spt_e == NULL)
    return false; // Endereço inválido

  //Se já está na memória, apenas pina
  if (spt_e->status == IN_MEMORY)
  {
    frame_pin(spt_e->kpage); // Chama a função de frame.c
    return true;
  }

  //Se não está na memória, carrega (swap ou file)
  bool success = false;
  if (spt_e->status == IN_SWAP)
    success = vm_swap_in(spt_e);
  else if (spt_e->status == IN_FILESYS)
    success = vm_load_from_file(spt_e);

  if (!success)
    return false;
  frame_pin(spt_e->kpage);

  return true;
}


void vm_unpin_page(void *upage)
{
  struct hash *spt = &thread_current()->spt;
  struct spt_entry *spt_e = spt_find_page(spt, upage);

  if (spt_e != NULL && spt_e->status == IN_MEMORY)
  {
    frame_unpin(spt_e->kpage); // Chama a função de frame.c
  }
}