#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "userprog/pagedir.h"
#include "lib/kernel/console.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include <string.h>
#include "vm/page.h"
#include "vm/frame.h"

static void syscall_handler (struct intr_frame *);
//Adicionado
static void validate_user_pointer(const void *uaddr);
//static struct lock filesys_lock;
struct lock filesys_lock;

//Helper de VM
static void
validate_user_pointer(const void *uaddr)
{
  if (uaddr == NULL || !is_user_vaddr(uaddr))
  {
    thread_exit_with_status(-1);
  }

  //Tenta carregar a página na memória (seja do swap ou arquivo)
  if (!vm_pin_page(pg_round_down(uaddr)))
  {
    thread_exit_with_status(-1); // Falhou ao carregar (ex: endereço inválido)
  }

  //Ok, a página é válida. Libera ela para eviction.
  vm_unpin_page(pg_round_down(uaddr));
}

//Valida e "pina" um buffer de usuário inteiro
static void
vm_pin_buffer(const void *buffer, unsigned size, bool write_access)
{
  if (buffer == NULL || !is_user_vaddr(buffer))
    thread_exit_with_status(-1);

  if (size > 0 && !is_user_vaddr((char *)buffer + size - 1))
    thread_exit_with_status(-1);

  char *ptr = (char *)pg_round_down(buffer);
  char *end = (char *)buffer + size;

  for (; (void *)ptr < (void *)end; ptr += PGSIZE)
  {
    // Traz a página para a memória e a "pina"
    if (!vm_pin_page(ptr))
      thread_exit_with_status(-1);

    // Se a syscall for de escrita, verifica se a página é writable
    if (write_access)
    {
      struct spt_entry *spt_e = spt_find_page(&thread_current()->spt, ptr);
      if (spt_e == NULL || !spt_e->writable)
        thread_exit_with_status(-1);
    }
  }
}

// "Despina" um buffer de usuário, permitindo que ele sofra eviction.
static void
vm_unpin_buffer(const void *buffer, unsigned size)
{
  if (buffer == NULL)
    return;

  char *ptr = (char *)pg_round_down(buffer);
  char *end = (char *)buffer + size;

  for (; (void *)ptr < (void *)end; ptr += PGSIZE)
  {
    if (is_user_vaddr(ptr))
      vm_unpin_page(ptr);
  }
}

// Valida uma string (terminada em nulo) em memória de usuário.
static void
validate_user_string(const char *ustr)
{
  if (ustr == NULL || !is_user_vaddr(ustr))
    thread_exit_with_status(-1);

  void *upage = pg_round_down(ustr);

  // Pina a primeira página
  if (!vm_pin_page(upage))
    thread_exit_with_status(-1);

  //validate_user_pointer(ustr); // Valida o início
  const char *ptr = ustr;
  // Agora, percorre a string página por página até achar '\0'
  while (true)
  {
    // Se o ponteiro saiu da página atual...
    if (pg_round_down(ptr) != upage)
    {
      vm_unpin_page(upage);
      upage = pg_round_down(ptr);
      if (upage == NULL || !is_user_vaddr(upage) || !vm_pin_page(upage))
        thread_exit_with_status(-1);
    }
    if (*ptr == '\0')
      break;

    ptr++;
  }
  // Despina a última página que foi lida
  vm_unpin_page(upage);
}

void
syscall_init(void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  //Adição
  lock_init(&filesys_lock);
}

void do_munmap(mapid_t mapping)
{
  struct thread *cur = thread_current();
  struct list_elem *e;

  //Encontra o mmap_entry na lista da thread
  for (e = list_begin(&cur->mmap_list); e != list_end(&cur->mmap_list); e = list_next(e))
  {
    struct mmap_entry *mmap_e = list_entry(e, struct mmap_entry, elem);
    if (mmap_e->mapid == mapping)
    {
      for (size_t i = 0; i < mmap_e->page_count; i++)
      {
        void *upage = mmap_e->addr + (i * PGSIZE);
        struct spt_entry *spt_e = spt_find_page(&cur->spt, upage);

        if (spt_e != NULL)
        {
          //Escreve de volta se estiver sujo
          if (spt_e->status == IN_MEMORY && pagedir_is_dirty(cur->pagedir, upage))
          {
            lock_acquire(&filesys_lock);
            file_write_at(spt_e->file, spt_e->kpage,
                          spt_e->read_bytes, spt_e->file_offset);
            lock_release(&filesys_lock);

            pagedir_set_dirty(cur->pagedir, upage, false);
          }
          vm_free_page(upage);
        }
      }

      //Fecha o arquivo e libera o mmap_entry
      lock_acquire(&filesys_lock);
      file_close(mmap_e->file);
      lock_release(&filesys_lock);

      list_remove(&mmap_e->elem);
      free(mmap_e);
      break;
    }
  }
}

static void
syscall_handler(struct intr_frame *f)
{
  // Valida o ponteiro da pilha para ler o número da syscall
  validate_user_pointer(f->esp + 3);
  int syscall_num = *(int *)f->esp;

  switch (syscall_num)
  {
    case SYS_HALT:
    {
      shutdown_power_off(); // Desliga o Pintos
      break;
    }
    case SYS_EXIT:
    {
      // Valida a leitura do argumento 'status' (bytes 4-7)
      validate_user_pointer(f->esp + 7);
      int status = *(int *)(f->esp + 4);
      thread_current()->exit_status = status;
      printf("%s: exit(%d)\n", thread_current()->name, status);
      thread_exit();
      break;
    }

    case SYS_WRITE:
    {
      validate_user_pointer(f->esp + 15);
      int fd = *(int *)(f->esp + 4);
      const void *buffer = *(void **)(f->esp + 8);
      unsigned size = *(unsigned *)(f->esp + 12);

      int bytes_written = -1;

      vm_pin_buffer(buffer, size, false); // false = estamos lendo do buffer

      if (fd == 1)
      {
        putbuf(buffer, size);
        bytes_written = size;
      }
      else if (fd >= 2 && fd < 128)
      {
        struct thread *cur = thread_current();
        struct file *file_ptr = cur->open_files[fd];

        if (file_ptr != NULL)
        {
          lock_acquire(&filesys_lock);
          bytes_written = file_write(file_ptr, buffer, size);
          lock_release(&filesys_lock);
        }
      }

      // Despina o buffer DEPOIS de largar o lock
      vm_unpin_buffer(buffer, size);
      f->eax = bytes_written;
      break;
    }

    case SYS_CREATE:
    {
      // Valida ponteiros da pilha para os 2 argumentos (bytes 4-11)
      validate_user_pointer(f->esp + 11);

      // Obtém argumentos da pilha do usuário
      const char *file = *(const char **)(f->esp + 4);
      unsigned initial_size = *(unsigned *)(f->esp + 8);

      // Valida o ponteiro do nome do arquivo em si
      //validate_user_pointer(file);
      validate_user_string(file);

      lock_acquire(&filesys_lock);
      bool success = filesys_create(file, initial_size);
      lock_release(&filesys_lock);
      f->eax = success;
      break;
    }

    case SYS_OPEN:
    {
      validate_user_pointer(f->esp + 7);
      const char *filename = *(const char **)(f->esp + 4);
      //validate_user_pointer(filename);
      validate_user_string(filename);

      struct file *file_ptr = NULL;
      int fd = -1;

      lock_acquire(&filesys_lock);
      file_ptr = filesys_open(filename);

      lock_release(&filesys_lock);

      if (file_ptr != NULL) // Arquivo aberto com sucesso?
      {
        struct thread *cur = thread_current();
        // Encontra um slot livre na tabela de arquivos abertos da thread
        for (fd = cur->next_fd; fd < 128; fd++)
        {
          if (cur->open_files[fd] == NULL)
          {
            cur->open_files[fd] = file_ptr;
            cur->next_fd = fd + 1;
            break;
          }
        }
        // Se o loop terminou sem break, não achou slot (fd == 128)
        if (fd >= 128)
        {
          file_close(file_ptr); // Fecha o arquivo que não pode ser rastreado
          fd = -1;
        }
      }
      f->eax = fd;
      break;
    }

    case SYS_CLOSE:
    {
      validate_user_pointer(f->esp + 7);
      int fd = *(int *)(f->esp + 4);

      if (fd < 2 || fd >= 128)
      {
        // FD inválido, termina o processo
        struct thread *cur = thread_current();
        printf("%s: exit(%d)\n", cur->name, -1);
        cur->exit_status = -1;
        thread_exit();
      }

      struct thread *cur = thread_current();
      struct file *file_ptr = cur->open_files[fd];

      // Verifica se o fd corresponde a um arquivo aberto
      if (file_ptr == NULL)
      {
        // fd não está aberto, termina o processo
        printf("%s: exit(%d)\n", cur->name, -1);
        cur->exit_status = -1;
        thread_exit();
      }

      lock_acquire(&filesys_lock);
      file_close(file_ptr);
      lock_release(&filesys_lock);

      cur->open_files[fd] = NULL;
      break;
    }

    case SYS_READ:
    {
      validate_user_pointer(f->esp + 15);
      int fd = *(int *)(f->esp + 4);
      void *buffer = *(void **)(f->esp + 8);
      unsigned size = *(unsigned *)(f->esp + 12);

      int bytes_read = -1;

      vm_pin_buffer(buffer, size, true);

      if (fd == 0)
      {
        uint8_t *buf_ptr = (uint8_t *)buffer;
        for (unsigned i = 0; i < size; i++)
        {
          buf_ptr[i] = input_getc();
        }
        bytes_read = size;
      }
      else if (fd >= 2 && fd < 128)
      {
        struct thread *cur = thread_current();
        struct file *file_ptr = cur->open_files[fd];

        if (file_ptr != NULL)
        {
          lock_acquire(&filesys_lock);
          bytes_read = file_read(file_ptr, buffer, size);
          lock_release(&filesys_lock);
        }
      }

      // Despina o buffer DEPOIS de largar o lock
      vm_unpin_buffer(buffer, size);
      f->eax = bytes_read;
      break;
    }

    case SYS_EXEC:
    {
      validate_user_pointer(f->esp + 7);
      const char *cmd_line = *(const char **)(f->esp + 4);

      if (cmd_line == NULL || !is_user_vaddr(cmd_line))
        thread_exit_with_status(-1);

      char *upage = pg_round_down(cmd_line);
      char *end = (char *)cmd_line;

      while (true)
      {
        if (!is_user_vaddr(end))
          thread_exit_with_status(-1);

        if (pg_round_down(end) != upage)
        {
          upage = pg_round_down(end);
          if (!vm_pin_page(upage))
            thread_exit_with_status(-1);
        }
        else if (upage == pg_round_down(cmd_line))
        {
          if (!vm_pin_page(upage))
            thread_exit_with_status(-1);
        }

        if (*end == '\0')
          break;
        end++;
      }

      //Agora que todas as páginas da string estão pinadas, podemos executar
      tid_t child_tid = process_execute(cmd_line);

      upage = pg_round_down(cmd_line);
      end = (char *)cmd_line;
      while (true)
      {
        if (pg_round_down(end) != upage)
        {
          vm_unpin_page(upage);
          upage = pg_round_down(end);
        }
        else if (upage == pg_round_down(cmd_line))
        {
          vm_unpin_page(upage);
        }

        if (*end == '\0')
          break;
        end++;
      }
      vm_unpin_page(upage); // Despina a última página

      f->eax = child_tid;
      break;
    }

    case SYS_FILESIZE:
    {
      validate_user_pointer(f->esp + 7);

      // Obtém o file descriptor da pilha
      int fd = *(int *)(f->esp + 4);

      if (fd < 2 || fd >= 128)
      {
        f->eax = -1; // Retorna -1 para fd inválido
        break;
      }

      struct thread *cur = thread_current();
      struct file *file_ptr = cur->open_files[fd];

      // Verifica se o fd corresponde a um arquivo aberto
      if (file_ptr == NULL)
      {
        f->eax = -1;
        break;
      }
      lock_acquire(&filesys_lock);

      // Obtém o tamanho do arquivo
      off_t size = file_length(file_ptr);

      lock_release(&filesys_lock);

      f->eax = size;
      break;
    }

    case SYS_REMOVE:
    {
      validate_user_pointer(f->esp + 7);
      const char *filename = *(const char **)(f->esp + 4);
      //validate_user_pointer(filename);
      validate_user_string(filename);

      lock_acquire(&filesys_lock);

      // Tenta remover o arquivo
      bool success = filesys_remove(filename);

      lock_release(&filesys_lock);

      f->eax = success;
      break;
    }

    case SYS_SEEK:
    {
      validate_user_pointer(f->esp + 11);

      int fd = *(int *)(f->esp + 4);
      unsigned position = *(unsigned *)(f->esp + 8);

      if (fd < 2 || fd >= 128)
      {
        break;
      }

      struct thread *cur = thread_current();
      struct file *file_ptr = cur->open_files[fd];

      if (file_ptr == NULL)
      {
        break;
      }
      lock_acquire(&filesys_lock);

      // Chama a função do sistema de arquivos para mover o "cursor"
      file_seek(file_ptr, position);

      lock_release(&filesys_lock);
      // SYS_SEEK não tem valor de retorno
      break;
    }

    case SYS_TELL:
    {
      validate_user_pointer(f->esp + 7);
      int fd = *(int *)(f->esp + 4);

      if (fd < 2 || fd >= 128)
      {
        f->eax = -1;
        break;
      }

      struct thread *cur = thread_current();
      struct file *file_ptr = cur->open_files[fd];

      if (file_ptr == NULL)
      {
        f->eax = -1;
        break;
      }
      lock_acquire(&filesys_lock);

      // Chama a função do sistema de arquivos para obter a posição
      off_t position = file_tell(file_ptr);

      lock_release(&filesys_lock);
      f->eax = position;
      break;
    }

    case SYS_WAIT:
    {
      // Valida o ponteiro para o argumento (TID)
      validate_user_pointer(f->esp + 7);

      tid_t child_tid = *(tid_t *)(f->esp + 4);
      int status = process_wait(child_tid);

      f->eax = status;
      break;
    }

    case SYS_MMAP:
    {
      //Obter argumentos
      validate_user_pointer(f->esp + 11);
      int fd = *(int *)(f->esp + 4);
      void *addr = *(void **)(f->esp + 8);

      if (addr == NULL || pg_ofs(addr) != 0 || fd < 2)
      {
        f->eax = -1;
        break;
      }

      struct thread *cur = thread_current();
      struct file *file = cur->open_files[fd];
      if (file == NULL)
      {
        f->eax = -1;
        break;
      }

      lock_acquire(&filesys_lock);
      off_t file_len = file_length(file);
      if (file_len == 0)
      {
        lock_release(&filesys_lock);
        f->eax = -1;
        break;
      }

      struct file *reopened_file = file_reopen(file);
      lock_release(&filesys_lock);

      if (reopened_file == NULL)
      {
        f->eax = -1;
        break;
      }

      //Criar o mmap_entry
      struct mmap_entry *mmap_e = malloc(sizeof(struct mmap_entry));
      if (mmap_e == NULL)
      {
        file_close(reopened_file);
        f->eax = -1;
        break;
      }

      mmap_e->mapid = cur->next_mapid++;
      mmap_e->file = reopened_file;
      mmap_e->addr = addr;
      mmap_e->page_count = 0;
      list_push_back(&cur->mmap_list, &mmap_e->elem);

      //Criar as entradas da SPT (Lazy Loading)
      size_t offset = 0;
      bool overlap_found = false;

      while (file_len > 0)
      {
        size_t page_read_bytes = file_len < PGSIZE ? file_len : PGSIZE;
        void *upage = addr + offset;

        if (spt_find_page(&cur->spt, upage) != NULL ||
            upage >= (PHYS_BASE - MAX_STACK_SIZE))
        {
          overlap_found = true;
          f->eax = -1;
          break;
        }

        struct spt_entry *spt_e = malloc(sizeof(struct spt_entry));
        if (spt_e == NULL)
        {
          overlap_found = true; // Trata como falha de overlap
          f->eax = -1;
          break;
        }

        spt_e->upage = upage;
        spt_e->kpage = NULL;
        spt_e->status = IN_FILESYS;
        spt_e->writable = true;
        spt_e->type = PAGE_FILE;
        spt_e->file = reopened_file;
        spt_e->file_offset = offset;
        spt_e->read_bytes = page_read_bytes;

        hash_insert(&cur->spt, &spt_e->elem);

        mmap_e->page_count++;
        file_len -= page_read_bytes;
        offset += PGSIZE;
      }

      if (overlap_found)
      {
        //Desfaz as SPT entries que já foram criadas 
        for (size_t i = 0; i < mmap_e->page_count; i++)
        {
          void *page_to_free = mmap_e->addr + (i * PGSIZE);
          struct spt_entry *spt_e = spt_find_page(&cur->spt, page_to_free);
          if (spt_e)
          {
            hash_delete(&cur->spt, &spt_e->elem);
            free(spt_e);
          }
        }

        list_remove(&mmap_e->elem);
        free(mmap_e);
        file_close(reopened_file);
        f->eax = -1;
      }
      else
      {
        f->eax = mmap_e->mapid;
      }
      break;
    }

    case SYS_MUNMAP:
    {
      validate_user_pointer(f->esp + 7);
      mapid_t mapping = *(mapid_t *)(f->esp + 4);
      do_munmap(mapping);
      break;
    }

    default:
    {
      thread_exit();
      break;
    }
  }
}

/* Sai da thread e define o status de saída. */
void thread_exit_with_status(int status)
{
  struct thread *cur = thread_current();
  cur->exit_status = status;
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}