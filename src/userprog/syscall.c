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


static void syscall_handler (struct intr_frame *);
//Adicionado
static void validate_user_pointer(const void *uaddr);
static struct lock filesys_lock;

void
syscall_init(void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  //Adição
  lock_init(&filesys_lock);
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

    validate_user_pointer(buffer);
    if (size > 0)
    {
      validate_user_pointer(buffer + size - 1);
    }

    int bytes_written = -1; // caso de erro

    if (fd == 1)
    {
      const char *user_ptr = (const char *)buffer;
      bytes_written = 0;
      while ((unsigned)bytes_written < size)
      {
        unsigned bytes_left_in_page = PGSIZE - pg_ofs(user_ptr);
        unsigned bytes_to_write = size - bytes_written;
        if (bytes_to_write > bytes_left_in_page)
        {
          bytes_to_write = bytes_left_in_page;
        }
        void *k_ptr = pagedir_get_page(thread_current()->pagedir, user_ptr);
        if (k_ptr == NULL)
        {
          struct thread *cur = thread_current();
          printf("%s: exit(%d)\n", cur->name, -1);
          cur->exit_status = -1;
          thread_exit();
        }
        putbuf(k_ptr, bytes_to_write);
        bytes_written += bytes_to_write;
        user_ptr += bytes_to_write;
      }
    }
    else if (fd >= 2 && fd < 128)
    {
      struct thread *cur = thread_current();
      struct file *file_ptr = cur->open_files[fd];

      if (file_ptr == NULL)
      {
        // fd não está aberto ou é inválido, bytes_written já é -1
      }
      else
      {
        lock_acquire(&filesys_lock);

        const char *user_ptr = (const char *)buffer;
        bytes_written = 0;

        while ((unsigned)bytes_written < size)
        {
          // Calcula quanto escrever *nesta página*
          unsigned bytes_left_in_page = PGSIZE - pg_ofs(user_ptr);
          unsigned bytes_to_write = size - bytes_written;
          if (bytes_to_write > bytes_left_in_page)
          {
            bytes_to_write = bytes_left_in_page;
          }

          void *k_ptr = pagedir_get_page(thread_current()->pagedir, user_ptr);
          if (k_ptr == NULL)
          {
            lock_release(&filesys_lock);
            struct thread *cur_err = thread_current();
            printf("%s: exit(%d)\n", cur_err->name, -1);
            cur_err->exit_status = -1;
            thread_exit();
          }

          // Escreve o pedaço do KERNEL para o arquivo
          int current_written = file_write(file_ptr, k_ptr, bytes_to_write);

          if (current_written <= 0)
          { // Erro na escrita ou escreveu 0 bytes inesperadamente
            if (bytes_written == 0)
            {
              bytes_written = -1; // Sinaliza erro
            }
            break;
          }
          bytes_written += current_written;
          user_ptr += current_written;

          if ((unsigned)current_written < bytes_to_write)
          {
            break;
          }
        }

        lock_release(&filesys_lock);
      }
    }

    // Define o valor de retorno (bytes escritos ou -1) em EAX
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
      validate_user_pointer(file);

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
      validate_user_pointer(filename);

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

      validate_user_pointer(buffer);
      if (size > 0)
      {
        validate_user_pointer(buffer + size - 1);
      }

      int bytes_read = -1;

      if (fd == 0)
      {
        unsigned i;
        uint8_t *buf_ptr = (uint8_t *)buffer;
        for (i = 0; i < size; i++)
        {
          buf_ptr[i] = input_getc();
        }
        bytes_read = i;
      }
      else if (fd >= 2 && fd < 128)
      {
        struct thread *cur = thread_current();
        struct file *file_ptr = cur->open_files[fd];

        if (file_ptr == NULL)
        {
          // fd inválido ou não aberto, bytes_read permanece -1
        }
        else
        {
          char *kernel_buffer = palloc_get_page(0);
          if (kernel_buffer == NULL)
          {
            bytes_read = -1;
          }
          else
          {
            bytes_read = 0;
            char *user_buf_ptr = (char *)buffer;

            lock_acquire(&filesys_lock);

            while (bytes_read < (int)size)
            {
              int bytes_to_read_this_time = size - bytes_read;
              if (bytes_to_read_this_time > PGSIZE)
              {
                bytes_to_read_this_time = PGSIZE;
              }
              if (bytes_to_read_this_time <= 0)
              {
                break;
              }

              // Lê do arquivo PARA o buffer do KERNEL
              int current_read = file_read(file_ptr, kernel_buffer, bytes_to_read_this_time);

              if (current_read <= 0)
              {// EOF ou erro na leitura do arquivo
                break;
              }

              // Copia do buffer do KERNEL para o buffer do USUÁRIO
              memcpy(user_buf_ptr + bytes_read, kernel_buffer, current_read);

              bytes_read += current_read;

              // Se leu menos que o solicitado, atingiu EOF
              if (current_read < bytes_to_read_this_time)
              {
                break;
              }
            }

            lock_release(&filesys_lock);
            palloc_free_page(kernel_buffer);
          }
        }
      }

      // Define o valor de retorno (bytes lidos ou -1) em EAX
      f->eax = bytes_read;
      break;
    }

    case SYS_EXEC:
    {
      validate_user_pointer(f->esp + 7);

      // Obtém o argumento (ponteiro para a string da linha de comando)
      const char *cmd_line = *(const char **)(f->esp + 4);
      validate_user_pointer(cmd_line);

      tid_t child_tid = process_execute(cmd_line);

      // Define o valor de retorno (o TID do filho ou -1) em EAX
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
        f->eax = -1; // Retorna -1 se o fd não estiver aberto
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
      validate_user_pointer(filename);

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

    default:
    {
      thread_exit();
      break;
    }
  }
}

// Valida um ponteiro do espaço de usuário.
// Encerra o processo se o ponteiro for inválido.
static void
validate_user_pointer(const void *uaddr)
{
  struct thread *cur = thread_current();
  // Verifica se não é nulo e se está abaixo de PHYS_BASE, e se está mapeado na tabela de páginas.
  if (uaddr == NULL || !is_user_vaddr(uaddr) || pagedir_get_page(cur->pagedir, uaddr) == NULL)
  {
    printf("%s: exit(%d)\n", cur->name, -1);
    cur->exit_status = -1;
    thread_exit();
  }
}
