# PintOS - CIn UFPE

## Sobre
Este repositório serve como arquivo para os projetos desenvolvidos na disciplina de **Implementação de Sistemas Operacionais (IF709)**, ministrada pelo **Prof. Eduardo Tavares** no **Centro de Informática (CIn) da UFPE**.

O foco principal é o sistema operacional educativo **PintOS**, onde cada pasta representa uma etapa incremental do desenvolvimento, consolidando conceitos fundamentais de sistemas operacionais.

## Estrutura do Repositório

Diferente de fluxos de trabalho baseados em branches, este repositório organiza a evolução do projeto em diretórios distintos. Cada pasta contém o código-fonte completo (`src`) correspondente àquela fase da entrega.

### 📁 Original
Contém o **código base do PintOS** sem modificações. Serve como ponto de partida e referência para o estado inicial do sistema antes de qualquer implementação.

### � Projeto 2
Foca na implementação de **User Programs**.
- **Argument Passing**: Mecanismo para passar argumentos da linha de comando para os programas.
- **System Calls**: Implementação de chamadas de sistema para permitir que programas de usuário interajam com o kernel de forma segura.

### 📁 Projeto 3
Implementação de **Virtual Memory** (Gerência de Memória Virtual).
- **Page Table**: Gerenciamento de tabelas de páginas suplementares.
- **Stack Growth**: Suporte ao crescimento dinâmico da pilha.
- **Swapping**: Mecanismo de troca de páginas entre memória e disco.

### � Projeto 4
Implementação do **File System** (Sistema de Arquivos).
- **Arquivos Extensíveis**: Suporte ao crescimento de arquivos.
- **Subdiretórios**: Possibilidade de criar e navegar em hierarquias de pastas.
- **Buffer Cache**: Otimização de acesso ao disco via cache.

> **Nota**: O *Projeto 1 (Threads - Alarm Clock, Priority Scheduling)* foi desenvolvido, mas suas funcionalidades já estão integradas e evoluídas nas pastas dos projetos subsequentes.

## Tecnologias

- **Linguagem**: C
- **Baixo Nível**: Assembly x86
- **Emulação**: QEMU
- **Ambiente**: Linux

---
*Aviso Académico: Este código foi desenvolvido exclusivamente para fins educacionais no contexto da disciplina de Sistemas Operacionais.*
