#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

/* Este é um sistema de ponto fixo de 17.14, o que significa que
    há 17 bits para a parte inteira e 14 bits para a parte fracionária.
    O bit mais significativo é o de sinal. */

// Define o tipo para o número de ponto fixo
typedef int fixed_point_t;

// Define a quantidade de bits da parte fracionária
#define FRACTIONAL_BITS 14

// Fator de escala (2^14)
#define F (1 << FRACTIONAL_BITS)

// Converte um inteiro 'n' para ponto fixo
#define INT_TO_FIXED(n) ((n) * F)

// Converte um número de ponto fixo 'x' para inteiro (arredondando para zero)
#define FIXED_TO_INT_ZERO(x) ((x) / F)

// Converte um número de ponto fixo 'x' para inteiro (arredondando para o mais próximo)
#define FIXED_TO_INT_NEAREST(x) ((x) >= 0 ? (((x) + F / 2) / F) : (((x) - F / 2) / F))

// Adiciona dois números de ponto fixo 'x' e 'y'
#define ADD_FIXED(x, y) ((x) + (y))

// Subtrai dois números de ponto fixo 'x' e 'y'
#define SUB_FIXED(x, y) ((x) - (y))

// Adiciona um número de ponto fixo 'x' e um inteiro 'n'
#define ADD_FIXED_INT(x, n) ((x) + INT_TO_FIXED(n))

// Subtrai um inteiro 'n' de um número de ponto fixo 'x'
#define SUB_INT_FROM_FIXED(x, n) ((x) - INT_TO_FIXED(n))

// Multiplica dois números de ponto fixo 'x' e 'y'
#define MULT_FIXED(x, y) ((((int64_t) (x)) * (y)) / F)

// Multiplica um número de ponto fixo 'x' por um inteiro 'n'
#define MULT_FIXED_INT(x, n) ((x) * (n))

// Divide dois números de ponto fixo 'x' e 'y'
#define DIV_FIXED(x, y) ((((int64_t) (x)) * F) / (y))

// Divide um número de ponto fixo 'x' por um inteiro 'n'
#define DIV_FIXED_INT(x, n) ((x) / (n))

#endif /* threads/fixed-point.h */