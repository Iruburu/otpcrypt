#include "findargs.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRUE 1
#define FALSE 0

int configFindArg(int argc, char *argv[], FindArgs *args) {
  args->arg_count = 0;
  args->arg_count = argc;
  args->arg_vetors = argv;

  return 0;
}

int addFlags(const char *flag,     // flag em si
             const char *help,     // mensagem de ajuda
             uint8_t type,         // Recebe o tipo da flag
             const char *argument, // argumento que deve receber
             FindArgs *args) {     // recebe a estrutura ultilizada

  if (args->count_args >= LIMIT_FLAG) {
    printf("Erro: limite maximo de flags excedida\n");
    exit(1);
  }

  size_t max_flag_size = sizeof(args->args_list[args->count_args].arg);
  size_t max_help_size = sizeof(args->args_list[args->count_args].help);
  size_t max_argument_size = sizeof(args->args_list[args->count_args].argument);

  if (type != 1 && type != 2) {
    printf("Erro: tipo de flag invalido\n");
    exit(1);
  }
  args->args_list[args->count_args].type = type;

  strncpy(args->args_list[args->count_args].arg, flag, max_flag_size);
  args->args_list[args->count_args].arg[max_flag_size - 1] = '\0';

  strncpy(args->args_list[args->count_args].help, help, max_help_size);
  args->args_list[args->count_args].help[max_help_size - 1] = '\0';

  strncpy(args->args_list[args->count_args].argument, argument,
          max_argument_size);
  args->args_list[args->arg_count].argument[max_argument_size - 1] = '\0';

  if (strlen(flag) >= max_flag_size) {
    printf("Aviso: flag %s foi truncada por exceder o limite\n", flag);
  }

  if (strlen(help) >= max_help_size) {
    printf("Aviso: help foi truncado por excerder o limite\n");
  }

  if (strlen(argument) >= max_argument_size) {
    printf("Aviso: argument foi truncado por exceder o limite\n");
  }

  args->count_args += 1;
  return 0;
}

void printHelp(const FindArgs *args) {
  printf("Uso:\n  %s [OPCAO] [ARGUMENTOS]\n\n", args->arg_vetors[0]);
  printf("Desricao:\n %s\n\n", args->desc);

  printf("Operacao:\n");
  for (size_t i = 0; i < args->count_args; i++) {
    if (args->args_list[i].type == 1)
      printf("  %s %-14s %s\n", args->args_list[i].arg,
             args->args_list[i].argument, args->args_list[i].help);
  }
  printf("\n");

  printf("Opcoes:\n");
  for (size_t i = 0; i < args->count_args; i++) {
    if (args->args_list[i].type == 2)
      printf("  %s %-14s %s\n", args->args_list[i].arg,
             args->args_list[i].argument, args->args_list[i].help);
  }
}

int isFlag(const char *flag, FindArgs args) {
  for (int i = 0; i < args.arg_count; ++i) {
    if (strcmp(flag, args.args_list[i].arg) == 0) {
      return FALSE;
    }
  }
  return TRUE;
}

// Procura uma flag booleana
// Exemplo:
// -v
// -debug
int findArgBoolean(const char *flag, FindArgs *args) {
  int i, result;
  for (i = 0; i < args->arg_count; ++i) {
    result = strcmp(args->arg_vetors[i], flag);
    if (result == 0 && isFlag(flag, *args)) {
      return TRUE;
    }
  }

  return FALSE;
}

// Procura uma flag que possui valor
// Exemplo:
// -u google.com
//
// Retorna o index do valor
int findArgValue(const char *flag, FindArgs *args) {
  int i;

  for (i = 0; i < args->arg_count; ++i) {
    if (strcmp(args->arg_vetors[i], flag) == 0) {

      // Verifica se existe valor apos a flag
      if (i + 1 >= args->arg_count) {
        fprintf(stderr, "Erro: valor de %s nao foi definido.\n", flag);
        exit(1);
      }

      if (!isFlag(args->arg_vetors[i + 1], *args)) {
        fprintf(stderr, "Erro: valor de %s nao foi definido.\n", flag);
        exit(1);
      }

      return i + 1;
    }
  }

  fprintf(stderr, "Erro: a flag %s nao foi informada.\n", flag);
  exit(1);
}

int tryGetArgValue(const char *flag, FindArgs *args) {
  int i;

  for (i = 0; i < args->arg_count; ++i) {

    if (strcmp(args->arg_vetors[i], flag) == 0) {

      // Verifica se existe valor apos a flag
      if (i + 1 >= args->arg_count) {
        return -1;
      }

      if (!isFlag(args->arg_vetors[i + 1], *args)) {
        return -1;
      }

      return i + 1;
    }
  }

  return -1;
}
