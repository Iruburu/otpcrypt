#include <stddef.h>
#include <stdint.h>

#ifndef FINDARGS_H
#define FINDARGS_H

#define LIMIT_FLAG 32
#define LIMIT_SIZE_FLAG 64
#define LIMIT_SIZE_HELP 512

typedef struct {
  char arg[LIMIT_SIZE_FLAG];
  char help[LIMIT_SIZE_HELP];
  uint8_t type; // 1 = operaçao / 2 = opcao
  char argument[128]; // fala na hora do help
} Args_list;

typedef struct {
  char desc[512];
  Args_list args_list[LIMIT_FLAG];
  int count_args;
  int arg_count;
  char **arg_vetors;
} FindArgs;

int configFindArg(int argc, char *argv[], FindArgs *args);
void printHelp(const FindArgs *args);
int findArgBoolean(const char *arg, FindArgs *args);
int findArgValue(const char *arg, FindArgs *args);
int tryGetArgValue(const char *arg, FindArgs *args);

int addFlags(const char *flag, // flag em si
             const char *help, // mensagem de ajuda
             uint8_t type,
             const char *argument,
             FindArgs *args);

#endif
