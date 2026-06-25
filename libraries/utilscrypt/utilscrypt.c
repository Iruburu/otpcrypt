#include "utilscrypt.h"
#include "findargs.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printError(const char *msg, const char *file) {
  fprintf(stderr, "Erro: %s '%s'\n", msg, file);
}

int getSizeKey(const char *size_key_opt) {
  if (strcmp(size_key_opt, "64") == 0)
    return KEY_64_BITS;
  else if (strcmp(size_key_opt, "128") == 0)
    return KEY_128_BITS;
  else if (strcmp(size_key_opt, "192") == 0)
    return KEY_192_BITS;
  else if (strcmp(size_key_opt, "256") == 0)
    return KEY_256_BITS;
  return 0;
}

int createKey(unsigned char *key, size_t size) {
  FILE *fptr;

  fptr = fopen("/dev/urandom", "rb");

  if (fptr == NULL) {
    perror("Erro: nao foi possivel ler arquivo '/dev/urandom'.");
    fclose(fptr);
    exit(1);
  }

  size_t bytesRead = fread(key, 1, size, fptr);

  if (bytesRead < size) {
    printf("Erro: nao foi possivl pegar conteudo de '/dev/urandom'.");
    fclose(fptr);
    exit(1);
  }

  fclose(fptr);

  return 0;
}

int decrypter(const char *input, const char *input_key, const char *output) {
  FILE *crypted_fptr;
  FILE *key_fptr;
  FILE *out_fptr;

  crypted_fptr = fopen(input, "rb");
  if (crypted_fptr == NULL) {
    printError("nao foi possivel abrir o arquivo", input);
    return -1;
  }

  key_fptr = fopen(input_key, "rb");
  if (key_fptr == NULL) {
    printError("nao foi possivel abrir o arquivo", input_key);
    fclose(crypted_fptr);
    return -1;
  }

  out_fptr = fopen(output, "wb");
  if (out_fptr == NULL) {
    printError("nao foi possivel criar arquivo decifrado", output);
    fclose(crypted_fptr);
    fclose(key_fptr);
    return -1;
  }

  unsigned char buff[1024];
  unsigned char key_buff[1024];

  size_t n1, n2, writeen;

  while ((n1 = fread(buff, 1, sizeof(buff), crypted_fptr)) > 0) {
    n2 = fread(key_buff, 1, n1, key_fptr);

    if (n1 != n2) {
      fprintf(
          stderr,
          "Erro: o arquivo de chave terminou antes do arquivo criptografado.\n"
          "Verifique se a chave corresponde ao arquivo utilizado na "
          "criptografia.\n");

      return -1;
    }

    for (size_t i = 0; i < n1; i++) {
      buff[i] ^= key_buff[i];
    }

    writeen = fwrite(buff, 1, n1, out_fptr);
    if (writeen != n1) {
      printError("falha ao gravar dados no arquivo de saida", output);
    }
  }

  fclose(crypted_fptr);
  fclose(key_fptr);
  fclose(out_fptr);

  return 0;
}

int crypter(const char *input, const char *output, const char *output_key) {
  FILE *fptr;
  FILE *save_fptr;
  FILE *save_key_fptr;

  fptr = fopen(input, "rb");
  if (fptr == NULL) {
    printError("nao foi possivel abrir o arquivo", input);
    return -1;
  }

  save_fptr = fopen(output, "wb");
  if (save_fptr == NULL) {
    printError("nao foi possivel criar arquivo cifrado", output);
    fclose(fptr);
    return -1;
  }

  save_key_fptr = fopen(output_key, "wb");
  if (save_key_fptr == NULL) {
    printError("nao foi possivel criar arquivo de chave", output_key);
    fclose(fptr);
    fclose(save_fptr);
    return -1;
  }

  unsigned char buff[1024];
  unsigned char key[1024];
  size_t n1, writeen1, writeen2;

  createKey(key, sizeof(key));
  size_t idxKey;

  while ((n1 = fread(buff, 1, sizeof(buff), fptr)) > 0) {

    for (idxKey = 0; idxKey < n1; ++idxKey) {
      buff[idxKey] ^= key[idxKey];
    }

    writeen1 = fwrite(buff, 1, n1, save_fptr);
    if (writeen1 != n1) {
      printError("nao foi possivel gravar o arquivo criptografado", output);
    }

    writeen2 = fwrite(key, 1, n1, save_key_fptr);
    if (writeen2 != n1) {
      printError("nao foi possivel gravar o arquivo de chave", output_key);
    }
  }

  fclose(fptr);
  fclose(save_fptr);
  fclose(save_key_fptr);

  return 0;
}

int streamDecrypter(const char *input, const char *input_key,
                    const char *output) {
  FILE *crypted_fptr;
  FILE *key_fptr;
  FILE *out_fptr;

  crypted_fptr = fopen(input, "rb");
  if (crypted_fptr == NULL) {
    printError("nao foi possivel abrir o arquivo", input);
    return -1;
  }

  key_fptr = fopen(input_key, "rb");
  if (key_fptr == NULL) {
    printError("nao foi possivel abrir o arquivo", input_key);
    fclose(crypted_fptr);
    return -1;
  }

  out_fptr = fopen(output, "wb");
  if (out_fptr == NULL) {
    printError("nao foi possivel criar arquivo decifrado", output);
    fclose(crypted_fptr);
    fclose(key_fptr);
    return -1;
  }

  fseek(key_fptr, 0, SEEK_END); // Move o ponteiro para o final
  size_t len_key =
      ftell(key_fptr); // Pega a posição do ponteiro e retorna tamanho em bits

  fseek(key_fptr, 0, SEEK_SET); // volta o ponteiro ao inicio

  unsigned char buff[1024];
  unsigned char key[len_key];
  size_t n1, writeen1;
  int count_stream = 0;

  fread(key, 1, len_key, key_fptr);

  while ((n1 = fread(buff, 1, sizeof(buff), crypted_fptr))) {
    for (int i = 0; i < n1; ++i) {
      buff[i] ^= key[count_stream];

      if (count_stream < len_key - 1)
        count_stream++;
      else
        count_stream = 0;
    }

    writeen1 = fwrite(buff, 1, n1, out_fptr);
    if (writeen1 != n1) {
      printError("nao foi possivel gravar o arquivo decifrado", output);
    }
  }

  return 0;
}

int streamCrypter(const char *input, const char *size_key_opt,
                  const char *output_key, const char *output) {
  FILE *fptr;
  FILE *save_fptr;
  FILE *save_key_fptr;

  fptr = fopen(input, "rb");
  if (fptr == NULL) {
    printError("nao foi possivel abrir o arquivo", input);
    return -1;
  }

  save_fptr = fopen(output, "wb");
  if (save_fptr == NULL) {
    printError("nao foi possivel criar arquivo cifrado", output);
    fclose(fptr);
    return -1;
  }

  save_key_fptr = fopen(output_key, "wb");
  if (save_key_fptr == NULL) {
    printError("nao foi possivel criar arquivo de chave", output_key);
    fclose(fptr);
    fclose(save_fptr);
    return -1;
  }

  size_t size_key;
  if ((size_key = getSizeKey(size_key_opt)) == 0) {
    printError("tamanho de chave invalida ou nao compativel",
               "Use: 32|128|192|256");
    return 1;
  }

  unsigned char buff[1024];
  unsigned char key[size_key];
  size_t n1, writeen1, writeen2;
  int count_stream = 0;

  createKey(key, size_key);

  while ((n1 = fread(buff, 1, sizeof(buff), fptr)) > 0) {
    for (size_t i = 0; i < n1; ++i) {
      buff[i] ^= key[count_stream];

      if (count_stream < size_key - 1)
        count_stream++;
      else
        count_stream = 0;
    }

    writeen1 = fwrite(buff, 1, n1, save_fptr);
    if (writeen1 != n1) {
      printError("nao foi possivel gravar o arquivo criptografado", output);
    }
  }

  writeen2 = fwrite(key, 1, size_key, save_key_fptr);
  if (writeen2 != size_key) {
    printError("nao foi possivel gravar o arquivo de chave", output_key);
  }

  return 0;
}

int blockDecrypter(const char *input, const char *input_key,
                   const char *output) {
  FILE *fptr;
  FILE *save_fptr;
  FILE *key_fptr;

  fptr = fopen(input, "rb");
  if (fptr == NULL) {
    printError("nao foi possivel abrir o arquivo", input);
    return -1;
  }

  save_fptr = fopen(output, "wb");
  if (save_fptr == NULL) {
    printError("nao foi possivel criar arquivo cifrado", output);
    fclose(fptr);
    return -1;
  }

  key_fptr = fopen(input_key, "rb");
  if (key_fptr == NULL) {
    printError("nao foi possivel criar arquivo de chave", input_key);
    fclose(fptr);
    fclose(save_fptr);
    return -1;
  }

  unsigned char current_buff[BLOCK_SIZE];
  unsigned char next_buff[BLOCK_SIZE];
  unsigned char key[BLOCK_SIZE];

  size_t current_bytes_r = 0;
  size_t next_bytes_r = 0;
  size_t key_bytes_r = 0;
  size_t writeen = 0;

  current_bytes_r = fread(current_buff, 1, BLOCK_SIZE, fptr);
  if (current_bytes_r == 0) {
    printf("Erro na leitura do cifrado\n");
    return -1;
  }

  key_bytes_r = fread(key, 1, BLOCK_SIZE, key_fptr);
  if (key_bytes_r == 0) {
    printf("erro na key");
    return -1;
  }

  while ((next_bytes_r = fread(next_buff, 1, BLOCK_SIZE, fptr)) > 0) {
    for (size_t i = 0; i < current_bytes_r; ++i) {
      current_buff[i] ^= key[i];
    }

    writeen = fwrite(current_buff, 1, BLOCK_SIZE, save_fptr);
    if (writeen != current_bytes_r) {
      printError("nao foi possivel gravar o arquivo decifrado", output);
    }

    memcpy(current_buff, next_buff, BLOCK_SIZE);
    current_bytes_r = next_bytes_r;
  }

  for (size_t i = 0; i < current_bytes_r; ++i) {
    current_buff[i] ^= key[i];
  }

  unsigned char padding_val = current_buff[BLOCK_SIZE - 1];
 
  if (padding_val > 0 && padding_val <= BLOCK_SIZE) {
    size_t actual_data_size = BLOCK_SIZE - padding_val;

    if (actual_data_size > 0) {
      fwrite(current_buff, 1, actual_data_size, save_fptr);
    }
  } else {
    printf("Arquivo fudido\n");
  }

  return 0;
}
int blockCypher(const char *input, const char *output_key, const char *output) {
  FILE *fptr;
  FILE *save_fptr;
  FILE *save_key_fptr;

  fptr = fopen(input, "rb");
  if (fptr == NULL) {
    printError("nao foi possivel abrir o arquivo", input);
    return -1;
  }

  save_fptr = fopen(output, "wb");
  if (save_fptr == NULL) {
    printError("nao foi possivel criar arquivo cifrado", output);
    fclose(fptr);
    return -1;
  }

  save_key_fptr = fopen(output_key, "wb");
  if (save_key_fptr == NULL) {
    printError("nao foi possivel criar arquivo de chave", output_key);
    fclose(fptr);
    fclose(save_fptr);
    return -1;
  }

  size_t size_key = BLOCK_SIZE;

  unsigned char buff[size_key];
  unsigned char key[size_key];
  size_t r_bytes, writeen1, writeen2;

  createKey(key, size_key);

  while ((r_bytes = fread(buff, 1, size_key, fptr)) == BLOCK_SIZE) {

    for (size_t i = 0; i < r_bytes; ++i) {
      buff[i] ^= key[i];
    }

    writeen1 = fwrite(buff, 1, BLOCK_SIZE, save_fptr);
    if (writeen1 != r_bytes) {
      printError("nao foi possivel gravar o arquivo criptografado", output);
    }
  }

  if (r_bytes > 0) {
    uint8_t padding_val = BLOCK_SIZE - r_bytes;

    for (size_t i = r_bytes; i < BLOCK_SIZE; ++i) {
      buff[i] = padding_val;
    }

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      buff[i] ^= key[i];
    }

    writeen1 = fwrite(buff, 1, BLOCK_SIZE, save_fptr);
    if (writeen1 != BLOCK_SIZE) {
      printError("nao foi possivel gravar o arquivo criptografado", output);
    }
  } else {
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      buff[i] = BLOCK_SIZE;
    }

    for (size_t i = 0; i < r_bytes; ++i) {
      buff[i] ^= key[i];
    }

    writeen1 = fwrite(buff, 1, BLOCK_SIZE, save_fptr);
    if (writeen1 != BLOCK_SIZE) {
      printError("nao foi possivel gravar o arquivo criptografado", output);
    }
  }

  writeen2 = fwrite(key, 1, size_key, save_key_fptr);
  if (writeen2 != size_key) {
    printError("nao foi possivel gravar o arquivo de chave", output_key);
  }

  return 0;
}
