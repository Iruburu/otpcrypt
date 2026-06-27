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

// Faz a decifragem de bloco utilizando o modo CBC (Cipher Block Chaining)
int blockDecrypter(const char *input, const char *input_key,
                   const char *output) {
  FILE *encrypted_file;
  FILE *decrypted_file;
  FILE *key_file;

  // Validacao de arquivos de entrada, chave e saida
  encrypted_file = fopen(input, "rb");
  if (encrypted_file == NULL) {
    printError("nao foi possivel abrir o arquivo", input);
    return -1;
  }

  decrypted_file = fopen(output, "wb");
  if (decrypted_file == NULL) {
    printError("nao foi possivel criar arquivo cifrado", output);
    fclose(encrypted_file);
    return -1;
  }

  key_file = fopen(input_key, "rb");
  if (key_file == NULL) {
    printError("nao foi possivel criar arquivo de chave", input_key);
    fclose(encrypted_file);
    fclose(decrypted_file);
    return -1;
  }

  // Formulas matematicas de referencia para o CBC:
  // P1 = (C1 XOR K) XOR IV
  // P2 = (C2 XOR K) XOR C1
  // P3 = (C3 XOR K) XOR C2

  // Variaveis usadas na decifragem
  unsigned char IV[BLOCK_SIZE];
  unsigned char
      current_buff[BLOCK_SIZE]; // Armazena o bloco atual em processamento
  unsigned char
      next_buff[BLOCK_SIZE];     // Armazena o proximo bloco lido do arquivo
  unsigned char key[BLOCK_SIZE]; // Armazena a chave simetrica (K)

  size_t IV_bytes_r = 0;
  size_t current_bytes_r = 0; // Bytes do bloco atual lido
  size_t next_bytes_r = 0;    // Bytes do proximo bloco lido
  size_t key_bytes_r = 0;     // Bytes da chave lido
  size_t writeen = 0;         // Bytes escritos

  // 1. Carrega o Vetor de Inicializacao (IV)
  IV_bytes_r = fread(IV, 1, BLOCK_SIZE, encrypted_file);
  if (IV_bytes_r == 0) {
    printError("nao foi possivel carregar IV", input);
    fclose(encrypted_file);
    fclose(decrypted_file);
    fclose(key_file);
    return -1;
  }

  // 2. Carrega o primeirissimo bloco cifrado (C1) para o buffer atual
  current_bytes_r = fread(current_buff, 1, BLOCK_SIZE, encrypted_file);
  if (current_bytes_r == 0) {
    printError("nao foi possivel carregar arquivo cifrado", input);
    fclose(encrypted_file);
    fclose(decrypted_file);
    fclose(key_file);
    return -1;
  }

  // Variaveis para armazenar o historico de blocos cifrados puros
  unsigned char previous_buff[BLOCK_SIZE];
  unsigned char copy_current_buff[BLOCK_SIZE];

  // Salva C1 puro no historico antes das alteracoes matematicas
  memcpy(previous_buff, current_buff, BLOCK_SIZE);

  // 3. Carrega a chave simetrica (K)
  key_bytes_r = fread(key, 1, BLOCK_SIZE, key_file);
  if (key_bytes_r == 0) {
    printError("nao foi possivel carregar a chave", input_key);
    fclose(encrypted_file);
    fclose(decrypted_file);
    fclose(key_file);
    return -1;
  }

  // Inicio da decifragem de P1: Remove a camada da chave -> (C1 XOR K)
  for (size_t i = 0; i < current_bytes_r; ++i) {
    current_buff[i] ^= key[i];
  }

  // Finaliza decifragem de P1: Aplica XOR com o IV -> ((C1 XOR K) XOR IV)
  for (size_t i = 0; i < IV_bytes_r; ++i) {
    current_buff[i] ^= IV[i];
  }

  // Grava o primeiro bloco decifrado (P1) no arquivo de texto limpo
  writeen = fwrite(current_buff, 1, current_bytes_r, decrypted_file);
  if (writeen != current_bytes_r) {
    printError("nao foi possivel gravar o arquivo decifrado", output);
    fclose(encrypted_file);
    fclose(decrypted_file);
    fclose(key_file);
    return -1;
  }

  // Carrega adiantado o segundo bloco cifrado (C2) para iniciar a estrutura do
  // loop
  current_bytes_r = fread(current_buff, 1, BLOCK_SIZE, encrypted_file);

  // LOOP PRINCIPAL: Processa blocos intermediarios ate encontrar o bloco final
  while ((next_bytes_r = fread(next_buff, 1, BLOCK_SIZE, encrypted_file)) ==
         BLOCK_SIZE) {

    // Guarda uma copia de seguranca do bloco cifrado atual antes de modifica-lo
    memcpy(copy_current_buff, current_buff, BLOCK_SIZE);

    // Inicio da decifragem do bloco intermediario: Remove a chave -> (C_atual
    // XOR K)
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      current_buff[i] ^= key[i];
    }

    // Finaliza decifragem do bloco: Aplica XOR com o bloco cifrado anterior ->
    // ((C_atual XOR K) XOR C_anterior)
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      current_buff[i] ^= previous_buff[i];
    }

    // Escreve o texto claro resultante (P) no arquivo de saida
    writeen = fwrite(current_buff, 1, current_bytes_r, decrypted_file);
    if (writeen != next_bytes_r) {
      printError("nao foi possivel gravar o arquivo decifrado", output);
      fclose(encrypted_file);
      fclose(decrypted_file);
      fclose(key_file);
      return -1;
    }

    // Atualiza os buffers de historico para o proximo ciclo do loop
    memcpy(previous_buff, copy_current_buff,
           next_bytes_r); // O bloco atual puro vira o anterior
    memcpy(current_buff, next_buff,
           next_bytes_r); // O proximo bloco lido vira o bloco atual
    current_bytes_r = next_bytes_r;
  }

  // PROCESSAMENTO DO ULTIMO BLOCO E TRATAMENTO DE PADDING (PKCS#7)

  // Salva copia do ultimo bloco cifrado puro
  memcpy(copy_current_buff, current_buff, current_bytes_r);

  // Remove a chave do bloco final -> (C_final XOR K)
  for (size_t i = 0; i < BLOCK_SIZE; ++i) {
    current_buff[i] ^= key[i];
  }

  // Aplica XOR com o bloco cifrado anterior -> ((C_final XOR K) XOR C_anterior)
  for (size_t i = 0; i < BLOCK_SIZE; ++i) {
    current_buff[i] ^= previous_buff[i];
  }

  // O ultimo byte do texto decifrado indica o tamanho do preenchimento
  // adicionado
  unsigned char padding_val = current_buff[BLOCK_SIZE - 1];

  // Faz a verificacao para saber se o valor do preenchimento e valido (entre 1
  // e 16)
  if (padding_val > 0 && padding_val <= BLOCK_SIZE) {
    // Calcula a quantidade real de dados textuais puros que devem ser mantidos
    size_t actual_data_size = BLOCK_SIZE - padding_val;

    // Se houver dados validos no bloco final, grava apenas a quantidade real
    // descartando o padding
    if (actual_data_size > 0) {
      writeen = fwrite(current_buff, 1, actual_data_size, decrypted_file);
      if (writeen != actual_data_size) {
        printError("nao foi possivel gravar o arquivo decifrado", output);
        fclose(encrypted_file);
        fclose(decrypted_file);
        fclose(key_file);
        return -1;
      }
    }
  } else {
    // Avisa que o arquivo sofreu alteracoes ou a chave utilizada esta incorreta
    printError("arquivo corrompido ou chave incorreta", input);
    fclose(encrypted_file);
    fclose(decrypted_file);
    fclose(key_file);
    return -1;
  }

  // Fecha todos os ponteiros de arquivos abertos com sucesso
  fclose(encrypted_file);
  fclose(decrypted_file);
  fclose(key_file);

  return 0;
}

// Faz a cifragem em bloco utilizando o modo CBC (Cipher Block Chaining)
int blockCypher(const char *input, const char *output_key, const char *output) {
  FILE *fptr;
  FILE *save_fptr;
  FILE *save_key_fptr;

  // Validacao de arquivos de entrada, saida e chave
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

  // Formulas matematicas de referencia para o CBC:
  // C1 = (P1 XOR IV) XOR K
  // C2 = (P2 XOR C1) XOR K
  // C3 = (P3 XOR C2) XOR K

  // Pega constante com tamanho de cada block
  const size_t size_key = BLOCK_SIZE;

  // Cria variaveis que serao usadas no processo
  unsigned char
      IV[size_key]; // Vetor de inicializacao (usado apenas no bloco 1)
  unsigned char current_buff[size_key]; // Guarda o bloco cifrado anterior
                                        // (historico para o CBC)
  unsigned char
      next_buff[size_key];     // Guarda o texto claro atual (P) lido do arquivo
  unsigned char key[size_key]; // Guarda a chave simetrica (K)
  size_t r_bytes, writeen1, writeen2; // Contadores de bytes lidos e gravados

  // Cria a chave (K) e o IV usando '/dev/urandom'
  createKey(key, size_key);
  createKey(IV, size_key);

  for (size_t i = 0; i < BLOCK_SIZE; ++i)
    printf("%hhx ", IV[i]);

  printf("\n");

  // Le o primeirissimo bloco de texto claro (P1)
  r_bytes = fread(current_buff, 1, BLOCK_SIZE, fptr);
  if (r_bytes != BLOCK_SIZE) {
    printError("nao foi possivel ler arquvo de entrada", input);
    fclose(fptr);
    fclose(save_fptr);
    fclose(save_key_fptr);
    return -1;
  }

  // Inicio da cifragem de C1: Aplica XOR entre o texto claro e o IV -> (P1 XOR
  // IV)
  for (size_t i = 0; i < BLOCK_SIZE; ++i) {
    current_buff[i] ^= IV[i];
  }

  // Finaliza cifragem de C1: Aplica XOR com a chave -> ((P1 XOR IV) XOR K)
  for (size_t i = 0; i < BLOCK_SIZE; ++i) {
    current_buff[i] ^= key[i];
  }

  // Escreve o IV e o primeiro bloco cifrado (C1) no arquivo de saida
  writeen2 = fwrite(IV, 1, BLOCK_SIZE, save_fptr);
  writeen1 = fwrite(current_buff, 1, BLOCK_SIZE, save_fptr);
  if (writeen2 != BLOCK_SIZE || writeen1 != BLOCK_SIZE) {
    printError("nao foi possivel escrever arquivo de saida", output);
    fclose(fptr);
    fclose(save_fptr);
    fclose(save_key_fptr);
    return -1;
  }

  // LOOP PRINCIPAL: Processa blocos cheios de texto claro (P2, P3, etc.)
  while ((r_bytes = fread(next_buff, 1, size_key, fptr)) == BLOCK_SIZE) {

    printf("Orig: ");
    for (int i = 0; i < BLOCK_SIZE; ++i) {
      printf("%hhx ", next_buff[i]);
    }
    printf("\nXOR:  ");

    // Inicio da cifragem do bloco atual: Aplica XOR com o bloco cifrado
    // anterior (C_anterior) Formula: (P_atual XOR C_anterior)
    for (size_t i = 0; i < r_bytes; ++i) {
      next_buff[i] ^= current_buff[i];
      printf("%hhx ", current_buff[i]);
    }
    printf("\nKey:  ");

    // Finaliza cifragem do bloco atual: Aplica XOR com a chave (K)
    // Formula: ((P_atual XOR C_anterior) XOR K)
    for (size_t i = 0; i < r_bytes; ++i) {
      next_buff[i] ^= key[i];
      printf("%hhx ", key[i]);
    }
    printf("\nres:  ");

    for (int i = 0; i < BLOCK_SIZE; ++i) {
      printf("%hhx ", next_buff[i]);
    }
    printf("\n\n");

    // Salva o bloco cifrado resultante no arquivo de saida
    writeen1 = fwrite(next_buff, 1, BLOCK_SIZE, save_fptr);
    if (writeen1 != BLOCK_SIZE) {
      printError("nao foi possivel gravar o arquivo criptografado", output);
    }

    // Copia o bloco cifrado atual para 'current_buff' para servir de historico
    // no proximo ciclo
    memcpy(current_buff, next_buff, r_bytes);
  }

  // TRATAMENTO DE PADDING (PKCS#7): Garante que o ultimo bloco tenha 16 bytes

  // CASO A: O arquivo terminou com um bloco incompleto (entre 1 e 15 bytes)
  if (r_bytes > 0) {
    // Calcula quantos bytes faltam para completar 16
    uint8_t padding_val = BLOCK_SIZE - r_bytes;

    // Preenche o restante do buffer com o valor numerico do proprio padding
    for (size_t i = r_bytes; i < BLOCK_SIZE; ++i) {
      next_buff[i] = padding_val;
    }

    // Aplica o CBC no bloco preenchido: XOR com o bloco cifrado anterior ->
    // (P_final XOR C_anterior)
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      next_buff[i] ^= current_buff[i];
    }

    // Finaliza cifragem do bloco final: XOR com a chave -> ((P_final XOR
    // C_anterior) XOR K)
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      next_buff[i] ^= key[i];
    }

    // Grava o ultimo bloco cifrado no arquivo de saida
    writeen1 = fwrite(next_buff, 1, BLOCK_SIZE, save_fptr);
    if (writeen1 != BLOCK_SIZE) {
      printError("nao foi possivel gravar o arquivo criptografado", output);
    }

    // CASO B: O arquivo terminou exatamente em um bloco cheio.
    // Devemos criar um bloco extra preenchido inteiramente com o valor 16
    // (0x10).
  } else {
    // Preenche todo o bloco com o valor 16
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      next_buff[i] = BLOCK_SIZE;
    }

    // Aplica o CBC no bloco extra: XOR com o bloco cifrado anterior -> (P_extra
    // XOR C_anterior)
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      next_buff[i] ^= current_buff[i];
    }

    // Finaliza cifragem do bloco extra: XOR com a chave -> ((P_extra XOR
    // C_anterior) XOR K)
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
      next_buff[i] ^= key[i];
    }

    // Salva o bloco extra cifrado no arquivo de saida
    writeen1 = fwrite(next_buff, 1, BLOCK_SIZE, save_fptr);
    if (writeen1 != BLOCK_SIZE) {
      printError("nao foi possivel gravar o arquivo criptografado", output);
    }
  }

  // Salva a chave secreta (K) gerada pelo sistema no arquivo de chaves separado
  writeen2 = fwrite(key, 1, size_key, save_key_fptr);
  if (writeen2 != size_key) {
    printError("nao foi possivel gravar o arquivo de chave", output_key);
  }

  // Fecha todos os ponteiros de arquivos abertos
  fclose(fptr);
  fclose(save_fptr);
  fclose(save_key_fptr);

  return 0;
}
