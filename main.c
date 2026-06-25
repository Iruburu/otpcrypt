#include "findargs.h"
#include "utilscrypt.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {

  FindArgs args = {0};

  configFindArg(argc, argv, &args);
  strncpy(args.desc,
          "Ferramenta para criptografia usando One-Time-Pad e Cifra de Fluxo.",
          sizeof(args.desc));

  addFlags("-c", "Arquivo que sera cifrado", 1, "<ARQUIVO>", &args);
  addFlags("-d", "Arquivo que sera decifrado", 1, "<ARQUIVO>", &args);
  addFlags("-k", "Chave para cifrar/decifrar", 2, "<CHAVE>", &args);
  addFlags("-o", "Caminho do arquivo de saida", 2, "<ARQUIVO>", &args);
  addFlags("-h", "Mostra esta mensagem de ajuda e sai", 2, "", &args);
  addFlags("-m", "Seleciona o modo", 2, "<otp|stream>", &args);
  addFlags("-s", "escollhe o tamanho da chave", 2, "<64|...|256>", &args);

  int idxInFile,
      idxHelpOpt, // Flag para o help
      statusCode; // Status da ex

  statusCode = 0;
  if ((idxHelpOpt = findArgBoolean("-h", &args)) == 1) {
    printHelp(&args);
    return 0;
  }

  char *mode = argv[findArgValue("-m", &args)];
  char *idxOutFile = argv[findArgValue("-o", &args)];
  char *idxKeyFile = argv[findArgValue("-k", &args)];

  if (strcmp(mode, "otp") == 0) {

    if ((idxInFile = tryGetArgValue("-c", &args)) > 0) {
      crypter(argv[idxInFile], idxOutFile, idxKeyFile);
    } else if ((idxInFile = tryGetArgValue("-d", &args)) > 0) {
      decrypter(argv[idxInFile], idxKeyFile, idxOutFile);
    }

  } else if (strcmp(mode, "stream") == 0) {
    if ((idxInFile = tryGetArgValue("-c", &args)) > 0) {
      char *idxSzStream = argv[findArgValue("-s", &args)];
      streamCrypter(argv[idxInFile], idxSzStream, idxKeyFile, idxOutFile);
    } else if ((idxInFile = tryGetArgValue("-d", &args)) > 0) {
      streamDecrypter(argv[idxInFile], idxKeyFile, idxOutFile);
    }

  } else if (strcmp(mode, "block") == 0) {
    if ((idxInFile = tryGetArgValue("-c", &args)) > 0)
      blockCypher(argv[idxInFile], idxKeyFile, idxOutFile);
    else if ((idxInFile = tryGetArgValue("-d", &args)) > 0) {
      blockDecrypter(argv[idxInFile], idxKeyFile, idxOutFile);
    }
  } else {
    fprintf(stderr, "Modo invalido.\n");
  }


  if (statusCode < 0) {
    return 1;
  }

  return 0;
}
