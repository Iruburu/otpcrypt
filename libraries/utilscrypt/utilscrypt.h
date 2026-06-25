#ifndef UTILSCRYPT_H
#define UTILSCRYPT_H

#define KEY_64_BITS (64 / 8)
#define KEY_128_BITS (128 / 8)
#define KEY_192_BITS (192 / 8)
#define KEY_256_BITS (256 / 8)

#define BLOCK_SIZE 16

int decrypter(const char *input, const char *input_key, const char *output);
int crypter(const char *input, const char *output, const char *output_keyi);
int streamDecrypter(const char *input, const char *input_key,
                    const char *output);
int streamCrypter(const char *input, const char *size_key_opt,
                  const char *output_key, const char *output);
int blockDecrypter(const char *input, const char *input_key,
                   const char *output);
int blockCypher(const char *input, const char *output_key, const char *output);

#endif
