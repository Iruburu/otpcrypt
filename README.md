# otpcrypt

`otpcrypt` é uma implementação em C do algoritmo **One-Time Pad (OTP)** e **Stream Cipher** para fins de estudo de criptografia.

O programa possui dois modos de criptografia, **Stream Cipher** e **One-Time Pad (OTP)**. O **OTP** gera uma chave aleatória do mesmo tamanho do arquivo. E **Stream Cipher** gera uma chave de tamanho que o cliente especificar (64, 128, 192 ou 256bits).

> **Aviso:** Este projeto foi desenvolvido para aprendizado. Não deve ser utilizado para proteger informações sensíveis em ambientes de produção.

---

## Funcionalidades

* Criptografia utilizando XOR.
* Geração automática de chave aleatória.
* Decifragem utilizando a chave gerada.
* Interface simples via linha de comando.
* Projeto escrito em C.
* Compilação utilizando Makefile.

---

## Compilação

Clone o repositório:

```bash
git clone https://github.com/SEU_USUARIO/otpcrypt.git
cd otpcrypt
```

Compile o projeto:

```bash
make
```

O executável será gerado na pasta:

```text
build/
```

---

## Uso

Para especificar o metodo que deseja usar, use a flag `-m`:

**One-Time Pad**:

```bash
./build/otpcrypt -c arquivo.txt -m otp
```

**Stream Cipher**:

```bash
./build/otpcrypt -c arquivo.txt -m stream
```

### Criptografar um arquivo usando OPT

```bash
./build/otpcrypt -c arquivo.txt -m otp -o arquivo.enc -k chave.bin
```

Parâmetros:

* `-c` Arquivo que será criptografado.
* `-m` Especificar método
* `-o` Arquivo de saída.
* `-k` Arquivo onde a chave será salva.

---

#### Decifrar One-Time Pad

```bash
./build/otpcrypt -d arquivo.enc -m otp -o arquivo.txt -k chave.bin
```

Parâmetros:

* `-d` Arquivo criptografado.
* `-m` Especificar método.
* `-o` Arquivo de saída.
* `-k` Arquivo contendo a chave utilizada na criptografia.

---

### Criptografar arquivo usando Stream Cipher

```bash
./buld/otpcrypt -c arquivo.txt -m stream -k key -o arquivo.enc -s 64
```

Parâmetros:

* `-c` Arquivo criptografado.
* `-m` Especificar método.
* `-k` Arquivo onde a chave será salva.
* `-o` Arquivo de saída.
* `-s` Tamanho da chave.

#### Decifrar Stream Cipher

```bash
./build/otpcrypt -d arquivo.enc -m stream -o arquivo.txt -k chave.bin
```

Parâmetros:

* `-d` Arquivo criptografado.
* `-m` Especificar método.
* `-o` Arquivo de saída.
* `-k` Arquivo contendo a chave utilizada na criptografia.

---

### Ajuda

```bash
./build/otpcrypt -h
```

---

## Estrutura do projeto

```text
.
├── build/
├── libraries/
├── Makefile
└── README.md
```

---

## Requisitos

* GCC
* Make

---

## Licença

Este projeto está disponível sob a licença MIT.

