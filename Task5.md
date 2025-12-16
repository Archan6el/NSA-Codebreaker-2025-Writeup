## Task 5 - Putting it all together - (Cryptanalysis)

> NSA analysts confirm that there is solid evidence that this binary was at least part of what had been installed on the military development network. Unfortunately, we do not yet have enough information to update NSA senior leadership on this threat. We need to move forward with this investigation!

> The team is stumped - they need to identify something about who was controlling this malware. They look to you. "Do you have any ideas?"

> Prompt: Submit the full URL to the adversary's server

### Solve:

Ah yes, the crypto task

Immediately, we can see that this task is pretty weird. It doesn't give us any new files. The solution to this task comes from what we have already found so far. 

To save the suspense, everything needed to solve this task comes from the pcap from task 2, and the last binary we found from task 4 (the binary that was inside the given binary)

We teased the interesting transmission in task 2, but it appears that the goal of this task is to decrypt these transmissions:

![image1](./images/task5img1.png)
![image2](./images/task5img2.png)

We actually know where these encrypted messages came from (specifically the messages in red)

Going back to Ghidra our beloved, in the binary from task 4, there is a class named `Comms`

> Again, note that I have already renamed functions based on my analysis of what they do

In said class, there was a function that I name `full_handshake`, which appears to establish a connection, and does so in a certain way

```c

/* WARNING: Unknown calling convention -- yet parameter storage is locked */
/* Comms::full_handshake() */

undefined8 Comms::full_handshake(void)

{
  int iVar1;
  long lVar2;
  undefined8 uVar3;
  long in_RDI;
  
  lVar2 = recv_rsa_pubkey();
  *(long *)(in_RDI + 0x40) = lVar2;
  if (lVar2 != 0) {
    iVar1 = send_aes_keys();
    free(*(void **)(in_RDI + 0x40));
    if (iVar1 == 0) {
      uVar3 = application_handshake();
      return uVar3;
    }
  }
  return 1;
}
```

As we can see, it first receives an RSA public key, which we see in the Wireshark transmissions. 

It then sends AES keys to encrypt future transmissions, which it encrypts using the received RSA public key so that we can't see what the keys are

```c

/* WARNING: Unknown calling convention -- yet parameter storage is locked */
/* Comms::send_aes_keys() */

bool Comms::send_aes_keys(void)

{
  void *pvVar1;
  int iVar2;
  runtime_error *this;
  void *__buf;
  ssize_t sVar3;
  long i;
  int *in_RDI;
  undefined8 *puVar4;
  long in_FS_OFFSET;
  void *local_488;
  void *local_480;
  long local_478;
  int local_468;
  int iStack_464;
  int iStack_460;
  int iStack_45c;
  int local_458;
  int iStack_454;
  int iStack_450;
  int iStack_44c;
  undefined8 local_448 [129];
  long local_40;
  
  local_468 = in_RDI[5];
  iStack_464 = in_RDI[6];
  iStack_460 = in_RDI[7];
  iStack_45c = in_RDI[8];
  local_458 = in_RDI[9];
  iStack_454 = in_RDI[10];
  iStack_450 = in_RDI[0xb];
  iStack_44c = in_RDI[0xc];
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  puVar4 = local_448;
  for (i = 0x80; i != 0; i = i + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  rsa_encrypt((uchar *)&local_488,(int)in_RDI,(ulong *)&local_468);
  pvVar1 = local_488;
  if (local_480 == local_488) {
    __buf = calloc(1,6);
    __memcpy_chk(__buf,&DAT_0010a141,6,6);
    __memcpy_chk((long)__buf + 6,pvVar1,0);
                    /* try { // try from 001077db to 00107812 has its CatchHandler @ 0010785d */
    send(*in_RDI,__buf,6,0);
    free(__buf);
    sVar3 = recv(*in_RDI,local_448,0x400,0);
    iVar2 = is_correct_response((Comms *)in_RDI,(uchar *)local_448,(int)sVar3,
                                (uchar *)"KEY_RECEIVED",0xc);
    if (local_488 != (void *)0x0) {
      operator.delete(local_488,local_478 - (long)local_488);
    }
    if (local_40 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return iVar2 == 0;
  }
  this = (runtime_error *)__cxa_allocate_exception(0x10);
  std::runtime_error::runtime_error(this,"Error");
  if (local_40 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
                    /* WARNING: Subroutine does not return */
  __cxa_throw(this,&std::runtime_error::typeinfo,std::runtime_error::~runtime_error);
}
```

This corresponds to the first red message we see in the transmission because the message it sends appears to have some sort of header, which it prepends here

```c
__memcpy_chk(__buf,&DAT_0010a141,6,6);
```

The contents of `DAT_0010a141`?

```
    DAT_0010a141                                       
        0010a141 de              ??         DEh
        0010a142 c0              ??         C0h
        0010a143 de              ??         DEh
        0010a144 c0              ??         C0h
        0010a145 ff              ??         FFh
        0010a146 ee              ??         EEh
```

`dec0dec0ffee`, which is exactly what we see at the beginning of the first red message

```
00000000  de c0 de c0 ff ee 06 45  fe 6a 62 8d 85 36 4a 9b   .......E .jb..6J.
00000010  15 cc bf 46 18 cc dc 76  71 8e b8 4c 24 39 04 2c   ...F...v q..L$9.,
00000020  f3 04 55 d4 e3 37 ed 26  0a 04 d5 b9 5c f0 eb 6a   ..U..7.& ....\..j
00000030  e3 01 81 7d 32 60 bb ef  44 71 de 97 21 03 9f 8d   ...}2`.. Dq..!...
00000040  9a 8f a8 f1 49 fb 68 da  04 88 e7 de 0f 48 a7 b5   ....I.h. .....H..
00000050  e1 60 2a 86 23 1d 83 ab  70 9c 52 68 6e bb 9b b9   .`*.#... p.Rhn...
00000060  5d 2e a4 56 23 b0 ca 45  6c d4 4b a8 ac bd f8 97   ]..V#..E l.K.....
00000070  84 f9 55 30 de 1c fd 8c  62 0b d7 3d f0 64 a8 31   ..U0.... b..=.d.1
00000080  40 43 f6 9d cb 91 01 20  cf 63 ef bd 3f 68 1f 27   @C.....  .c..?h.'
00000090  9b 31 5d ce cf dd 37 b3  e8 37 85 72 7d 9e 77 21   .1]...7. .7.r}.w!
000000A0  7a 4b 72 77 da f1 32 93  2b e7 5c 6f de 1f 34 c3   zKrw..2. +.\o..4.
000000B0  c3 da f7 cd f6 60 05 63  ec 95 f3 85 63 4a cc 08   .....`.c ....cJ..
000000C0  f3 e2 96 f1 1c 55 72 08  fb a7 a0 0e 25 e4 25 55   .....Ur. ....%.%U
000000D0  4b 23 8f 77 6d 89 07 73  a5 ee e8 a5 65 45 01 16   K#.wm..s ....eE..
000000E0  61 96 cc 68 b7 cf 28 34  00 13 5d 05 51 b1 50 b8   a..h..(4 ..].Q.P.
000000F0  81 c6 4e 37 b2 01 98 b1  f7 1e 26 77 39 d4 36 fb   ..N7.... ..&w9.6.
00000100  46 1e 47 44 11 19                                  F.GD..
```

In this same `send_aes_keys` function, it checks to see if the response recieved was correct

```c
    sVar3 = recv(*in_RDI,local_448,0x400,0);
    iVar2 = is_correct_response((Comms *)in_RDI,(uchar *)local_448,(int)sVar3,
                                (uchar *)"KEY_RECEIVED",0xc);
```

With the correct response consisting of a message, `KEY_RECEIVED`

Well what do we see as the next message? (the second blue message)

```
    000001C9  de c0 de c0 ff ee 4b 45  59 5f 52 45 43 45 49 56   ......KE Y_RECEIV
    000001D9  45 44                                              ED
```

Exactly that. Then the remaining messages in the Wireshark transmission appear to be encrypted with the AES key so we can't read them. However, we do have an idea of what they consist of. 

Back looking at `full_handshake`, we see that it calls a function that I call `application_handshake`

```c
    if (iVar1 == 0) {
      uVar3 = application_handshake();
      return uVar3;
    }
```

In this function, it sends a message and expects a response

```c

/* WARNING: Unknown calling convention -- yet parameter storage is locked */
/* Comms::application_handshake() */

bool Comms::application_handshake(void)

{
  int iVar1;
  uchar *puVar2;
  Comms *in_RDI;
  long in_FS_OFFSET;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = 0;
  puVar2 = (uchar *)send_message(in_RDI,&DAT_0010a13a,7,&local_14);
  iVar1 = is_correct_response(in_RDI,puVar2,local_14,&DAT_0010a130,10);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return iVar1 == 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

`DAT_0010a13a`, which is the message, is the string `"REQCONN"`, and `DAT_0010a130` which is the response it's expecting is `"REQCONN_OK"`. 

Also to save some time, I will just note that it expects both of these messages to have the same `dec0dec0ffee` header from before. `send_message` always prepends the hex `dec0dec0ffee` to the beginning of each message

This is very likely what the next two messages are in the transmission stream, but of course, they're encrypted

![image3](./images/task5img3.png)

As for the last two messages, we have no idea what they are, and they probably have the juicy content 

```
00000126  02 db 7b d5 4f ed 23 d1  2d 48 59 9d e5 25 2d c6   ..{.O.#. -HY..%-.
00000136  24 a3 b7 6d 45 46 3a 6a  fb 38 e6 43 4b 9c f8 ae   $..mEF:j .8.CK...
00000146  e0 e3 ae 53 db 69 df 09  fe 99 88 24 56 83 0b c4   ...S.i.. ...$V...
00000156  86 c4 bb af 7c d8 fe c4  b7 82 b4 4f 01 db 0f 1e   ....|... ...O....

    0000020B  7f 91 71 b6 52 fc 82 ca  32 0a 0a e6 7c b7 4b ad   ..q.R... 2...|.K.
    0000021B  5e 4f b0 22 16 2e 6f 9a  bf 51 4b fe c1 a5 64 b3   ^O."..o. .QK...d.
    0000022B  42 2c 3c 4c 82 38 df 66  8e ee e0 0f df 87 99 18   B,<L.8.f ........
    0000023B  80 8f c4 fd 93 24 7d 50  68 c9 41 f8 fc 4d 61 64   .....$}P h.A..Mad
    0000024B  86 c4 bb af 7c d8 fe c4  b7 82 b4 4f 01 db 0f 1e   ....|... ...O....
```

So we have to actually somehow decrypt these messages, but how do we do that?

#### Finding the flaw

Well, we can find the constructor for the `Comms` class

```c
/* Comms::Comms() */

void __thiscall Comms::Comms(Comms *this)

{
  Comms *pCVar1;
  Comms *pCVar2;
  EVP_CIPHER_CTX *pEVar3;
  
  *(undefined4 *)(this + 0x38) = 0;
  pCVar1 = this + 0x14;
  pCVar2 = this + 0x24;
  *(undefined8 *)(this + 0x40) = 0;
  *(undefined4 *)this = 0xffffffff;
  this[0x34] = (Comms)0x0;
  *(undefined (*) [16])(this + 0x14) = (undefined  [16])0x0;
  *(undefined (*) [16])(this + 0x24) = (undefined  [16])0x0;
  pEVar3 = EVP_CIPHER_CTX_new();
  *(EVP_CIPHER_CTX **)(this + 0x48) = pEVar3;
  pEVar3 = EVP_CIPHER_CTX_new();
  *(EVP_CIPHER_CTX **)(this + 0x50) = pEVar3;
  pEVar3 = EVP_CIPHER_CTX_new();
  *(EVP_CIPHER_CTX **)(this + 0x58) = pEVar3;
  pEVar3 = EVP_CIPHER_CTX_new();
  *(EVP_CIPHER_CTX **)(this + 0x60) = pEVar3;
  gen_key(this,(uchar *)pCVar1,0x10);
  gen_key(this,(uchar *)pCVar2,0x10);
  this[0x34] = (Comms)0x1;
  aes_init_enc(pCVar1,*(undefined8 *)(this + 0x48));
  aes_init_enc(pCVar2,*(undefined8 *)(this + 0x50));
  aes_init_dec(pCVar1,*(undefined8 *)(this + 0x58));
  aes_init_dec(pCVar2,*(undefined8 *)(this + 0x60));
  return;
}
```

From my function naming, we can see that it generates two keys using a `gen_key` function. It then uses these keys to initialize two different AES ECB contexts, both consisting of the corresponding encrypt and decrypt contexts

Why does it generate two keys and initialize two different AES ECB contexts?

Well, if we look at how the binary sends messages, we can see that it performs some kind of custom encryption scheme on messages before it sends them

```c
void custom_enc(undefined8 param_1,undefined8 param_2,undefined8 param_3,int param_4,
               undefined8 param_5,undefined8 param_6)

{
  void *__ptr;
  long in_FS_OFFSET;
  int local_44;
  long local_40;
  
  local_44 = param_4 + 0x10;
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  __ptr = malloc((long)local_44);
  aes_encrypt(param_1,param_3,param_4,__ptr,&local_44);
  aes_encrypt(param_2,__ptr,local_44,param_5,param_6);
  if (local_40 == *(long *)(in_FS_OFFSET + 0x28)) {
    free(__ptr);
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

As we can see, it encrypts messages twice, once with the first AES ECB context, and again with the second AES ECB context

```c
  aes_encrypt(param_1,param_3,param_4,__ptr,&local_44);
  aes_encrypt(param_2,__ptr,local_44,param_5,param_6);
```

Well that makes things a little harder. Thankfully, the bad actors messed up how they're generating the keys that initialize the AES ECB contexts

We can look at the function that generates said keys

```c
/* Comms::gen_key(unsigned char*, int) */

void __thiscall Comms::gen_key(Comms *this,uchar *param_1,int param_2)

{
  long lVar1;
  uint uVar2;
  ulong uVar3;
  ulong uVar4;
  long lVar5;
  long in_FS_OFFSET;
  undefined8 uStack_50;
  char local_48 [32];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  local_48[0] = '\0';
  local_48[1] = '\0';
  local_48[2] = '\0';
  local_48[3] = '\0';
  local_48[4] = '\0';
  local_48[5] = '\0';
  local_48[6] = '\0';
  local_48[7] = '\0';
  local_48[8] = '\0';
  local_48[9] = '\0';
  local_48[10] = '\0';
  local_48[11] = '\0';
  local_48[12] = '\0';
  local_48[13] = '\0';
  local_48[14] = '\0';
  local_48[15] = '\0';
  local_48[16] = '\0';
  local_48[17] = '\0';
  local_48[18] = '\0';
  local_48[19] = '\0';
  local_48[20] = '\0';
  local_48[21] = '\0';
  local_48[22] = '\0';
  local_48[23] = '\0';
  local_48[24] = '\0';
  local_48[25] = '\0';
  local_48[26] = '\0';
  local_48[27] = '\0';
  local_48[28] = '\0';
  local_48[29] = '\0';
  local_48[30] = '\0';
  local_48[31] = '\0';
  uStack_50 = (undefined *)0x10705e;
  generate_key((uint8_t)local_48,0x20);
  uVar2 = 0x20;
  if (param_2 < 0x21) {
    uVar2 = param_2;
  }
  uVar4 = (ulong)(int)uVar2;
  if (uVar4 < 8) {
    if ((uVar4 & 4) == 0) {
      if (uVar4 != 0) {
        *param_1 = local_48[0];
        if ((uVar2 & 2) != 0) {
          *(undefined2 *)(param_1 + (uVar4 - 2)) = *(undefined2 *)(local_48 + (uVar4 - 2));
        }
      }
    }
    else {
      *(undefined4 *)param_1 = local_48._0_4_;
      *(undefined4 *)(param_1 + (uVar4 - 4)) = *(undefined4 *)(local_48 + (uVar4 - 4));
    }
  }
  else {
    *(undefined8 *)param_1 = local_48._0_8_;
    *(undefined8 *)(param_1 + (uVar4 - 8)) = *(undefined8 *)(local_48 + (uVar4 - 8));
    lVar5 = (long)param_1 - ((ulong)(param_1 + 8) & 0xfffffffffffffff8);
    uVar4 = uVar4 + lVar5 & 0xfffffffffffffff8;
    if (7 < uVar4) {
      uVar3 = 0;
      do {
        *(undefined8 *)(((ulong)(param_1 + 8) & 0xfffffffffffffff8) + uVar3) =
             *(undefined8 *)(local_48 + (uVar3 - lVar5));
        uVar3 = uVar3 + 8;
      } while (uVar3 < uVar4);
    }
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    uStack_50 = &UNK_00107114;
    __stack_chk_fail();
  }
  return;
}
```

This looks pretty complicated, but essentially, the key generation is flawed, since the majority of the key is actually zeroed out according to this disassembly

I wanted to be 100% sure of this however, since I also looked at the disassembly in Binja and it differed a little bit from the Ghidra disassembly. I did trust what Ghidra was giving us, but you can never be too sure. 

I used Python to import this `gen_key` function and run it. First though I had to create a shared library wrapper to call said functions since the function symbols are all garbled

```cpp
#include <cstdint>
#include <cstring>

extern "C" {
    // declare mangled symbols from the .so
    int _ZN5Comms7gen_keyEPhi(void* this_ptr, unsigned char* buf, int len);
    void _ZN5CommsC2Ev(void* this_ptr);
    void _ZN5CommsD1Ev(void* this_ptr);
}

struct CommsWrapper {
    unsigned char key[32];

    // construct, call gen_key, store in key
    void gen() {
        // allocate actual Comms object on stack
        unsigned char obj[0x400]; // guess object size
        _ZN5CommsC2Ev(obj);      // call constructor
        _ZN5Comms7gen_keyEPhi(obj, key, sizeof(key));
        _ZN5CommsD1Ev(obj);      // call destructor
    }
};

extern "C" void gen_key_bytes(unsigned char* out_buf) {
    CommsWrapper w;
    w.gen();
    std::memcpy(out_buf, w.key, sizeof(w.key));
}
```

I got said symbols by just running strings on the binary and grepping for function names since we know them (I should preface that I did not name `gen_key`, it was already named that). Additionally, the base object constructor is usually `C2Ev` and the complete destructor is `D1Ev` (with `Ev` meaning that the function takes no arguments)

```bash
┌──(archangel✝LAPTOP-2ESFOORT)-[~/comps/nsa-codebreaker/nsa-codebreaker-2025/task4]
└─$ strings mimic_p21658_p416785_zlib.bin | grep gen_key
_ZN5Comms7gen_keyEPhi

┌──(archangel✝LAPTOP-2ESFOORT)-[~/comps/nsa-codebreaker/nsa-codebreaker-2025/task4]
└─$ strings mimic_p21658_p416785_zlib.bin | grep "C2Ev"
_ZN5CommsC2Ev

┌──(archangel✝LAPTOP-2ESFOORT)-[~/comps/nsa-codebreaker/nsa-codebreaker-2025/task4]
└─$ strings mimic_p21658_p416785_zlib.bin | grep "D1Ev"                                                              
_ZN5CommsD1Ev
```

Compiling this shared library wrapper as `comms_wrapper.so`, we can then use Python to call `gen_key`

```python
from ctypes import CDLL, create_string_buffer

lib = CDLL("./comms_wrapper.so")
buf = create_string_buffer(16)
lib.gen_key_bytes(buf)
print("generated key:", buf.raw.hex())

buf2 = create_string_buffer(16)
lib.gen_key_bytes(buf2)
print("generated key:", buf2.raw.hex())
```

I call it twice each run just to make sure that what we're getting is deterministic. 

Running this gets us

```
generated key: 88683800000000000000000000000000
generated key: f8510102000000000000000000000000
```

Well would you look at that, we were right! The majority of the key is indeed zeroed out. Good job kind of odd Ghidra disassembly. 

It appears that only the first 4 bytes of the keys actually contain data, while the remaining bytes are all zeroes. This is huge, this means that brute forcing these keys is actually feasible. 

Ok, so we know what we have to do. We have to brute force the correct keys since they are mathematically feasible to crack due to the much smaller key space (since only the first 4 bytes for each key matters), and we can check if we are correct since we already know some of the plaintext (`REQCONN` and `REQCONN_OK`, with `dec0dec0ffee` as the headers)

#### Cracking the keys

Since we are cracking two keys, to save time, we can perform what is called a ["Meet in the Middle"](https://en.wikipedia.org/wiki/Meet-in-the-middle_attack) attack

Essentially, we encrypt the known plaintext forward with all possible variations of the first key

We then decrypt the ciphertext backward with all possible variations of the second key

We then look for a match in the middle. If we get one, we have found our two keys. 

I end up creating a program that can do this for us in Go. I will warn the program is pretty long (I sorta just had AI cook something up). There's probably a better, more efficient way to do this. 

```go
// mitm-runner.go
// Build: go build -o mitm-runner mitm-runner.go
// Usage example:
// ./mitm-runner -cipher f4dd46... -tmp /tmp/mitmtmp -chunk 1048576 -workers 8
package main

import (
	"container/heap"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

const TOTAL_KEYS uint32 = 1 << 26

type Rec struct {
	Key [16]byte
	K   uint32
}

func constructKeyFromV(v uint32) []byte {
	k := make([]byte, 16)
	k[0] = byte(v & 0xff)
	k[1] = byte((v >> 8) & 0xff)
	k[2] = byte((v >> 16) & 0xff)
	k[3] = byte((v >> 24) & 0xff)
	return k
}

func ecbEncryptBlock(key []byte, in []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	c.Encrypt(out, in)
	return out, nil
}

func ecbDecryptBlock(key []byte, in []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	c.Decrypt(out, in)
	return out, nil
}

// writeRecords writes slice of records to file in binary: 16 bytes key + 4 bytes little-endian k
func writeRecords(path string, recs []Rec) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 20)
	for _, r := range recs {
		copy(buf[:16], r.Key[:])
		binary.LittleEndian.PutUint32(buf[16:], r.K)
		_, err := f.Write(buf)
		if err != nil {
			return err
		}
	}
	return nil
}

// read one record from file (expects file pointer positioned correctly)
func readRecord(f *os.File, r *Rec) (bool, error) {
	var buf [20]byte
	n, err := io.ReadFull(f, buf[:])
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, nil
		}
		return false, err
	}
	if n != 20 {
		return false, nil
	}
	copy(r.Key[:], buf[:16])
	r.K = binary.LittleEndian.Uint32(buf[16:])
	return true, nil
}

// HeapItem is the single heap element type used for k-way merge.
type HeapItem struct {
	idx int
	key [16]byte
	rec Rec
}

// minHeap implements container/heap.Interface using HeapItem
type minHeap []HeapItem

func (h minHeap) Len() int           { return len(h) }
func (h minHeap) Less(i, j int) bool { return string(h[i].key[:]) < string(h[j].key[:]) }
func (h minHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *minHeap) Push(x interface{}) {
	*h = append(*h, x.(HeapItem))
}

func (h *minHeap) Pop() interface{} {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}

// chunk generation for k1 or k2 types
func generateChunks(tmpdir string, prefix string, start, end uint32, chunkEntries uint32, workers int, block16 []byte, isK1 bool) ([]string, error) {
	var chunkFiles []string
	var wg sync.WaitGroup
	tasks := make(chan uint32, 1<<16)
	errChan := make(chan error, 1)
	var mu sync.Mutex

	// worker pool: compute in parallel and send results to writer goroutine
	type outChunk struct {
		idx  uint32
		recs []Rec
	}
	outChan := make(chan outChunk, 4)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for base := range tasks {
				limit := base + chunkEntries
				if limit > end {
					limit = end
				}
				recs := make([]Rec, 0, limit-base)
				for v := base; v < limit; v++ {
					key := constructKeyFromV(v)
					var out16 []byte
					var err error
					if isK1 {
						out16, err = ecbEncryptBlock(key, block16)
					} else {
						out16, err = ecbDecryptBlock(key, block16)
					}
					if err != nil {
						select {
						case errChan <- err:
						default:
						}
						return
					}
					var k16 [16]byte
					copy(k16[:], out16[:16])
					recs = append(recs, Rec{Key: k16, K: v})
				}
				outChan <- outChunk{idx: base, recs: recs}
			}
		}()
	}

	// writer goroutine: receives chunks, sorts them, writes chunk file
	writerWg := sync.WaitGroup{}
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		count := 0
		for oc := range outChan {
			sort.Slice(oc.recs, func(i, j int) bool {
				return string(oc.recs[i].Key[:]) < string(oc.recs[j].Key[:])
			})
			chfile := filepath.Join(tmpdir, fmt.Sprintf("%s_chunk_%08x.bin", prefix, oc.idx))
			if err := writeRecords(chfile, oc.recs); err != nil {
				select {
				case errChan <- err:
				default:
				}
				return
			}
			mu.Lock()
			chunkFiles = append(chunkFiles, chfile)
			mu.Unlock()
			count++
		}
	}()

	// feed tasks
	for base := start; base < end; base += chunkEntries {
		tasks <- base
	}
	close(tasks)

	// wait
	wg.Wait()
	close(outChan)
	writerWg.Wait()

	// check errors
	select {
	case e := <-errChan:
		return nil, e
	default:
	}

	return chunkFiles, nil
}

// k-way merge chunk files into a single sorted file
func mergeChunkFiles(chunkFiles []string, outpath string) error {
	// open all files
	type readerState struct {
		f   *os.File
		rec Rec
		ok  bool
	}
	rs := make([]*readerState, 0, len(chunkFiles))
	for _, p := range chunkFiles {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		r := &readerState{f: f}
		ok, err := readRecord(f, &r.rec)
		if err != nil {
			return err
		}
		if ok {
			r.ok = true
			rs = append(rs, r)
		} else {
			f.Close()
		}
	}
	// min-heap by key
	h := &minHeap{}
	heap.Init(h)
	for i, r := range rs {
		heap.Push(h, HeapItem{idx: i, key: r.rec.Key, rec: r.rec})
	}

	outf, err := os.Create(outpath)
	if err != nil {
		return err
	}
	defer outf.Close()

	buf := make([]byte, 20)
	for h.Len() > 0 {
		it := heap.Pop(h).(HeapItem)
		copy(buf[:16], it.rec.Key[:])
		binary.LittleEndian.PutUint32(buf[16:], it.rec.K)
		if _, err := outf.Write(buf); err != nil {
			return err
		}
		// advance reader it.idx
		rsIdx := it.idx
		ok, err := readRecord(rs[rsIdx].f, &rs[rsIdx].rec)
		if err != nil {
			return err
		}
		if ok {
			heap.Push(h, HeapItem{idx: rsIdx, key: rs[rsIdx].rec.Key, rec: rs[rsIdx].rec})
		} else {
			rs[rsIdx].f.Close()
		}
	}

	return nil
}

// stream-merge sorted k1 file and k2 file; when keys equal, verify full ciphertext
func mergeTwoFilesAndVerify(k1path, k2path string, ct []byte, verifyPrefix []byte) error {
	f1, err := os.Open(k1path)
	if err != nil {
		return err
	}
	defer f1.Close()
	f2, err := os.Open(k2path)
	if err != nil {
		return err
	}
	defer f2.Close()

	var r1, r2 Rec
	ok1, err := readRecord(f1, &r1)
	if err != nil {
		return err
	}
	ok2, err := readRecord(f2, &r2)
	if err != nil {
		return err
	}

	for ok1 && ok2 {
		s1 := string(r1.Key[:])
		s2 := string(r2.Key[:])
		if s1 < s2 {
			ok1, err = readRecord(f1, &r1)
			if err != nil {
				return err
			}
			continue
		}
		if s2 < s1 {
			ok2, err = readRecord(f2, &r2)
			if err != nil {
				return err
			}
			continue
		}
		// s1 == s2
		var k1s []uint32
		var k2s []uint32
		cur := r1
		for ok1 && string(cur.Key[:]) == s1 {
			k1s = append(k1s, cur.K)
			ok1, err = readRecord(f1, &cur)
			if err != nil {
				return err
			}
		}
		cur2 := r2
		for ok2 && string(cur2.Key[:]) == s2 {
			k2s = append(k2s, cur2.K)
			ok2, err = readRecord(f2, &cur2)
			if err != nil {
				return err
			}
		}
		// verify cross product
		for _, k1v := range k1s {
			k1key := constructKeyFromV(k1v)
			for _, k2v := range k2s {
				k2key := constructKeyFromV(k2v)
				// verify: decrypt with k2 then k1 -> should equal plaintext starting with verifyPrefix
				mid := make([]byte, len(ct))
				for i := 0; i < len(ct); i += 16 {
					block := ct[i : i+16]
					decblock, err := ecbDecryptBlock(k2key, block)
					if err != nil {
						return err
					}
					copy(mid[i:i+16], decblock)
				}
				pt := make([]byte, len(ct))
				for i := 0; i < len(mid); i += 16 {
					block := mid[i : i+16]
					decblock, err := ecbDecryptBlock(k1key, block)
					if err != nil {
						return err
					}
					copy(pt[i:i+16], decblock)
				}
				if len(pt) >= len(verifyPrefix) && string(pt[:len(verifyPrefix)]) == string(verifyPrefix) {
					fmt.Printf("FOUND keys: k1=0x%08x k2=0x%08x\n", k1v, k2v)
				}
			}
		}
	}

	return nil
}

func main() {
	var cipherHex string
	var tmpdir string
	var chunkEntries uint64
	var workers int
	flag.StringVar(&cipherHex, "cipher", "", "ciphertext hex (required)")
	flag.StringVar(&tmpdir, "tmp", "./mitm_tmp", "temporary directory for chunk files")
	flag.Uint64Var(&chunkEntries, "chunk", 1<<20, "number of entries per chunk (tune smaller for low RAM)")
	flag.IntVar(&workers, "workers", runtime.NumCPU(), "parallel workers for chunk generation")
	flag.Parse()

	if cipherHex == "" {
		fmt.Println("cipher required")
		os.Exit(1)
	}
	ct, err := hex.DecodeString(cipherHex)
	if err != nil {
		panic(err)
	}
	if len(ct)%16 != 0 {
		panic("cipher length must be multiple of 16")
	}
	verifyPrefix := []byte{0xDE, 0xC0, 0xDE, 0xC0, 0xFF, 0xEE, 'R', 'E', 'Q', 'C', 'O', 'N', 'N'} // user-provided

	if err := os.MkdirAll(tmpdir, 0755); err != nil {
		panic(err)
	}

	chunk := uint32(chunkEntries)
	fmt.Printf("Generating k1 chunks...\n")
	start := uint32(0)
	end := TOTAL_KEYS
	P1 := make([]byte, 16)
	copy(P1, verifyPrefix)
	if len(verifyPrefix) < 16 {
		pad := 16 - len(verifyPrefix)
		for i := len(verifyPrefix); i < 16; i++ {
			P1[i] = byte(pad)
		}
	}
	k1Chunks, err := generateChunks(tmpdir, "k1", start, end, chunk, workers, P1, true)
	if err != nil {
		panic(err)
	}
	fmt.Printf("k1 chunks: %d\n", len(k1Chunks))

	fmt.Printf("Merging k1 chunks into k1_all.dat ...\n")
	k1All := filepath.Join(tmpdir, "k1_all.dat")
	if err := mergeChunkFiles(k1Chunks, k1All); err != nil {
		panic(err)
	}
	fmt.Printf("k1 merged at %s\n", k1All)

	// k2 using first ciphertext block
	C1 := ct[:16]
	fmt.Printf("Generating k2 chunks...\n")
	k2Chunks, err := generateChunks(tmpdir, "k2", 0, TOTAL_KEYS, chunk, workers, C1, false)
	if err != nil {
		panic(err)
	}
	fmt.Printf("k2 chunks: %d\n", len(k2Chunks))

	fmt.Printf("Merging k2 chunks into k2_all.dat ...\n")
	k2All := filepath.Join(tmpdir, "k2_all.dat")
	if err := mergeChunkFiles(k2Chunks, k2All); err != nil {
		panic(err)
	}
	fmt.Printf("k2 merged at %s\n", k2All)

	fmt.Printf("Streaming merge and verify...\n")
	t0 := time.Now()
	if err := mergeTwoFilesAndVerify(k1All, k2All, ct, verifyPrefix); err != nil {
		panic(err)
	}
	fmt.Printf("Done in %s\n", time.Since(t0))
}
```

We can run this like so

```
./mitm-runner -cipher <CIPHER> -tmp /tmp/mitmtmp -chunk 1048576 -workers 8
```

For the cipher, I will use the relatively short message that is sent right after the `KEY_RECIEVED` message. This is the message that we believe decrypts to the `dec0dec0ffee` header and `REQCONN`

```
00000106  f4 dd 46 f9 82 34 1b 5d  da c9 0f f0 fd 70 c3 67   ..F..4.] .....p.g
00000116  86 c4 bb af 7c d8 fe c4  b7 82 b4 4f 01 db 0f 1e   ....|... ...O....
```

So the hex for that is 

```
f4dd46f982341b5ddac90ff0fd70c36786c4bbaf7cd8fec4b782b44f01db0f1e
```

I run our Go program with

```
./mitm-runner -cipher f4dd46f982341b5ddac90ff0fd70c36786c4bbaf7cd8fec4b782b44f01db0f1e -tmp /tmp/mitmtmp -chunk 1048576 -workers 8
```

and hope for the best

The program first generates all possible variations for both keys, which takes a while. It then performs the Meet in the Middle attack, which it actually did pretty fast. It spams me telling me it found the keys, it appears I forgot to code in a `break` if it found a match

```
FOUND keys: k1=0x0309d694 k2=0x00617d73
FOUND keys: k1=0x0309d694 k2=0x00617d73
FOUND keys: k1=0x0309d694 k2=0x00617d73
FOUND keys: k1=0x0309d694 k2=0x00617d73
FOUND keys: k1=0x0309d694 k2=0x00617d73
FOUND keys: k1=0x0309d694 k2=0x00617d73
FOUND keys: k1=0x0309d694 k2=0x00617d73
FOUND keys: k1=0x0309d694 k2=0x00617d73
FOUND keys: k1=0x0309d694 k2=0x00617d73
FOUND keys: k1=0x0309d694 k2=0x00617d73
FOUND keys: k1=0x0309d694 k2=0x00617d73
FOUND keys: k1=0x0309d694 k2=0x00617d73
```

Well, we can now make a Python script to test if these keys are correct. We compile all of the encrypted messages from the Wireshark transmission, and try to decrypt them using our found keys


```python
# verify_candidates_multi.py
from Crypto.Cipher import AES
from binascii import unhexlify
import sys

# messages to decode (hex strings)
msgs = [
    "f4dd46f982341b5ddac90ff0fd70c36786c4bbaf7cd8fec4b782b44f01db0f1e",
    "68b7847dbd4c602d5807a7fe8943459b804d5b0e9cf604ffd2c59eeea3a8980686c4bbaf7cd8fec4b782b44f01db0f1e",
    "02db7bd54fed23d12d48599de5252dc624a3b76d45463a6afb38e6434b9cf8aee0e3ae53db69df09fe99882456830bc486c4bbaf7cd8fec4b782b44f01db0f1e",
    "7f9171b652fc82ca320a0ae67cb74bad5e4fb022162e6f9abf514bfec1a564b3422c3c4c8238df668eeee00fdf879918808fc4fd93247d5068c941f8fc4d616486c4bbaf7cd8fec4b782b44f01db0f1e"
]

# expected prefix
expected_prefix = unhexlify("DEC0DEC0FFEE")

def key_from_v(v):
    # v: integer, produce 16-byte AES-128 key: little-endian 4 bytes then 12 zeros
    return v.to_bytes(4, "little") + b"\x00"*12

# your candidate values (integers)
k1_v = 0x0309d694
k2_v = 0x00617d73

k1 = key_from_v(k1_v)
k2 = key_from_v(k2_v)

print("k1 (hex):", k1.hex())
print("k2 (hex):", k2.hex())
print("expected prefix (hex):", expected_prefix.hex())
print()

for i, mhex in enumerate(msgs, start=1):
    print(f"=== msg {i} ===")
    try:
        ct = unhexlify(mhex)
    except Exception as e:
        print("Invalid hex for message:", mhex)
        print("Error:", e)
        continue

    # decrypt: C = E_k2(E_k1(P)) so decrypt with k2 then k1
    try:
        mid = AES.new(k2, AES.MODE_ECB).decrypt(ct)
        pt = AES.new(k1, AES.MODE_ECB).decrypt(mid)
    except Exception as e:
        print("Decryption error (k2 then k1):", e)
        pt = b""

    print("decrypted (k2->k1) hex:", pt.hex())
    print("decrypted (k2->k1) ascii:", pt.decode('utf-8', errors='replace'))
    if pt.startswith(expected_prefix):
        print("=> MATCH: plaintext starts with expected prefix.")
    else:
        print("=> NO MATCH with expected prefix.")

    # also show swapped order (just in case)
    try:
        mid_s = AES.new(k1, AES.MODE_ECB).decrypt(ct)
        pt_s = AES.new(k2, AES.MODE_ECB).decrypt(mid_s)
    except Exception as e:
        print("Decryption error (k1 then k2):", e)
        pt_s = b""

    print("--- swapped (k1->k2) hex:", pt_s.hex())
    print("--- swapped (k1->k2) ascii:", pt_s.decode('utf-8', errors='replace'))
    if pt_s.startswith(expected_prefix):
        print("=> MATCH with swapped order (unexpected).")
    else:
        print("=> NO MATCH with swapped order.")
    print()
```

Running this gets us

```
k1 (hex): 94d60903000000000000000000000000
k2 (hex): 737d6100000000000000000000000000
expected prefix (hex): dec0dec0ffee

=== msg 1 ===
decrypted (k2->k1) hex: dec0dec0ffee524551434f4e4e0303039afb71e62754886f48d3bdb8edbe6e3c
decrypted (k2->k1) ascii: ������REQCONN��q�'T�oHӽ���n<
=> MATCH: plaintext starts with expected prefix.
--- swapped (k1->k2) hex: 61894c1530ba12ca9e5f3d586271a4b0a5510e759d867cf26dd454c0addd2b43
--- swapped (k1->k2) ascii: a�L0�ʞ_=Xbq���Qu��|�m�T���+C
=> NO MATCH with swapped order.

=== msg 2 ===
decrypted (k2->k1) hex: dec0dec0ffee524551434f4e4e5f4f4b101010101010101010101010101010109afb71e62754886f48d3bdb8edbe6e3c
decrypted (k2->k1) ascii: ������REQCONN_OK��q�'T�oHӽ���n<
=> MATCH: plaintext starts with expected prefix.
--- swapped (k1->k2) hex: 96e32dec116222985c82ae5d354bf3bacfd12fb1ed566f74739eca5163236df7a5510e759d867cf26dd454c0addd2b43
--- swapped (k1->k2) ascii: ��-�b"�\��]5K���/��Vots��Qc#m��Qu��|�m�T���+C
=> NO MATCH with swapped order.

=== msg 3 ===
decrypted (k2->k1) hex: dec0dec0ffee444154412052455155455354206d61747465726d6f73745f75726c0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f9afb71e62754886f48d3bdb8edbe6e3c
decrypted (k2->k1) ascii: ������DATA REQUEST mattermost_url��q�'T�oHӽ���n<
=> MATCH: plaintext starts with expected prefix.
--- swapped (k1->k2) hex: 07847bc1f1503cb1774d1654e2cb50778e478b1a5caab7ba27a44ede5b7c4235c58baca50a3440f6c810bf0ed7cadb14a5510e759d867cf26dd454c0addd2b43
--- swapped (k1->k2) ascii: �{��P<�wMT��Pw�G�\���'�N�[|B5ŋ��
4@�������Qu��|�m�T���+C
=> NO MATCH with swapped order.

=== msg 4 ===
decrypted (k2->k1) hex: dec0dec0ffee68747470733a2f2f3139382e35312e3130302e3136362f6d61747465726d6f73742f50574d38436d727858387145350b0b0b0b0b0b0b0b0b0b0b9afb71e62754886f48d3bdb8edbe6e3c
decrypted (k2->k1) ascii: ������https://198.51.100.166/mattermost/PWM8CmrxX8qE5










                                                                               ��q�'T�oHӽ���n<
=> MATCH: plaintext starts with expected prefix.
--- swapped (k1->k2) hex: df20fa7153da8f515ab1eaedce674116a77c4cfc3b0cb766ff4480ca3bb861f4b4713af66377996b9ab349e4a77b948a7f7e40a73ee6261e5025ee2dcba5dfc8a5510e759d867cf26dd454c0addd2b43
--- swapped (k1->k2) ascii: � �qSڏQZ����gA�|L�;
                                               �f�D��;�a��q:�cw�k��I�{��~@�>�&P%�-˥�ȥQu��|�m�T���+C
=> NO MATCH with swapped order.
```

Lots of output here, but the first encrypted message decrypts to `dec0dec0ffee524551434f4e4e0303039afb71e62754886f48d3bdb8edbe6e3c`, which is the `dec0dec0ffee` header and then `REQCONN`, exactly as we expected

The second encrypted message decrypts to the `dec0dec0ffee` header and `REQCONN_OK`, again, exactly as we expected

The third encrypted message decrypts to the `dec0dec0ffee` header and `DATA REQUEST mattermost_url`

The last encrypted message decrypts to the `dec0dec0ffee` header and `https://198.51.100.166/mattermost/PWM8CmrxX8qE5` 

Bingo! The last message has exactly what we need

This task asked us to "submit the full URL to the adversary's server"

Submitting `https://198.51.100.166/mattermost/PWM8CmrxX8qE5` solves this task!

**Response**:
> Brilliant! The malware communications lead us right to the adversary's Mattermost server!