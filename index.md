# idk :)

> **Category:** Reversing
**Description:** Three open ports. Two are honeypots.
**Flag format:** `THEM?!CTF{...}`
> 

## TL;DR

The “three open ports” turn out to be the three top level functions `main` calls before deciding Wrong vs Correct: `sub_401a80` (anti tamper self check), `sub_401ed0` (the entire `[VM0] ...` banner show), and `sub_402120` (the actual flag check). The first two are the honeypots. All the flag logic lives in `sub_402120`.

`sub_402120` requires a 46 byte input, splits it into three slices (20, 20, 6), runs each through a tiny AES style keystream generator seeded by the literal string `THEMVM1:` plus a stage byte, then `memcmp`s the result against a precomputed target buffer.

Because the keystream is fully determined by stage and byte position (it never sees the input), one debugger run with any 46 byte input gives us enough information to recover the keystream and invert the whole thing.

## Recon

```bash
file 'THEM$%!'
```

```
THEM$_!: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=376aa93463cce1e623ce525230db73e03212b816, for GNU/Linux 3.2.0, stripped
```

A quick `strings` pass already gives away the structure of the program:

```
[VM0] decrypting bytecode...
[VM0] checksum ok.
[VM0] stage1 ok.
[VM0] stage2 ok.
Enter flag:
[VM1] patching bytecode...
Correct! THEM?!CTF win.
Wrong.
[VM1] switching endian wheel...
THEMVM1:
VM1KEY!!
VM1EXP!!
6666666666666666
\\\\\\\\\\\\\\\\
```

Two interesting things jump out. The fixed 16 byte constants `6666...` and `\\\\...`, and the literal seed `THEMVM1:`. 

## Static analysis with Binary Ninja

Loaded the binary, and looked at the call graph rooted at `main`. Six functions matter:

```
0x004010c0    main                   the front desk
0x00401a80    sub_401a80             "port 1": anti tamper self check  (honeypot)
0x00401ed0    sub_401ed0             "port 2": prints the VM0 banners  (honeypot)
0x00402120    sub_402120             "port 3": the real flag check
0x00402080    sub_402080             per stage seed builder (called from sub_402120)
0x00401f00    sub_401f00             target buffer generator (called from sub_402120)
```

`main` calls exactly three things before deciding the result, in this order: `sub_401a80`, `sub_401ed0`, `sub_402120`. The first two are the honeypots, the third is real. The remaining functions (`sub_402080`, `sub_401f00`, plus the AES style helpers `sub_4015f0`, `sub_401cf0`, `sub_401870`, `sub_401b10`, `sub_401480`, `sub_4015e0`) are all internal to the third one. Skip the AES style helpers, no need to understand them.

### `main`

```c
int32_t main(int32_t argc, char** argv, char** envp)
{
    sub_401a80();
    char buf[0x100];
    __builtin_memset(&buf, 0, 256);
    printf("Enter flag: ");
    if (fgets(&buf, 0x100, stdin) != 0)
    {
        uint64_t rax_1 = strcspn(&buf, "\r\n");
        buf[rax_1] = 0;
        sub_401ed0();
        puts("[VM1] switching endian wheel...");
        puts("[VM1] patching bytecode...");
        if (sub_402120(&buf, rax_1) == 0)
            puts("Wrong.");
        else
            puts("Correct! THEM?!CTF win.");
    }
    return 0;
}
```

Read the input, strip the trailing newline, call `sub_401ed0`, then hand the buffer plus its length to `sub_402120`. That return value decides Wrong vs Correct.

### `sub_401a80`, the anti tamper check

```c
int64_t sub_401a80()
{
    char result = 0;
    for (int64_t i = 0; i != 8;) { i += 1; result ^= *(i + 0x4034f7); }
    for (int64_t i_1 = 0; i_1 != 8;) { i_1 += 1; result ^= *(i_1 + 0x4034ef); }
    for (int64_t i_2 = 0; i_2 != 0x5e;) { i_2 += 1; result ^= *(i_2 + 0x40345f); }
    if (result == 0xff)
        return puts("x") __tailcall;
    return result;
}
```

Just XOR folds bytes from three regions inside the binary. If the running accumulator hits `0xff` it prints `x` and returns. Either way it never touches the input. ignore it.

### `sub_401ed0`, the decoy `VM0`

```c
int64_t sub_401ed0()
{
    puts("[VM0] decrypting bytecode...");
    puts("[VM0] checksum ok.");
    puts("[VM0] stage1 ok.");
    return puts("[VM0] stage2 ok.") __tailcall;
}
```

Four `puts`. That is the entire `VM0`. 

### `sub_402120`, the real flag check

This is the function that decides everything. 

```c
int64_t sub_402120(int64_t arg1, int64_t arg2)
{
    if (arg2 != 46)
        return 0;
    char* rax_1 = malloc(46);
    if (rax_1 != 0)
    {
        int64_t r15_1 = 0;
        sub_401f00(rax_1);                       // fills the 46 byte target
        int64_t var_410_1 = arg1 + 0x14;         // slice offsets: 0, 0x14, 0x28
        int64_t var_418   = arg1;
        int64_t var_408_1 = arg1 + 0x28;
        int64_t var_448 = 0;
        int128_t var_438;
        __builtin_memcpy(&var_438,
            "\x14\x00\x00\x00\x00\x00\x00\x00"
            "\x14\x00\x00\x00\x00\x00\x00\x00"
            "\x06\x00\x00\x00\x00\x00\x00\x00", 0x18);   // sizes: 20, 20, 6
        while (true)
        {
            uint64_t bytes = *(&var_438 + (r15_1 << 3));
            int128_t var_3f8;
            sub_402080(&var_3f8, r15_1.b);        // build per stage seed
            ...
        }
    }
}
```

So, the function does five things per slice:

1. Build the key stream. Two 0x80 byte blobs are made by XORing the seed with the 16 byte constants `6666...` (at `0x403590`) and `\\\\...` (at `0x4035a0`), the `VM1KEY!!` and `VM1EXP!!`  from `strings`. They run through `sub_4015f0` (key expansion), `sub_401cf0` (encrypt 32 bytes), `sub_401870` (post mix), giving a 0x80 byte stream `S[]`.

2. Preprocess each input byte with a position dependent mask:

```c
 rbx[0] = input[0] ^ 0x0d
 rbx[i] = input[i] ^ (((bswap32(i) + 7) * bswap32(i) + 13) & 0xff)   for i >= 1
```

3. Apply the keystream, XORing each `rbx[i]` with two bytes pulled from `S[]` at positions derived from `i`, giving `r12[i]`.

4. Compare: `memcmp(r12, ptr + slice_offset, n)`. Any mismatch returns 0.

5. Repeat for the next slice.

### `sub_402080`, the per stage seed builder

```c
int64_t sub_402080(int32_t* arg1, char arg2)
{
    uint128_t zmm0 = data_403500;
    int64_t var_90;
    __builtin_strncpy(&var_90, "THEMVM1:", 8);
    uint128_t var_88 = zmm0;
    int64_t var_68 = 0x20;
    uint128_t var_78 = data_403510;
    uint128_t var_60 = data_403520;
    uint128_t var_50 = data_403530;
    sub_401b10(&var_88, &var_90, 8);   // mix in "THEMVM1:"
    char var_91 = arg2;
    sub_401b10(&var_88, &var_91, 1);   // mix in the stage byte
    return sub_401480(&var_88, arg1);  // emit seed into caller buffer
}
```

This is what makes the keystream stage dependent. The  `"THEMVM1:"` is hashed together with a single byte (0, 1, or 2) into a 16 byte seed.

### `sub_401f00`, the target buffer generator

```c
int64_t sub_401f00(char* arg1)
{
    void* r13 = nullptr;
    uint128_t zmm11 = data_403500;
    int128_t  zmm10 = data_403510;
    int128_t  zmm9  = data_403520;
    int128_t  zmm8  = data_403530;

    while (true)
    {
        char     var_ba_1 = 0;
        int16_t  var_bc   = 0;
        uint128_t var_98  = zmm11;
        uint8_t  var_b9_1 = (r13 u>> 4).b;
        int64_t  var_78_1 = 0x20;
        int128_t var_88_1 = zmm10;
        int128_t var_70_1 = zmm9;
        int128_t var_60_1 = zmm8;

        sub_401b10(&var_98, &var_bc, 4);
        char var_b8[0x20];
        sub_401480(&var_98, &var_b8);

        int32_t rax_3;
        rax_3.b = (0x3d * r13.d).b ^ *(&var_b8 + (r13.d & 0x1f));
        if ((r13.b & 1) != 0)
            rax_3.b = rol.b(rax_3.b, 4);
        uint8_t rax_9 = ((rax_3 << 2).b & 0xcc) | (rax_3.b u>> 2 & 0x33);
        ...
    }
}
```

So,

- It is a 46 iteration loop seeded purely by the four 128 bit constants at `0x403500`, `0x403510`, `0x403520`, `0x403530` plus the constants `0x3d`, `0x1f`, the byte rotation, and the bit interleave. The loop counter `r13` is the only state that changes.
- `arg1` (the destination) is written to but never read. The user input is never read.
- Therefore every byte of `ptr` is a constant of the program. Same on every run.

So `ptr[]` is the deterministic 46 byte target the transformed input must equal. Combined with the per stage keystream from `sub_402080`, that fixes everything.

Putting it together:

```
flag[i] = rbx[i] ^ 0x0d
        = (ptr[off + i] ^ K[i]) ^ 0x0d
        = ptr[off + i] ^ r12[i] ^ rbx_observed[i] ^ 0x0d
```

If we feed `'A' = 0x41`, then `rbx_observed[i] = 0x41 ^ 0x0d = 0x4c`, so:

```
flag[i] = ptr[off + i] ^ r12[i] ^ 0x4c ^ 0x0d
        = ptr[off + i] ^ r12[i] ^ 0x41
```

So a single instrumented run with input `"A" * 46` reveals everything.

## Dynamic analysis:

run target:

```bash
qemu-x86_64 -g 1234 ./THEM\$_\! < /tmp/in.txt
```

where `/tmp/in.txt` is just 46 `A`s.

The script I used:

```
set architecture i386:x86-64
target remote :1234

break *0x402168
commands
  x/46bx *(unsigned long*)($rsp+8)
  c
end

break *0x402461
commands
  x/20bx $r12
  x/20bx $rbx
  set $rax = 0
  c
end

c
```

What this script is doing:

`break *0x402168` lands right after `sub_401f00` returns. At that exact instruction `[rsp+8]` holds the pointer to the freshly built target buffer (we saw it stored there during static analysis). So `*(unsigned long*)($rsp+8)` is the address, and `x/46bx` dumps 46 bytes from it. That gives us the deterministic target.

`break *0x402461` is one byte after the `call memcmp` returns. `eax` holds the comparison result. `r12` and `rbx` are callee saved across the call, so they still point at the per slice post AES and pre AES buffers respectively. We dump 20 bytes from each.

The clever bit is `set $rax = 0`. The next instruction in the program is `test eax, eax; jne fail`. By forcing `eax` to zero we make the test pass and the function continues into the next slice. That way one run gives us all three stage outputs even though our input is wrong.

### Output we got

```
Breakpoint 1, 0x0000000000402168 in ?? ()
0x407730:       0x89    0xfc    0xb3    0xf9    0x9e    0x6f    0xee    0x93
0x407738:       0x93    0xfc    0xef    0xe5    0xf7    0xdd    0x7d    0x92
0x407740:       0xeb    0x8f    0x84    0xa8    0x32    0xef    0x1e    0x67
0x407748:       0xc6    0x84    0xe3    0x2b    0x3e    0x28    0x34    0x50
0x407750:       0x21    0xa0    0xeb    0xc4    0x3d    0x5b    0x83    0x74
0x407758:       0x92    0xfa    0x5e    0x5e    0xf2    0xb0

Breakpoint 2, 0x0000000000402461 in ?? ()
0x4077b0:       0x9c    0xf5    0xb7    0xf5    0xe0    0x0f    0xec    0x86
0x4077b8:       0x94    0xc6    0xc6    0x94    0x86    0xec    0x0f    0xe0
0x4077c0:       0xf5    0xb7    0xf5    0x9c
0x407770:       0x4c    0x4c    0x4c    0x4c    0x4c    0x4c    0x4c    0x4c
0x407778:       0x4c    0x4c    0x4c    0x4c    0x4c    0x4c    0x4c    0x4c
0x407780:       0x4c    0x4c    0x4c    0x4c

Breakpoint 2, 0x0000000000402461 in ?? ()
0x407770:       0x06    0xf1    0x6c    0x48    0xed    0xf5    0x92    0x13
0x407778:       0x20    0x1d    0x1d    0x20    0x13    0x92    0xf5    0xed
0x407780:       0x48    0x6c    0xf1    0x06
0x4077b0:       0x4c    0x4c    0x4c    0x4c    0x4c    0x4c    0x4c    0x4c
0x4077b8:       0x4c    0x4c    0x4c    0x4c    0x4c    0x4c    0x4c    0x4c
0x4077c0:       0x4c    0x4c    0x4c    0x4c

Breakpoint 2, 0x0000000000402461 in ?? ()
0x4077b0:       0x8c    0xdd    0x4a    0x4a    0xdd    0x8c    0x00    0x00
0x4077b8:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x4077c0:       0x4c    0x4c    0x4c    0x4c
0x407770:       0x4c    0x4c    0x4c    0x4c    0x4c    0x4c    0x00    0x00
0x407778:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x407780:       0x48    0x6c    0xf1    0x06
```

Tidying that up. Breakpoint 1 fires once and gives the 46 byte target buffer:

```
89 fc b3 f9 9e 6f ee 93 93 fc ef e5 f7 dd 7d 92
eb 8f 84 a8 32 ef 1e 67 c6 84 e3 2b 3e 28 34 50
21 a0 eb c4 3d 5b 83 74 92 fa 5e 5e f2 b0
```

Breakpoint 2 fires three times, once per slice. First dump is `r12` (post AES), second is `rbx` (pre AES). Pulling out the meaningful bytes (20, 20, 6 per slice, the rest is leftover stack):

Stage 0 (offset 0, n=20):

```
r12 = 9c f5 b7 f5 e0 0f ec 86 94 c6 c6 94 86 ec 0f e0 f5 b7 f5 9c
rbx = 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c
```

Stage 1 (offset 20, n=20):

```
r12 = 06 f1 6c 48 ed f5 92 13 20 1d 1d 20 13 92 f5 ed 48 6c f1 06
rbx = 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c 4c
```

Stage 2 (offset 40, n=6):

```
r12 = 8c dd 4a 4a dd 8c
rbx = 4c 4c 4c 4c 4c 4c
```

## Inversion

Per byte:

```
flag[i] = ptr[i] ^ r12[i] ^ 0x41
```

Stage 0:

```
89^9c^41 = 54 'T'
fc^f5^41 = 48 'H'
b3^b7^41 = 45 'E'
f9^f5^41 = 4d 'M'
9e^e0^41 = 3f '?'
6f^0f^41 = 21 '!'
ee^ec^41 = 43 'C'
93^86^41 = 54 'T'
93^94^41 = 46 'F'
fc^c6^41 = 7b '{'
ef^c6^41 = 68 'h'
e5^94^41 = 30 '0'
f7^86^41 = 30 '0'
dd^ec^41 = 70 'p'
7d^0f^41 = 33 '3'
92^e0^41 = 33 '3'
eb^f5^41 = 5f '_'
8f^b7^41 = 79 'y'
84^f5^41 = 30 '0'
a8^9c^41 = 75 'u'
=> "THEM?!CTF{h00p33_y0u"
```

Stage 1 the same way gives `u_3nj00y_th1ss_h4v33`.
Stage 2 gives `_fUUn}`.

Concatenated:

```
THEM?!CTF{h00p33_y0uu_3nj00y_th1ss_h4v33_fUUn}
```

Length 46. Submit:

```bash
echo 'THEM?!CTF{h00p33_y0uu_3nj00y_th1ss_h4v33_fUUn}' | ./THEM\$_\!
```

Output:

```
Enter flag: [VM0] decrypting bytecode...
[VM0] checksum ok.
[VM0] stage1 ok.
[VM0] stage2 ok.
[VM1] switching endian wheel...
[VM1] patching bytecode...
Correct! THEM?!CTF win.
```
