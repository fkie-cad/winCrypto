# Crypto utils
Implementations of some useful crypto utils using the windows CNG API.

## Contents
* [Requirements](#requirements)
* [Build Stuff](#build-stuff)
* [AES](#aes)
* [Base64](#base64)
* [MD5, SHA1, SHA256](#md5,-sha1,-sha256)
* [Copyright, Credits & Contact ](#Copyright,-Credits-&-Contact )

## Requirements
- msbuild

## Build Stuff
```bash
$ ./build.bat [/md5] [/sh1] [/sh2] [/b64] [/aes] [/hash] [/all] [/r] [/d] [/dp <flag>] [/b 32|64] [/rtl] [/pdb] [/pts <platformToolSet>] [/h]
```



## AES

AES encryption & decryption tool using CBC mode.
Encrypts or decrypts an user input string, bytes or file.
The result is written to file and/or printed to the cmd.

### version
1.0.0  
Last changed: 01.06.2023


### build
```bash
$ ./build.bat /aes
```

### usage
```bash
$ aes [/d|/e] [/ia|/iu|/ib|/ip <value>] [/op <path>] [/pwa|/pwu|/pwb] [/iva|/ivu|/ivb] [/p*] [/v]
```

**Modes:**
- /d: Decode aes cypher into plain bytes.
- /e: Encode bytes into aes cypher.

**Password:**
- /pwa: Ascii password string of which the sha256 hash will be calculated and used as the secret.
- /pwu: Unicode (utf-16) password string of which the sha256 will be calculated and used as the secret.
- /pwb: 0x20 hex bytes used directly as the secret.
- If no password is given, a random one will be generated. This obviously only works while encoding.

**Initial vector:**
- /iva: Ascii initial vector string of which the md5 hash will be calculated and used as the iv.
- /ivu: Unicode (utf-16) initial vector string of which the md5 hash will be calculated and used as the iv.
- /ivb: 0x10 hex bytes used directly as the iv.
- If no initial vector is given, a random one will be generated. This obviously only works while encoding.

**Input:**
- /ib: Input bytes as hex string. If set it's the source of /e or /d.
- /ia: Input ascii string. If set it's the source of /e.
- /iu: Input unicode string. If set it's the source of /e.
- /ip: Path to a file. If set it's the source of /e or /d.

**Output:**
- /op: Path to a file. If set the result of /e or /d will be written to it.
- /p*: Print result of /e or /d even if /op is set.
    - /pa: Print as ascii string.
    - /pb: Print in plain bytes (default).
    - /pc8: Print in cols of Address | bytes | ascii chars.
    - /pc16: Print in cols of Address | words | utf-16 chars.
    - /pc32: Print in cols of Address | dwords.
    - /pc64: Print in cols of Address | qwords.

**Other:**
- /v: More verbose
- /h: Print this

 **Examples**
```bash
# encrypt a/file into a/nother/file with random password and initial vector
$ aes /e /ip a/file /op a/nother/file 

# encrypt a/file into a/nother/file with given password and initial vector
$ aes /e /ip a/file /op a/nother/file /pwa secret /iva initial 

# decrypt a/file into a/nother/file with given password and initial vector
$ aes /d /ip a/file /op a/nother/file /pwa secret /iva initial 

# decrypt a/file and print result to console
$ aes /d /ip a/file /pwa secret /iva initial

# encrypt ascii string "bla" with random password and initial vector and print result to the console
$ aes /e /ia bla 

# encrypt input bytes 102030 with random pw and iv and print result as col 8 print
$ aes /e /ib 102030 /pc8 

# decrypt input bytes, print result as col 8 and write it to file
$ aes /d /ib 3e9a37c7e2450d4fe0a806142da1dddc /pc8 /op %tmp%\file.txt /pwa bla /iva blub 
```



## Base64

Base64 converter tool.
Converts an user input string, bytes or file.
The result is written to file and/or printed to the cmd.

### version
1.0.2  
Last changed: 25.05.2023


### build
```bash
$ ./build.bat /b64
```

### usage
```bash
$ base64 [/d] [/e] [/ib <bytes>] [/is <string>] [/ip <path>] [/op <path>] [/p*] [/h]
```

**Modes:**  
* /d: Decode base64 string into bytes.
* /e: Encode bytes into base64 string.

**Input:**  
* /ib: Input bytes as hex string. If set it's the source of /e or /d.
* /is: Input string. If set it's the source of /e or /d.
* /ip: Path to a file. If set it's the source of /e or /d.

**Format:**  
* /cr: Insert line feeds (LF / 0x0A) into encoded string.
* /crlf: Insert carriage return/line feed (CR LF / 0x0D 0x0A) into encoded string.
 
**Output:**  
* /op: Path to a file. If set the result of /e or /d will be written to it.
* /p*: Print result of /e or /d even if /op is set.
  * /pa: Print as ascii string (default).
  * /pb: Print in plain bytes.
  * /pc8: Print in cols of Address | bytes | ascii chars.
  * /pc16: Print in cols of Address | words | utf-16 chars.
  * /pc32: Print in cols of Address | dwords.
  * /pc64: Print in cols of Address | qwords.
  
**Other:**  
* /h: Print this
 
 **Examples**
```bash
# encode a/file into a/nother/file
$ base64 /e -ip a/file -op a/nother/file 

# decode a/file into a/nother/file
$ base64 /d -ip a/file -op a/nother/file 

# decode a/file and print result to console
$ base64 /d -ip a/file 

# encode ascii string "bla" and print result to the console
$ base64 /e -is bla 

# encode input bytes 102030 and print result as col 8 print
$ base64 -e -ib 102030 -pc8 

# decode input bytes 45434177, print result as bytes and write it to a/nother/file
$ base64 -d -ib 45434177 -pb -op %tmp%\file.txt
```



## Md5, Sha1, Sha256
Calculates the hash sum of files or files in folders.
The hash sum will be md5, sha128 or sha256 depending on the executed binary.

### version
1.0.6  
Last changed: 13.02.2024  


### build
```bash
$ ./build.bat /md5 # builds md5.exe
$ ./build.bat /sh1 # builds sha1.exe
$ ./build.bat /sh2 # builds sha256.exe
```

### usage
```bash
$ md5 [/h] [/r] [/c] <path>...
$ sha1 [/h] [/r] [/c] <path>...
$ sha256 [/h] [/r] [/c] <path>...
```

Options:  
 * /r Do recursive folder walks.
 * /c Compare path1 with path2 or path1 with a sha256 value.
 * /h Print help.
 * path: One or more pathes to files or dirs for hash calculation

**sha256 Examples**
```bash
# calculate sha256 of two files
$ sha256 a/file a/nother/file

# calculate sha256 of all files in a dir
$ sha256 a/dir/ 

# compare sha256 of file1 with file2
$ sha256 /c file1 file2 

# compare sha256 of file1 with a sha256 value
$ sha256 /c file1 0011223344...
```
Use `md5` or `sha1` for the other hash types.



## Copyright, Credits & Contact 
Published under [GNU GENERAL PUBLIC LICENSE](LICENSE).

#### author
- Henning Braun ([henningbraun@gmx.net](mailto:henningbraun@gmx.net)) 
