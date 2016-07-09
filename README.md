# vc

A tool read and set vermagic and crc of kernel module

**build:**

  gcc -o vc vc.c

**use:**

  ./vc --help

**examples:**

-  *set vermagic value to "hello"*
  
./vc -v +hello some-name.ko
  
-  *set single_open crc value to 0x123*
  
./vc -c "+{single_open, 0x123}" some-name.ko

Anather more magic example:

./vc -c "+{single_open, 0x123}" "+{ some-name ,  0x1234 }" some-name.ko

## any other do you want?
  tell me: feqin1023 AT gmail dot com

