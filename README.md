# vc

A tool read and set vermagic and crc of kernel module

**build**:
  gcc -o vc vc.c

**use**:
  ./vc --help

**example**
  *set vermagic value to "hello"*
  ./vc -v +hello some-name.ko
  *set single_open crc value to 0x123*
  ./vc -c +{single_open, 0x123} some-name.ko

