# vermagic

A tool dump .modinfo section and set vermagic variable of Linux Kernel Modules.

It also supports (not tested) CRC dump and changes.

The original work is from here: https://github.com/fanfuqiang/vc

### Build
`make`

### Use
`./vermagic -help`

### Examples
- Set vermagic value to "hello world"
`./vermagic -v "hello world" some-name.ko`

- Set single_open crc value to 0x123  
`./vermagic -c "+{single_open, 0x123}" some-name.ko` (not tested after code upgrade)

Anather more magic example:

That was implemented on the release I cloned. But the code is very dirty and I removed a lot of code.
The way of setting multiple CRCs at time is undeveloped.
Re-execute the binary instead or give support in a clean way, please.

~~`./vermagic -c "+{single_open, 0x123}" "+{ some-name ,  0x1234 }" some-name.ko`
