# ELF Loader

example todo revision

TODO:
ifdef macro: 
    - LOG_SYSTEM
    - RAND_PERC

VEDERE MACRO:
    - IOCTL_INSTRUM_MAP # rimosso
    - RANDOM_SUBSET_FUNC    // set funzioni random (percentuale fissa ??)
    - LOG_SYSTEM            // logging system
    - RAND_PERC             // percentuale random
    - WITH_IN

`gcc -I ./include/ -Wall -Werror -pedantic -std=gnu99 --static-pie -DDEBUG ./src/main.c ./src/exec.c ./src/map_elf.c ./src/stack_setup.c ./src/jump.c -o reflect`
`gcc -I ./include/ -Wall -Werror -pedantic -std=gnu99 --static-pie ./src/main.c ./src/exec.c ./src/map_elf.c ./src/stack_setup.c ./src/jump.c -o reflect`


`./reflect ./examples/nmap`
`./reflect ./examples/readelf`