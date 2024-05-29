# ELF Loader

example todo revision

`gcc -I ./include/ -Wall -Werror -pedantic -std=gnu99 --static-pie -DDEBUG ./src/main.c ./src/exec.c ./src/map_elf.c ./src/stack_setup.c ./src/jump.c -o reflect`
`gcc -I ./include/ -Wall -Werror -pedantic -std=gnu99 --static-pie ./src/main.c ./src/exec.c ./src/map_elf.c ./src/stack_setup.c ./src/jump.c -o reflect`


`./reflect ./examples/nmap`
`./reflect ./examples/readelf`