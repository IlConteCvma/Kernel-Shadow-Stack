#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(void) {

redo:
	sleep(3);
	printf("Ciao Mondo!\n");
	goto redo;
	exit(0);
}
