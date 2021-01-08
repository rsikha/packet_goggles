#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void dump(const char *msg, int len) {
	int num = len;
	int min_len = 16;
	unsigned char c;

	if (len < 16) {
		num = 16;
	}
	else if (len > 16) {
		num = len + (16-len%16); // making it multiple of 16
	}

	for (int i= 1; i<=num; i++) {
		if (i > len) {
			printf("   ");
		}
		else {
			printf("%02x ", (unsigned char)msg[i-1]);
		}
		if (i%16 == 0) {
			printf(" | ");
			for (int j = (i-16); j<i; j++) {
				c = msg[j];
				if ((c > 31) && (c < 127)) {
					putchar(msg[j]);
				}
				else
					putchar('.');
			}
			printf("|\n");
		}
	}
	printf("\n");
}


void fatal(const char *msg) {
	printf("DEBUG: %s", msg);
	exit(127);
}
