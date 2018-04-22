#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#define MAX_FILE_NAME 100

struct rule {
	int srcIP;
	int dstIP;
	int srcPrt;
	int dstPrt;
	int prot;
	char target[16];
};

void readRules(void);

void main(int argc, char *argv[]) {
	if(argc <= 1) {
		printf("Not enough arguments.\n");
		printf("usage: nsf \"[firewall rule]\"\n");
		exit(0);
	}
	
	struct rule rules[999];

	// get the iptables list
	system("sudo iptables --list > iptables");
	
	readRules();
	

    exit(0);
}

void readRules(void) {
	FILE *fp;
	char filename[MAX_FILE_NAME];
	char cwd[1024];
	char c;
	char *tokens;
	getcwd(cwd, sizeof(cwd));

	strcpy(filename, strcat(cwd,"/iptables"));
	
	fp = fopen(filename, "r");

	if (fp != NULL) {
		char line[1000]; /* or other suitable maximum line size */
 		while(fgets(line, sizeof line, fp) != NULL) {
			if((strstr(line,"Chain") == NULL) && (strstr(line,"target") == NULL)) {
				//while((tokens = strtok(line, " "))) {
				//	printf("%s,",tokens);
				//	*line = '\0';
				//}
				fputs(line, stdout);
			}
		}
		fclose(fp);
	} else {
		perror(filename); /* why didn't the file open? */
	}
}
