#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>

#include <sys/kcov.h>

#define KCOV_PATH "/dev/kcov"
#define COVER_SIZE (16 << 20)	//maximum size
#define BUF_SIZE (2 << 20)
#define COUNT 16000000
#define COV_FILE "coverage.info"
#define ADDR2LINE "/usr/local/bin/addr2line"
#define KERNEL "/usr/lib/debug/boot/kernel/kernel.debug"
#define KERNDIR "/usr/src/sys"
#define COV_DIR "cov_info"

size_t bufsize = KCOV_ENTRY_SIZE * BUF_SIZE;

#define NF_FILE "notfound.log"  //not found functions

static int compare(const void *p1, const void *p2)
{
	size_t i = *((size_t *)p1);
	size_t j = *((size_t *)p2);

	if (i > j) return (1);
	if (i < j) return (-1);
	return 0;
}

// write to the file
int wtfile(size_t *buffer, int nbuf)
{
	int i;
	FILE *fd;
	fd = fopen("rawfile.log", "w");
	if (!fd) 
		return 1;
	fprintf(fd, "%jx\n", (uintmax_t)buffer[0]);
	for (i = 0; i < nbuf - 1; i++) {
		if (buffer[i] != buffer[i + 1])
			fprintf(fd, "%jx\n", (uintmax_t)buffer[i + 1]);
	}
	fclose(fd);
	return 0;
}

//write to the buffer
int wtbuffer(char *fname, size_t *cover, size_t *buffer, int *nbuf)
{
	int i;
	if (*nbuf > (bufsize * 70 / 100)) {
		bufsize *= 2;
		buffer = realloc(buffer, bufsize);
		if (!buffer) 
			return 1;
	}
	size_t size = cover[0] * KCOV_ENTRY_SIZE;
	size_t *dupl = malloc(size);
	if (!dupl) 
		return 1;
	for (int j = 0; j < cover[0]; j++)
		dupl[j] = cover[j + 1];

	//sort
	qsort(dupl, cover[0], KCOV_ENTRY_SIZE, compare);

	//compress without counting
	buffer[(*nbuf)++] = dupl[0];
	for (i = 0; i < cover[0] - 1; i++) {
		if (dupl[i] != dupl[i + 1])
			buffer[(*nbuf)++] = dupl[i + 1];
	}
	free(dupl);
	return 0;
}

//copy the function name from the string
int copyfunc(char *nmfname, char *str)
{
	int i;
	for (i = 0; str[i] != ' '; i++) {
		nmfname[i] = str[i];
	}
	nmfname[i] = '\0';
	return 0;
}

//copy the path to the file from the string
//copy the line number
int copypath(char *fpath, int *line, char *str)
{
	int i, k;
	char *start;
	char nmline[10];
	start = strchr(str, '/');
	if (!start) 
		return 1;
	if (!strncmp(start, "/usr/obj", 8)) 
		return 2;
	for (i = 0; start[i] != ':'; i++) {
		fpath[i] = start[i];
	}
	fpath[i] = '\0';
	i++;
	if (start[i] == '?' || start[i] == '0') 
		return 3;
	for (k = 0; !isspace(start[i]); i++, k++) {
		nmline[k] = start[i];
	}
	nmline[k] = '\0';
	printf("%s:%s\n", fpath, nmline);
	*line = atoi(nmline);
	return 0;
}

//create a coverage report in lcov format
int coverage(FILE *nmfile, FILE *adfile) 
{
	FILE *covfile, *srcfile;
	char *match;
	int nmline, aline, ret, len, nf = 0;		// line number in nm file
	char afname[100];				// function name in address file
	char nmfname[100] = "";				// function name in nm file
	char fpath[200];				// function path in nm file
	char str[400];					// nm file string
	char srcstr[1024];
	covfile = fopen(COV_FILE, "w");
	if (!covfile)
		return 1;

	FILE *notfound;
	notfound = fopen(NF_FILE, "w");
	if (!notfound)
		return 1;

	while (fgets(afname, 100, adfile) != NULL) {
		if (afname[0] == '?') {
			fgets(str, 200, adfile);
			continue;
		}
		ret = 0;
		afname[strlen(afname) - 1] = '\0';
		while (fgets(str, 400, nmfile) != NULL) {
			copyfunc(nmfname, str);
			if (strcmp(nmfname, afname)) 
				continue;
			printf("%s\n", nmfname);
			ret = copypath(fpath, &nmline, str);
			if (ret) 
				break;
			nf = 1;
			fprintf(covfile, "SF:%s\n", fpath);
			fprintf(covfile, "FN:%i,%s\n", nmline, afname);
			fprintf(covfile, "FNDA:1,%s\n", afname);
			fprintf(covfile, "DA:%i,1\n", nmline);
			fprintf(covfile, "end_of_record\n");
			break;
		}
		fgets(str, 200, adfile);
		if (ret != 2 && !nf) {			
			ret = copypath(fpath, &aline, str);
			if (!ret) {
				fprintf(covfile, "SF:%s\n", fpath);
				fprintf(covfile, "FN:%i,%s\n", aline, afname);
				fprintf(covfile, "FNDA:1,%s\n", afname);
				fprintf(covfile, "DA:%i,1\n", aline);
				fprintf(covfile, "end_of_record\n");
				nf = 1;
			} else if (ret == 3) {
				srcfile = fopen(fpath, "r");
				if (!srcfile)
					return 1;
				nmline = 0;
				while (fgets(srcstr, 1024, srcfile) != NULL) {
					nmline++;
					match = strstr(srcstr, afname);
					if (!match) 
						continue;
					len = strlen(afname);
					if (match[len] != '(' && match[len] != ' ')
						continue;
					if (!isspace(srcstr[0])) {
						nf = 1;
						break;
					}
				}
				if (nf) {
					fprintf(covfile, "SF:%s\n", fpath);
					fprintf(covfile, "FN:%i,%s\n", nmline, afname);
					fprintf(covfile, "FNDA:1,%s\n", afname);
					fprintf(covfile, "DA:%i,1\n", nmline);
					fprintf(covfile, "end_of_record\n");
				}
			}
		}
		
		if (ret == 2)
			fprintf(notfound, "%s: in /usr/obj: ", afname);
		else if (!nf)
			fprintf(notfound, "%s: not found: ", afname);

		if (!nf)
			fprintf(notfound, "%s", str);

		nf = 0;
		fseek(nmfile, 0, SEEK_SET);
	}
	
	fclose(notfound);
	fclose(covfile);
	return 0;
}

int main(int argc, char **argv)
{
	int fd, pid, status, nbuf = 0, nl = 0, html = 0;
	FILE *nmfile, *addrfile;
	size_t *cover, *buffer;
	char fname[40];
	char command[200];
	char smbl;

	if (argc == 1)
		fprintf(stderr, "usage: kcovtrace [--html] program [args...]\n"), exit(1);
	if (!strcmp(argv[1], "--html"))
		html = 1;
	nmfile = fopen(KERNEL, "r");
	if (!nmfile)
		perror("File "KERNEL), exit(1);
	fclose(nmfile);
	nmfile = fopen(KERNDIR, "r");
	if (!nmfile) 
		perror("Directory "KERNDIR), exit(1);
	fclose(nmfile);
		
	fd = open(KCOV_PATH, O_RDWR);
	if (fd == -1)
		perror("open"), exit(1);

	if (ioctl(fd, KIOSETBUFSIZE, COVER_SIZE))
		perror("ioctl:KIOSETBUFSIZE"), exit(1);
	cover = (size_t*)mmap(NULL, COVER_SIZE * KCOV_ENTRY_SIZE,
			       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if ((void *)cover == MAP_FAILED)
		perror("mmap"), exit(1);
	pid = fork();
	if (pid < 0)
		perror("fork"), exit(1);
	if (pid == 0) {
		if (ioctl(fd, KIOENABLE, KCOV_MODE_TRACE_PC))
			perror("ioctl:KIOENABLE"), exit(1);
		cover[0] = 0;
		if (html)
			execvp(argv[2], argv + 2);
		else
			execvp(argv[1], argv + 1);
		perror("execvp");
		exit(255);
	}
	buffer = malloc(bufsize);
	if (!buffer){
		kill(pid, SIGTERM);
		perror("malloc: BUF_SIZE"), exit(1);
	}
	//control the child proccess
	while (waitpid(-1, &status, WNOHANG) != pid) {
		if (cover[0] > COUNT) {
			kill(pid, SIGSTOP);
			if (wtbuffer(fname, cover, buffer, &nbuf)) {
				kill(pid, SIGTERM);
				perror("wtbuffer"), exit(1);
			}
			cover[0] = 0;
			kill(pid, SIGCONT);
		}
	}
	
	if (WEXITSTATUS(status) == 255) {
		if (html)			
			fprintf(stderr, "File %s not found\n", argv[2]);
		else
			fprintf(stderr, "File %s not found\n", argv[1]);
		exit(1);
	}
	if (wtbuffer(fname, cover, buffer, &nbuf)) {
		perror("wtbuffer"), exit(1);
	}
	if (munmap(cover, COVER_SIZE * KCOV_ENTRY_SIZE))
		perror("munmap"), exit(1);
	if (close(fd))
		perror("close"), exit(1);
	
	char *a2l;
	nmfile = fopen(ADDR2LINE, "r");
	if (nmfile) {
		a2l = ADDR2LINE;
		fclose(nmfile);
	} else
		a2l = "addr2line";

	qsort(buffer, nbuf, KCOV_ENTRY_SIZE, compare);
	if (wtfile(buffer, nbuf))
		perror("wtfile"), exit(1);

	//use addr2file system program to get function and file names 
	sprintf(command, "%s -f -e "KERNEL" < rawfile.log | tee trace.log", a2l);
	system(command);
	free(buffer);

	if (!html) {
		printf("Full report in trace.log file\n");
		return 0;
	}

	//use the nm system program to get a list of all kernel functions,
	//except static functions
	nmfile = fopen("nmlines.txt", "r");
	if (!nmfile) {
		system("nm --debug-syms -elP "KERNEL" | tee nmlines.txt");
		nmfile = fopen("nmlines.txt", "r");
		if (!nmfile)
			perror("nmlines"), exit(1);
	}

	addrfile = fopen("trace.log", "r");
	if (!addrfile)
		perror("open: addrfile"), exit(1);
	if (coverage(nmfile, addrfile))
		perror("coverage"), exit(1);
	fclose(addrfile);
	fclose(nmfile);

	//generate html coverage report
	system("rm -R "COV_DIR);
	if (system("genhtml coverage.info --output-directory ./"COV_DIR)) {
		printf("\nlcov not installed\nUse: genhtml coverage.info --output-directory /out/dir");
		exit(1);
	}

	printf("Full report in trace.log file\n");
	printf("Html report in cov_info directory\n");
	printf("Functions not shown in html report are in notfound.log file\n");
	return 0;
}
