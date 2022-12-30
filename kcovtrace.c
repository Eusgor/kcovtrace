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
typedef uint64_t cover_t;
#define COVER_SIZE (16 << 20)
#define COUNT 15000000
#define COV_FILE "coverage.info"
#define ADDR2LINE "/usr/local/bin/addr2line"
#define KERNEL "/usr/obj/usr/src/amd64.amd64/sys/GENERIC/kernel.debug"
#define KERNDIR "/usr/src/sys"
#define COV_DIR "cov_info_full"

#define NOTFOUND 1
#define NF_FILE "notfound.txt"  //not found functions

static int compare(const void *p1, const void *p2)
{
	cover_t i = *((cover_t *)p1);
	cover_t j = *((cover_t *)p2);

	if (i > j) return (1);
	if (i < j) return (-1);
	return (0);
}

int wtfile(char *fname, int j, cover_t *cover)
{
	FILE *fd;
	long i;
	cover_t *dupl = malloc(cover[0] * KCOV_ENTRY_SIZE);
	if (!dupl) return 1;
	memcpy(dupl, &cover[1], cover[0] * KCOV_ENTRY_SIZE);

	qsort(dupl, cover[0], KCOV_ENTRY_SIZE, compare);

	sprintf(fname, "rawfiles/rawfile%i.txt", j);
	fd = fopen(fname, "w");
	if (!fd) return 1;
	fprintf(fd, "%jx\n", (uintmax_t)dupl[0]);
	for (i = 0; i < cover[0] - 1; i++) {
		if (dupl[i] != dupl[i + 1])
			fprintf(fd, "%jx\n", (uintmax_t)dupl[i + 1]);
	}
	fclose(fd);
	free(dupl);
	return 0;
}

int copyfunc(char *nmfname, char *str)
{
	int i;
	for (i = 0; str[i] != ' '; i++) {
		nmfname[i] = str[i];
	}
	nmfname[i] = '\0';
	return 0;
}

int copypath(char *fpath, int *line, char *str)
{
	int i;
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
	int k;
	for (k = 0; !isspace(start[i]); i++, k++) {
		nmline[k] = start[i];
	}
	nmline[k] = '\0';
	printf("%s:%s\n", fpath, nmline);
	*line = atoi(nmline);
	return 0;
}

int coverage(FILE *nmfile, FILE *adfile, int fl) 
{
	FILE *covfile;
	int nmline, ret;    // line number in nm file
	char afname[100];  	// function name in address file
	char nmfname[100] = "";  // function name in nm file
	char fpath[200];  	// function path in nm file
	char str[400]; 		// nm file string
	if (fl)
		covfile = fopen(COV_FILE, "a");
	else
		covfile = fopen(COV_FILE, "w");

#ifdef NOTFOUND
	int nf = 0;
	FILE *notfound;
	if (fl)
		notfound = fopen(NF_FILE, "a");
	else
		notfound = fopen(NF_FILE, "w");
#endif

	while (fgets(afname, 100, adfile) != NULL) {
		afname[strlen(afname) - 1] = '\0';
		// TODO if functions are repeated 
		if (afname[0] == '?' || !strcmp(nmfname, afname)) {
			fgets(afname, 100, adfile);
			continue;
		}		
		while (fgets(str, 400, nmfile) != NULL) {
			copyfunc(nmfname, str);
			if (strcmp(nmfname, afname)) 
				continue;
			printf("%s\n", nmfname);
			ret = copypath(fpath, &nmline, str);
			if (ret) 
				break;
#ifdef NOTFOUND
			nf = 1;
#endif
			fprintf(covfile, "SF:%s\n", fpath);
			fprintf(covfile, "DA:%i,1\nDA:%i,1\nDA:%i,1\n", nmline -2, nmline -1, nmline);
			fprintf(covfile, "end_of_record\n");
			break;
		}
#ifdef NOTFOUND
		if (ret == 2)
			fprintf(notfound, "%s: in /usr/obj/\n", afname);
		else if (!nf)
			fprintf(notfound, "%s: not found: ", afname);
#endif
		fgets(afname, 100, adfile);
#ifdef NOTFOUND
		if (!nf)
			fprintf(notfound, "%s", afname);
		nf = 0;
#endif
		fseek(nmfile, 0, SEEK_SET);
	}
	
#ifdef NOTFOUND
	fclose(notfound);
#endif

	fclose(covfile);
	return 0;
}

int main(int argc, char **argv)
{
	int fd, pid, status, nl = 0;
	FILE *nmfile, *addrfile;
	cover_t *cover;
	int j = 1;
	char fname[40];
	char command[200];
	char smbl;

	system("rm -R rawfiles");
	mkdir("rawfiles", 0755);

	if (argc == 1)
		fprintf(stderr, "usage: kcovtrace program [args...]\n"), exit(1);
	nmfile = fopen(KERNEL, "r");
	if (!nmfile)
		perror("File "KERNEL" doesn't exist"), exit(1);
	fclose(nmfile);
	nmfile = fopen(KERNDIR, "r");
	if (!nmfile)
		perror("Directory "KERNDIR" doesn't exist"), exit(1);
	fclose(nmfile);
		
	fd = open(KCOV_PATH, O_RDWR);
	if (fd == -1)
		perror("open"), exit(1);

	if (ioctl(fd, KIOSETBUFSIZE, COVER_SIZE))
		perror("ioctl:KIOSETBUFSIZE"), exit(1);
	cover = (cover_t*)mmap(NULL, COVER_SIZE * KCOV_ENTRY_SIZE,
			       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if ((void*)cover == MAP_FAILED)
		perror("mmap"), exit(1);
	pid = fork();
	if (pid < 0)
		perror("fork"), exit(1);
	if (pid == 0) {
		if (ioctl(fd, KIOENABLE, KCOV_MODE_TRACE_PC))
			perror("ioctl:KIOENABLE"), exit(1);
		cover[0] = 0;
		execvp(argv[1], argv + 1);
		perror("execvp");
		exit(1);
	}
	while (waitpid(-1, &status, WNOHANG) != pid) {
		if (cover[0] > COUNT) {
			kill(pid, SIGSTOP);
			if (wtfile(fname, j, cover)) {
				kill(pid, SIGTERM);
				perror("wtfile"), exit(1);
			}
			j++;
			cover[0] = 0;
			kill(pid, SIGCONT);
		}
	}
	if (wtfile(fname, j, cover)) {
		perror("wtfile"), exit(1);
	}
	if (munmap(cover, COVER_SIZE * KCOV_ENTRY_SIZE))
		perror("munmap"), exit(1);
	if (close(fd))
		perror("close"), exit(1);
	
	system("rm -R addrs");
	mkdir("addrs", 0755);
	char *a2l;
	nmfile = fopen(ADDR2LINE, "r");
	if (nmfile) {
		a2l = ADDR2LINE;
		fclose(nmfile);
	} else
		a2l = "addr2line";
	for (int k = 0; k < j; k++) {
		sprintf(command, "%s -f -e "KERNEL" < rawfiles/rawfile%i.txt | tee addrs/addrtrace%i.txt", a2l, k + 1, k + 1);
		system(command);
	}

	nmfile = fopen("nmlines.txt", "r");
	if (!nmfile) {
		system("nm --debug-syms -elP "KERNEL" | tee nmlines.txt");
		nmfile = fopen("nmlines.txt", "r");
	}

	int fl = 0;
	for (int k = 0; k < j; k++) {
		sprintf(fname, "addrs/addrtrace%i.txt", k + 1);
		addrfile = fopen(fname, "r");
		coverage(nmfile, addrfile, fl);
		fclose(addrfile);
		fl = 1;
	}
	fclose(nmfile);

	system("rm -R "COV_DIR);
	if (system("genhtml coverage.info --output-directory ./"COV_DIR)) {
		printf("\nlcov not installed\nUse: genhtml coverage.info --output-directory /out/dir");
		exit(1);
	}

	return 0;
}
