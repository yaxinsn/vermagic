/*
 * A tool read and set section value
 * Writed by zet (feqin1023 AT gmail dot com)
 *
 * 2018/02/01 - Updated by Abel Romero Pérez aka D1W0U <abel@abelromero.co>
 * I've fixed the check_vermagic() and set_vermagic() functions.
 * unload_module() dumps the memory into the module (saves the modification of vermagic).
 * So we are able to see the module info section fine, and to modify the vermagic.
 * Also cleaned the source code.
 *
 * I've tested it to work on Ubuntu Linux Kernel, 4.13.0-32-generic => 4.13.0-31-generic
 *
 * Work done for the ARP-RootKit.
*/

#include <ctype.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/mman.h>

/// ELF object
#define EI_CLASS 4
#define ELF_32 1
#define ELF_64 2
// none = 0, Elf32 = 1, Elf64 = 2
int class_flag;

/// This data structure defined in linux kernel, include/kernel/module.h
#define MODULE_NAME_LEN	 (64 - sizeof(unsigned long))
typedef struct modversion_info {
	unsigned long crc;
	char name[MODULE_NAME_LEN];
} version_t;

#define VMAGIC_LEN 8 // Length of "vermagic" variable.

/// All of these elf structure pointer point to mapped virtual address.
Elf32_Ehdr *eh_32;
Elf64_Ehdr *eh_64;
// TODO useless
Elf32_Phdr *phdr_32;
Elf64_Phdr *phdr_64;
Elf32_Shdr *sha_32;
Elf64_Shdr *sha_64;
/// Module name
char *name;
/// Virtual address of mapped module
char *map;
/// Virtual address of sction header string table 
char *vaddr_shst;
// file descriptor of the module
int file;
// file state buffer
struct stat sb;
// program name
char *bin = NULL;

void usage (FILE *stream) {
  fprintf(stream, 
  "Read and set vermagic and crc of module\n"
  "Usage: %s <options> <module>\n"
  "Options are:\n"
  "\t-d, dump .modinfo section.\n"
  "\t-v new-value, set vermagic.\n"
  "\t-D, dump CRCs.\n"
  "\t-c {\"+'{'name, no-zero-value'}'\"}, set CRC.\n",
  bin
  );

  exit(stream == stdout ? EXIT_SUCCESS : EXIT_FAILURE);
}

/// Initialize the global elf variables
void set_elf_data ()
{
  Elf32_Shdr *shst_32;
  Elf64_Shdr *shst_64;

  if (class_flag == ELF_64) {

#define SET_ELF_DATA_ARCH(A)                                            \
    eh_##A = (Elf##A##_Ehdr *)map;                                      \
    /* program header mostly is empty in shared module*/                \
    if (eh_##A->e_phoff)                                                \
      phdr_##A = (Elf##A##_Phdr *)((char *)eh_##A + eh_##A->e_phoff);   \
    sha_##A = (Elf##A##_Shdr *)((char *)eh_##A + eh_##A->e_shoff);      \
    shst_##A = &sha_##A[eh_##A->e_shstrndx];                            \
    /* this is a common variable for elf32 and elf64*/                  \
    vaddr_shst = map + shst_##A->sh_offset;                             \

    SET_ELF_DATA_ARCH(64)
  } else {        
    SET_ELF_DATA_ARCH(32)
  }

  return;
}

int load_module () {
  // file descriptor of the module
  int file;

  assert(name);
  file = open(name, O_RDWR);
  
  if (file == -1) {
    perror("open");
    return EXIT_FAILURE;
  }

  if (fstat(file, &sb) == -1) {
    perror("fstat");
    return EXIT_FAILURE;
  }

  // TODO: maybe need a more carefull protection value.
  // for now READ and write.
  map = (char *)mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, 
                             MAP_SHARED, file, 0);
  if(map == MAP_FAILED) {
    perror("mmap");
    return EXIT_FAILURE;
  }

  // check elf object version, EI_CLASS == 4
  class_flag = (int) *(map + EI_CLASS);
  if (class_flag != ELF_32 && class_flag != ELF_64) {
    fprintf(stderr, "error: Module :%s format error\n", name);
    return EXIT_FAILURE;
  }

  // if i386 operate elf64
#ifdef __i386__
  if (class_flag == ELF_64)
    fprintf(stderr, "error: You are operating ELF64 object in 32 bits machine.\
       \nMostly you will receive Segmentation Fault.                          \
       \nIf you really need do this.                                          \
       \nContact me: feqin1023 AT gmail dot com                               \
       \n");
#endif

  set_elf_data();

  return EXIT_SUCCESS;
}

/// if find return the section index
//  not return 0 
unsigned int find_section (char *name) {
  unsigned int i = 0, sec_num = 0;

  if (class_flag == ELF_64) {
//        
#define FIND_SECTION_ARCH(A)                                        \
    sec_num = (unsigned int)eh_##A->e_shnum;                        \
    assert(sec_num && "elf section number is 0");                   \
                                                                    \
    for (; i < sec_num; i++)                                        \
      if (! strcmp(vaddr_shst + sha_##A[i].sh_name, name)) {        \
        printf("Section name:\t\t\t\t%s\n", name);                  \
        return i;                                                   \
      }                                                             \
                                                                    \
    /* if has not find sectuion*/                                   \
    if (i == (unsigned int)eh_##A->e_shnum)                         \
      fprintf(stderr, "Not any section named: %s\n", name);         \
 
    // elf64
    FIND_SECTION_ARCH(64)
  } else {
    // elf32
    FIND_SECTION_ARCH(32)
  }

  return 0;
}

void formalize(char *p, char **name, unsigned long *value) {
  char *comma, *last, ch;

  // {+'{'(name)?, no-zero-value'}'}?
  if (*p != '{')
    usage(stderr);
  // skip '{' and space/tab
  while (isspace(*++p))
    ;
  // only one comma
  if (!(comma = strchr(p, ',')) || !(last = strrchr(p, ',')) || comma != last)
    usage(stderr);
  //
  if (isalpha(ch = *p) || ch == '_' || ch == ',') {
    if (ch != ',') {
      *name = p;
      p = comma;
      // skip space and tab before comma
      while (isspace(*--p))
        ;
      // set name null-terminate
      ++p;
      *p = 0;
    }
    *value = strtoul(++comma, NULL, 0);
  }else
    usage(stderr);

  if (*value == 0)
    usage(stderr);
}

int set_crc (char *crc) {
  version_t *vv;
  unsigned int vn, i = 0;
  size_t vs;
  char *cn;
  unsigned long cv;
  int flag = 0;

  if (! (i = find_section("__versions")))
    return EXIT_FAILURE;
  if (class_flag == ELF_64) {

#define SET_CRC_ARCH(A)                                                       \
      vv = (version_t *)((char *)eh_##A + sha_##A[i].sh_offset);              \
      vs = (size_t)sha_##A[i].sh_size;                                        \
    
    // elf64
    SET_CRC_ARCH(64)
  } else {
    // elf32
    SET_CRC_ARCH(32)
  }
  // number of modversion entry
  vn = vs / sizeof(version_t);
  
  formalize(crc, &cn, &cv);
  if (strlen(cn) + 1 > MODULE_NAME_LEN) {
    fprintf(stderr, "Size of new crc name can not beyond %ld\n",
            MODULE_NAME_LEN);
    return EXIT_FAILURE;
  }
  // 
  for (i = 0; i < vn; i++) {
    if (! strcmp(vv[i].name, cn)) {
      flag = 1;
      printf("{-}Old value => %s:\t\t 0X%lX\n", vv[i].name, vv[i].crc);
      //memcpy(vv[i].name, cn, strlen(cn));
      //vv[i].name[strlen(cn)] = 0;
      vv[i].crc = cv;
      printf("{+}New value => %s:\t\t 0X%lX\n", vv[i].name, vv[i].crc);
      break;
    }
  }

  if (flag == 0)
    fprintf(stderr, "Can not find any crc-name : %s", cn);

  return EXIT_SUCCESS;
}

void dump_modinfo (void) {
  unsigned int i = 0; 
  // section size
  size_t size = 0;
  // original section size
  char *p = NULL;

  if (! (i = find_section(".modinfo")))
    return;

  if (class_flag == ELF_64) {
    p = map + sha_64[i].sh_offset;
    size = (size_t)sha_64[i].sh_size;
  } else {
    p = map + sha_32[i].sh_offset;
    size = (size_t)sha_32[i].sh_size;
  }

  // there is no difference between elf32 and elf64 at this point
  for (i = 0; size > i;) {
    printf("[%03d] %s\n", i, &p[i]);
	i += strlen(&p[i]);
	while (!p[i]) i++; // skip 0's
  }
 
  return;
}

int set_vermagic(char *ver) {
  char *p;
  unsigned int i;
  unsigned long new_len = strlen(ver);
  size_t size;

  // no seection named .modinfo 
  if (! (i = find_section(".modinfo")))
    return EXIT_FAILURE;

  if (class_flag == ELF_64) {
    p = map + sha_64[i].sh_offset;
    size = (size_t)sha_64[i].sh_size;
  } else {
    p = map + sha_32[i].sh_offset;
    size = (size_t)sha_32[i].sh_size;
  }

  for (i = 0; size > i;) {
    if (! strncmp(&p[i], "vermagic", VMAGIC_LEN) && p[i + VMAGIC_LEN] == '=') {
      printf("{-}Old value => %s\n", &p[i]);
      if (new_len > strlen(&p[i + VMAGIC_LEN + 1])) {
        fprintf(stderr, "Length of the new specified vermagic overflow\n");
		return EXIT_FAILURE;
      }
      memcpy(&p[i + VMAGIC_LEN + 1], ver, new_len);
      memset(&p[i + VMAGIC_LEN + 1 + new_len], 0, strlen(&p[i]) - VMAGIC_LEN - 1 - new_len);

      printf("{+}New value => %s\n", &p[i]);
    }
    i += strlen(&p[i]);
    while (!p[i]) i++; // skip 0's
  }

  return EXIT_SUCCESS;
}

int unload_module (void) {
  if (msync(map, sb.st_size, MS_SYNC) == -1) {
    perror("Could not sync the file to disk");
    return EXIT_FAILURE;
  }
  if (munmap(map, sb.st_size) == -1) {
    perror("munmap");
    return EXIT_FAILURE;
  }
  close(file);
  return EXIT_SUCCESS;
}

void dump_crc (void) {
  // version info vector
  version_t *vv;
  unsigned int vn, i = 0;
  size_t vs;

  if (class_flag == ELF_64) {
#define CHECK_CRC_ARCH(A)                                                   \
    if (! (i = find_section("__versions")))                                 \
      return;                                                               \
    vv = (version_t *)((char *)eh_##A + sha_##A[i].sh_offset);              \
    vs = (size_t)sha_##A[i].sh_size;                                        \

    // elf64
    CHECK_CRC_ARCH(64)
  } else {
    // elf32
    CHECK_CRC_ARCH(32)
  }
  //
  vn = vs / sizeof(version_t);

  for (i = 0; i < vn; i++)
    printf("[%03d] %s\t\t\t: 0X%08lX \n", i + 1, vv[i].name, vv[i].crc);

  return;
}

int main (int argc, char **argv) {
  bin = argv[0];
  name = argv[argc - 1];
  
  if (!name || argc < 3) {
    usage(stderr);
  }
  
  if (load_module()) {
	fprintf(stderr, "error: Load module : %s failed.\n", name);
	return EXIT_FAILURE;
  }

  if (!strncmp(argv[1], "-d", 2) && argc == 3) {
    dump_modinfo();
  } else if (!strncmp(argv[1], "-v", 2) && argc == 4) {
    set_vermagic(argv[2]);
  } else if (!strncmp(argv[1], "-D", 2) && argc == 3) {
	dump_crc();
  } else if (!strncmp(argv[1], "-c", 2) && argc == 4) {
	set_crc(argv[2]);
  } else {
	usage(stderr);
  }

  return unload_module();
}

