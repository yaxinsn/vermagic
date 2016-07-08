//=-------------------------------------------------------------------------=//
// A tool read and set section value
// Writed by zet (feqin1023 AT gmail dot com)
//=-------------------------------------------------------------------------=//

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
static int class_flag;

/// This data structure defined in linux kernel, include/kernel/module.h
#define MODULE_NAME_LEN	 (64 - sizeof(unsigned long))
typedef struct modversion_info {
	unsigned long crc;
	char name[MODULE_NAME_LEN];
} version_t;

/// All of these elf structure pointer point to mapped virtual address.
static Elf32_Ehdr *eh_32;
static Elf64_Ehdr *eh_64;
// TODO useless
static Elf32_Phdr *phdr_32;
static Elf64_Phdr *phdr_64;
static Elf32_Shdr *sha_32;
static Elf64_Shdr *sha_64;
/// Module name
static char *name;
/// Virtual address of mapped module
static char *map;
/// Virtual address of sction header string table 
static char *vaddr_shst;
// file descriptor of the module
static int file;
// file state buffer
static struct stat sb;

///
static void
usage (FILE *stream)
{
  fprintf(stream, "Usage: bin <option <+new-value>(s)> <module-name>\n");
  fprintf(stream, " Raed and set vermagic and crc of module\n");
  fprintf(stream, " Opthons are:\n");
  fprintf(stream, "  -v\t\t\t\t\tCheck vermgaic.\n");
  fprintf(stream, "  -v +new-value\t\t\t\tSet vermagiv.\n");
  fprintf(stream, "  -c\t\t\t\t\tCheck crc.\n");
  fprintf(stream, "  -c {\"+'{'name, no-zero-value'}'\"}\tSet crc.\n");

  exit(stream == stdout ? EXIT_SUCCESS : EXIT_FAILURE);
}

/// Initialize the global elf variables
static void
set_elf_data ()
{
  Elf32_Shdr *shst_32;
  Elf64_Shdr *shst_64;
  // print welcome info
  printf("Module name:\t\t\t%s\n", name);

  // Elf64
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

    // elf64
    SET_ELF_DATA_ARCH(64)
  } else {        
    // elf32
    SET_ELF_DATA_ARCH(32)
  }

  return;
}

//
static int
load_module ()
{
  // file descriptor of the module
  int file;

  assert(name);
  file = open(name, O_RDONLY);
  
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
                             MAP_PRIVATE, file, 0);
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
static unsigned int
find_section (char *name)
{
  unsigned int i = 0, sec_num = 0;

  if (class_flag == ELF_64) {
//        
#define FIND_SECTION_ARCH(A)                                        \
    sec_num = (unsigned int)eh_##A->e_shnum;                        \
    assert(sec_num && "elf section number is 0");                   \
                                                                    \
    for (; i < sec_num; i++)                                        \
      if (! strcmp(vaddr_shst + sha_##A[i].sh_name, name)) {        \
        printf("Section name:\t\t\t%s\n", name);                    \
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

///
static void
formalize(char *p, char **name, unsigned long *value) {
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

///
static int
set_crc (char *crc)
{
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
      printf("[-]Old value => %s:\t\t 0X%lX\n", vv[i].name, vv[i].crc);
      //memcpy(vv[i].name, cn, strlen(cn));
      //vv[i].name[strlen(cn)] = 0;
      vv[i].crc = cv;
      printf("[+]New value => %s:\t\t 0X%lX\n", vv[i].name, vv[i].crc);
      break;
    }
  }

  if (flag == 0)
    fprintf(stderr, "Can not find any crc-name : %s", cn);

  return EXIT_SUCCESS;
}

/// After this function value of pp will point to a no-zero character.
//
static void
advance (char **pp, size_t *size)
{
  char *p = *pp;

  if (*p)
    return;
  
  // skip zero
  while (! *p++)
    if (--*size == 0)
      return;

  // update the pointer of caller
  *pp = p;

  return;
}

///
static void
check_vermagic ()
{
  unsigned int i = 0; 
  // section size
  size_t size = 0;
  // original section size
  size_t os;
  char *p = NULL;

  // elf64
  if (class_flag == ELF_64) {

#define CHECK_VERMAGIC_ARCH(A)                                            \
    if (! (i = find_section(".modinfo")))                                 \
      return;                                                             \
                                                                          \
    /* if has not sectuion .modinfo*/                                     \
    if (i == (unsigned int)eh_##A->e_shnum) {                             \
      printf("Warnning: has not any section named .modinfo\n");           \
      return;                                                             \
    }                                                                     \
                                                                          \
    size = sha_##A[i].sh_size;                                            \
    p = map + sha_##A[i].sh_offset;                                       \

    // elf64
    CHECK_VERMAGIC_ARCH(64)
  } else {    
    // elf32
    CHECK_VERMAGIC_ARCH(32)
  }

  os = size;
  // there is no difference between elf32 and elf64 at this point
  for (i = 0; size; p += strlen(p) + 1) {
    advance(&p, &size);
    if (size && strlen(p))
      size -= strlen(p) + 1;
    // variable size pass critical?
    assert(size < os);
    printf("<%03d> %s\n", ++i, p);
  }
 
  return;
}

//
static int
set_vermagic(char *ver)
{
  char *p;
  unsigned int i;
  unsigned long len = strlen("vermagic");
  unsigned long new_len = strlen(ver);
  size_t size, os;

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

  os = size;
  for (; size; p += strlen(p) + 1) {
    advance(&p, &size);
    if (size && strlen(p))
      size -= strlen(p) + 1;
    assert(size < os);
    if (! strncmp(p, "vermagic", len) && p[len] == '=') {
      printf("[-]Old value => %s\n", p);
      if (strlen(ver) > strlen(p) - len - 1) {
        fprintf(stderr, "Length of the new specified vermagic overflow\n");
	return EXIT_FAILURE;
      }
      memcpy(p + len + 1, ver, new_len);
      memset(p + len + 1 + new_len, 0, strlen(p) - len - 1 - new_len);

      printf("[+]New value => %s\n", p);
    }
  }

  return EXIT_SUCCESS;
}

///
static int
unload_module ()
{
  close(file);
  if (munmap(map, sb.st_size) == -1) {
    perror("munmap");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

///
static void
check_crc (void)
{
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
    printf("<%03d> %s\t\t\t: 0X%08lX \n", i + 1, vv[i].name, vv[i].crc);

  return;
}

///
int
main (int argc, char **argv) 
{
  // skip the program name
  int i = 1;
  // 
  size_t opt_len = strlen("-c");

  // initialize module name
  for (; i < argc; ++i) {
    if (name)
      usage(stderr);
    if (*argv[i] != '-' && *argv[i] != '+')
    name = argv[i];
  }
  
  if (! name)
    usage(stderr);
  //
  if (argc == 2 && ! strncmp(argv[1], "--help", strlen("--help")))
    usage(stdout);
  //
  if (! load_module()) {
    for (i = 1; i < argc; ++i) {
      if (! strncmp(argv[i], "-v", opt_len))
        if (*argv[i + 1] == '+')
          set_vermagic(argv[++i] + 1);
        else
          check_vermagic();
      else if (! strncmp(argv[i], "-c", opt_len)) {
        while (*argv[i + 1] == '+')
          set_crc(argv[++i] + 1);
        if (*argv[i] != '+')
          check_crc();
      } else if (i < argc - 1)
        // other options?
        usage(stderr);
    }
  } else {
      fprintf(stderr, "error: Load module : %s failed.\n", name);
      return EXIT_FAILURE;
  }

  return unload_module();
}

