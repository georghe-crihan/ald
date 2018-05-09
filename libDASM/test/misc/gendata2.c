/*
 * This program is designed to test the libDASM library. It generates
 * a file called 'data' with various assembly language instructions
 * in it. The program 'disasm' can then be used to disassemble it.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

/* opcode buffer */

char buf[] = {
  0xE8, 0x78, 0x45, 0x23, 0x10,
  0x0F, 0x20, 0xD8,
  0x0F, 0x21, 0xF3,
  0x0F, 0x21, 0xFC,
  0x0F, 0x21, 0xD3,
  0x0F, 0x23, 0xF3,
  0x0F, 0x23, 0xFC,
  0x0F, 0x23, 0xD3,
};

int
main()

{
  FILE *fp;

  fp = fopen("data", "w");
  if (!fp)
  {
    printf("error: %s\n", strerror(errno));
    return 0;
  }

  fwrite(buf, 1, sizeof(buf), fp);

  fclose(fp);

  return 0;
}
