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
  0x37,                                              /* aaa */

  0xD5, 0x0A,                                        /* aad */
  0xD5, 0x55,                                        /* aad 0x55 */

  0xD4, 0x0A,                                        /* aam */
  0xD4, 0x43,                                        /* aam 0x43 */

  0x3F,                                              /* aas */

  0x14, 0x55,                                        /* adc al, 0x55 */
  0x15, 0x12, 0x34,                                  /* adc ax, 0x3412 */
  0x66, 0x15, 0x78, 0x56, 0x34, 0x12,                /* adc eax, 0x12345678 */
  0x80, 0x10, 0x55,                                  /* adc [bx+si], 0x55 */
  0x81, 0x10, 0x34, 0x12,                            /* adc [bx+si], 0x1234 */
  0x67, 0x81, 0x10, 0x34, 0x12,                      /* adc [eax], 0x1234 */
  0x66, 0x81, 0x10, 0x78, 0x56, 0x34, 0x12,          /* adc [bx+si], 0x12345678 */
  0x67, 0x66, 0x81, 0x10, 0x78, 0x56, 0x34, 0x12,    /* adc [eax], 0x12345678 */
  0x83, 0x10, 0x55,                                  /* adc [bx+si], 0x55 */
  0x66, 0x83, 0x10, 0x55,                            /* adc [bx+si], 0x55 */
  0x10, 0x3D,                                        /* adc [di], bh */
  0x67, 0x10, 0x3D, 0x78, 0x56, 0x34, 0x12,          /* adc [+0x12345678], bh */
  0x11, 0xE0,                                        /* adc ax, sp */
  0x66, 0x11, 0xE0,                                  /* adc eax, esp */
  0x67, 0x66, 0x11, 0xE0,                            /* adc eax, esp */
  0x12, 0x77, 0x96,                                  /* adc dh, [bx+0x96] */
  0x13, 0x77, 0x96,                                  /* adc si, [bx+0x96] */
  0x66, 0x13, 0x77, 0x96,                            /* adc esi, [bx+0x96] */

  0x04, 0x55,                                        /* add al, 0x55 */
  0x05, 0x55, 0x66,                                  /* add ax, 0x6655 */
  0x66, 0x05, 0x78, 0x56, 0x34, 0x12,                /* add eax, 0x12345678 */
  0x80, 0x00, 0x05,                                  /* add [bx+si], 0x05 */
  0x81, 0x01, 0x34, 0x12,                            /* add [bx+di], 0x1234 */
  0x66, 0x81, 0x01, 0x78, 0x56, 0x34, 0x12,          /* add [bx+di], 0x12345678 */
  0x83, 0x00, 0x15,                                  /* add [bx+si], 0x15 */
  0x66, 0x83, 0x00, 0x15,                            /* add [bx+si], 0x15 */
  0x00, 0x33,                                        /* add [bp+di], dh */
  0x01, 0x33,                                        /* add [bp+di], si */
  0x66, 0x01, 0x33,                                  /* add [bp+di], esi */
  0x02, 0x33,                                        /* add dh, [bp+di] */
  0x03, 0x33,                                        /* add si, [bp+di] */
  0x66, 0x03, 0x33,                                  /* add esi, [bp+di] */

  0x0F, 0x58, 0x33,                                  /* addps xmm6, [bp+di] */

  0x24, 0x45,                                        /* and al, 0x45 */
  0x25, 0x12, 0x34,                                  /* and ax, 0x3412 */
  0x66, 0x25, 0x78, 0x56, 0x34, 0x12,                /* and eax, 0x12345678 */
  0x80, 0x27, 0x55,                                  /* and [bx], 0x55 */
  0x81, 0x27, 0x34, 0x12,                            /* and [bx], 0x1234 */
  0x66, 0x81, 0x27, 0x78, 0x56, 0x34, 0x12,          /* and [bx], 0x12345678 */
  0x83, 0xA4, 0x54, 0x43, 0x88,                      /* and [si+0x4354], 0x88 */
  0x66, 0x83, 0xA4, 0x54, 0x43, 0x88,                /* and [si+0x4354], 0x88 */
  0x20, 0xCD,                                        /* and ch, cl */
  0x21, 0x46, 0x77,                                  /* and [bp+0x77], ax */
  0x66, 0x21, 0x14,                                  /* and [si], edx */
  0x22, 0xCD,                                        /* and cl, ch */
  0x23, 0x46, 0x77,                                  /* and ax, [bp+0x77] */
  0x66, 0x23, 0x14,                                  /* and edx, [si] */

  0x63, 0x10,                                        /* arpl [bx+si], dx */

  0x62, 0x10,                                        /* bound dx, [bx+si] */
  0x66, 0x62, 0x10,                                  /* bound edx, [bx+si] */

  0xE8, 0x56, 0x22,                                  /* call near +0x2256 */
  0x66, 0xE8, 0x78, 0x56, 0x34, 0x12,                /* call near +0x12345678 */

  0xFF, 0x16, 0x34, 0x88,                            /* call near [+0x8834] */
  0xFF, 0x15,                                        /* call near [di] */
  0x66, 0xFF, 0x15,                                  /* call near [di] */
  0x9A, 0x78, 0x56, 0x34, 0x12,                      /* call far 0x1234:0x5678 */
  0x66, 0x9A, 0x78, 0x56, 0x34, 0x12, 0x90, 0x87,    /* call far 0x8790:0x12345678 */
  0xFF, 0x1A,                                        /* call far [bp+si] */
  0x66, 0xFF, 0x1A,                                  /* call far [bp+si] */

  0xD8, 0x01,                                        /* fadd st0, [bx+di] */
  0xDC, 0x01,                                        /* fadd st0, [bx+di] */
  0xD8, 0xC0,                                        /* fadd st0, st0 */
  0xD8, 0xC1,                                        /* fadd st0, st1 */
  0xD8, 0xC2,                                        /* fadd st0, st2 */
  0xD8, 0xC3,                                        /* fadd st0, st3 */
  0xD8, 0xC4,                                        /* fadd st0, st4 */
  0xD8, 0xC5,                                        /* fadd st0, st5 */
  0xD8, 0xC6,                                        /* fadd st0, st6 */
  0xD8, 0xC7,                                        /* fadd st0, st7 */
  0xDC, 0xC0,                                        /* fadd st0, st0 */
  0xDC, 0xC1,                                        /* fadd st1, st0 */
  0xDC, 0xC2,                                        /* fadd st2, st0 */
  0xDC, 0xC3,                                        /* fadd st3, st0 */
  0xDC, 0xC4,                                        /* fadd st4, st0 */
  0xDC, 0xC5,                                        /* fadd st5, st0 */
  0xDC, 0xC6,                                        /* fadd st6, st0 */
  0xDC, 0xC7,                                        /* fadd st7, st0 */
  0xDE, 0xC0,                                        /* faddp st0, st0 */
  0xDE, 0xC1,                                        /* faddp st1, st0 */
  0xDE, 0xC2,                                        /* faddp st2, st0 */
  0xDE, 0xC3,                                        /* faddp st3, st0 */
  0xDE, 0xC4,                                        /* faddp st4, st0 */
  0xDE, 0xC5,                                        /* faddp st5, st0 */
  0xDE, 0xC6,                                        /* faddp st6, st0 */
  0xDE, 0xC7,                                        /* faddp st7, st0 */
  0xDA, 0x02,                                        /* fiadd st0, [bp+si] */
  0xDE, 0x03,                                        /* fiadd st0, [bp+di] */

  0x88, 0x89, 0x23, 0x76,                            /* mov [bx+di+0x7623], cl */
  0x89, 0x89, 0x23, 0x76,                            /* mov [bx+di+0x7623], cx */
  0x66, 0x89, 0x89, 0x23, 0x76,                      /* mov [bx+di+0x7623], ecx */
  0x8A, 0x89, 0x23, 0x76,                            /* mov cl, [bx+di+0x7623] */
  0x8B, 0x89, 0x23, 0x76,                            /* mov cx, [bx+di+0x7623] */
  0x66, 0x8B, 0x89, 0x23, 0x76,                      /* mov ecx, [bx+di+0x7623] */
  0x8C, 0x00,                                        /* mov [bx+si], es */
  0x8C, 0x08,                                        /* mov [bx+si], cs */
  0x8C, 0x10,                                        /* mov [bx+si], ss */
  0x8C, 0x18,                                        /* mov [bx+si], ds */
  0x8C, 0x20,                                        /* mov [bx+si], fs */
  0x8C, 0x28,                                        /* mov [bx+si], gs */
  0x67, 0x8C, 0x00,                                  /* mov [eax], es */
  0x8E, 0x01,                                        /* mov es, [bx+di] */
  0x8E, 0x09,                                        /* mov cs, [bx+di] */
  0x8E, 0x11,                                        /* mov ss, [bx+di] */
  0x8E, 0x19,                                        /* mov ds, [bx+di] */
  0x8E, 0x21,                                        /* mov fs, [bx+di] */
  0x8E, 0x29,                                        /* mov gs, [bx+di] */
  0xA0, 0x56, 0x23,                                  /* mov al, [+0x2356] */
  0x67, 0xA0, 0x56, 0x23, 0x45, 0x89,                /* mov al, [+0x89452356] */
  0xA1, 0x56, 0x23,                                  /* mov ax, [+0x5623] */
  0x66, 0xA1, 0x56, 0x23,                            /* mov eax, [+0x5623] */
  0x66, 0x67, 0xA1, 0x56, 0x23, 0x45, 0x89,          /* mov eax, [+0x89455623] */
  0xA2, 0x56, 0x23,                                  /* mov [+0x2356], al */
  0x67, 0xA2, 0x56, 0x23, 0x45, 0x89,                /* mov [+0x89452356], al */
  0xA3, 0x56, 0x23,                                  /* mov [+0x5623], ax */
  0x66, 0xA3, 0x56, 0x23,                            /* mov [+0x5623], eax */
  0x66, 0x67, 0xA3, 0x56, 0x23, 0x45, 0x89,          /* mov [+0x89455623], eax */
  0xB0, 0x55,                                        /* mov al, 0x55 */
  0xB1, 0x55,                                        /* mov cl, 0x55 */
  0xB2, 0x55,                                        /* mov dl, 0x55 */
  0xB3, 0x55,                                        /* mov bl, 0x55 */
  0xB4, 0x55,                                        /* mov ah, 0x55 */
  0xB5, 0x55,                                        /* mov ch, 0x55 */
  0xB6, 0x55,                                        /* mov dh, 0x55 */
  0xB7, 0x55,                                        /* mov bh, 0x55 */
  0xB8, 0x23, 0x78,                                  /* mov ax, 0x7823 */
  0xB9, 0x23, 0x78,                                  /* mov cx, 0x7823 */
  0xBA, 0x23, 0x78,                                  /* mov dx, 0x7823 */
  0xBB, 0x23, 0x78,                                  /* mov bx, 0x7823 */
  0xBC, 0x23, 0x78,                                  /* mov sp, 0x7823 */
  0xBD, 0x23, 0x78,                                  /* mov bp, 0x7823 */
  0xBE, 0x23, 0x78,                                  /* mov si, 0x7823 */
  0xBF, 0x23, 0x78,                                  /* mov di, 0x7823 */
  0x66, 0xB8, 0x23, 0x78, 0x45, 0x99,                /* mov eax, 0x99457823 */
  0x66, 0xB9, 0x23, 0x78, 0x45, 0x99,                /* mov ecx, 0x99457823 */
  0x66, 0xBA, 0x23, 0x78, 0x45, 0x99,                /* mov edx, 0x99457823 */
  0x66, 0xBB, 0x23, 0x78, 0x45, 0x99,                /* mov ebx, 0x99457823 */
  0x66, 0xBC, 0x23, 0x78, 0x45, 0x99,                /* mov esp, 0x99457823 */
  0x66, 0xBD, 0x23, 0x78, 0x45, 0x99,                /* mov ebp, 0x99457823 */
  0x66, 0xBE, 0x23, 0x78, 0x45, 0x99,                /* mov esi, 0x99457823 */
  0x66, 0xBF, 0x23, 0x78, 0x45, 0x99,                /* mov edi, 0x99457823 */
  0xC6, 0x00, 0x55,                                  /* mov [bx+si], 0x55 */
  0xC7, 0x00, 0x23, 0x56,                            /* mov [bx+si], 0x5623 */
  0x66, 0xC7, 0x00, 0x23, 0x56, 0x78, 0x99,          /* mov [bx+si], 0x99785623 */

  0x0F, 0x22, 0xF3,                                  /* mov cr6, ebx */
  0x0F, 0x22, 0xFC,                                  /* mov cr7, esp */
  0x0F, 0x22, 0xD3,                                  /* mov cr2, ebx */
  0x0F, 0x20, 0xF3,                                  /* mov ebx, cr6 */
  0x0F, 0x20, 0xFC,                                  /* mov esp, cr7 */
  0x0F, 0x20, 0xD3,                                  /* mov ebx, cr2 */
  0x0F, 0x21, 0xF3,                                  /* mov ebx, dr6 */
  0x0F, 0x21, 0xFC,                                  /* mov esp, dr7 */
  0x0F, 0x21, 0xD3,                                  /* mov ebx, dr2 */
  0x0F, 0x23, 0xF3,                                  /* mov dr6, ebx */
  0x0F, 0x23, 0xFC,                                  /* mov dr7, esp */
  0x0F, 0x23, 0xD3,                                  /* mov dr2, ebx */

  0x0F, 0x28, 0x33,                                  /* movaps xmm6, [bp+di] */
  0x0F, 0x29, 0x33,                                  /* movaps [bp+di], xmm6 */
  0x67, 0x0F, 0x28, 0x15, 0x40, 0x91, 0x04, 0x08,    /* movaps xmm2, [+0x08049140] */

  0x0F, 0x10, 0x33,                                  /* movups xmm6, [bp+di] */
  0x0F, 0x11, 0x33,                                  /* movups [bp+di], xmm6 */

  0x0F, 0xF1, 0x36, 0x34, 0x12,                      /* psllw mm6, [+0x1234] */
  0x0F, 0xF1, 0xD0,                                  /* psllw mm2, mm0 */
  0x0F, 0x71, 0x36, 0x01,                            /* psllw mm6, 0x01 */
  0x0F, 0x71, 0xB1, 0x02,                            /* psllw mm1, 0x02 */
  0x0F, 0x71, 0xF3, 0x03,                            /* psllw mm3, 0x03 */

  0x0F, 0xEF, 0xD0,                                  /* pxor mm2, mm0 */
  0x0F, 0xEF, 0xEE,                                  /* pxor mm5, mm6 */
  0x0F, 0xEF, 0x2C,                                  /* pxor mm5, [si] */
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
