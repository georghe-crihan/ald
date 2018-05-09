/*
 * libDASM
 *
 * Copyright (C) 2000-2003 Patrick Alken
 * This library comes with absolutely NO WARRANTY
 *
 * Should you choose to use and/or modify this source code, please
 * do so under the terms of the GNU General Public License under which
 * this library is distributed.
 *
 * $Id: disasm-x86.c,v 1.3 2004/09/02 00:11:59 pa33 Exp $
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "args-x86.h"
#include "common-x86.h"
#include "disasm-x86.h"
#include "modsib-x86.h"
#include "operands-x86.h"
#include "optab-x86.h"
#include "prefix-x86.h"

/* Top-level includes */
#include "libDASM.h"

static long x86findOpCode(struct disasmWorkspace *ws, unsigned char *data,
                          char *outbuf, struct x86matchInfo *bestmatch);

/*
x86procDisasm()
  Disassemble one instruction

Inputs: ws      - disasm workspace
        data    - data to disassemble
        outbuf  - buffer to store result
        address - address of this opcode in the file or memory;
                  when given, relative addresses such as in a
                  CALL opcode will be added to this to compute
                  an exact target address.

Return: number of bytes disassembled, or if an error occurs -1 and
        an error message goes in outbuf
*/

long
x86procDisasm(struct disasmWorkspace *ws, unsigned char *data,
              char *outbuf, unsigned int address)

{
  unsigned char *origdata;
  long bytesMatched;           /* number of bytes matched to opcode */
  struct x86matchInfo match;   /* opcode matching data */
  int ret;                     /* return result */

  origdata = data;

  assert(data && outbuf);

  memset(&match, '\0', sizeof(struct x86matchInfo));
  ws->prefixFlags = 0;
  ws->effectiveAddress = 0;

  bytesMatched = x86findOpCode(ws, data, outbuf, &match);

  if (bytesMatched < 0)
  {
    /* 'outbuf' will contain the error message */
    return (bytesMatched);
  }
  else if (bytesMatched == 0)
  {
    /* No match found */
    return (0);
  }

  /*
   * We found a good match
   */

  data += bytesMatched;

  ret = x86constructArguments(ws,
                              (unsigned char **) &data,
                              &match,
                              outbuf,
                              address);

  if (ret)
    return (data - origdata);
  else
    return (-1);
} /* x86procDisasm() */

/*
x86findOpCode()
  Attempt to locate best matching opcode for given string in
the x86OpCodes[] array.

Inputs: ws         - disasm workspace
        data       - actual opcode
        outbuf     - string in which to store error messages
        bestmatch  - structure in which to store best matching
                     opcode

Return: Number of bytes matched if matching opcode is found
        0 if no matching opcode found
        -1 if error encountered

Side effects: On a good match, 'bestmatch' is modified to point to
              the matching OpCode structure.

              On an error, -1 is returned and 'outbuf' is modified
              to contain the error message.

Developer's Note:
  The optab.pl scripts sets up the array x86OpCodes[00..FF] with pointers
to different opcode arrays each corresponding to one byte (00..FF). This
byte is the first byte of the opcode. These opcode arrays are called
OpCode_XX where XX is the first byte of the opcode. Since several
different instructions could share the same first byte of their opcodes,
the OpCode_XX arrays contain pointers to all instructions which have
XX as the first byte of their opcode.

  This function looks at data[0] (the first byte of the opcode) and
jumps to the array defined by x86OpCodes[data[0]]. This array may contain
many pointers to different instructions in the array Instructions[], but
we know they all share the same first byte of their opcodes. We then
proceed along the data[] array and compare those bytes with
the opcodes in the OpCode_XX array given by x86OpCodes[data[0]].
*/

static long
x86findOpCode(struct disasmWorkspace *ws, unsigned char *data,
              char *outbuf, struct x86matchInfo *bestmatch)

{
  struct x86OpCode **candidates;         /* opcode candidates */
  unsigned char index;                   /* index into x86OpCodes[] */
  struct x86OpCode **OpPtr;              /* pointer to an opcode candidate */
  struct x86matchInfo matches[MAXBUF];   /* possible opcode matches */
  int midx;                              /* index into matches[] */
  long bytesMatched;                     /* bytes matched on some opcode */
  unsigned char *codeptr;                /* pointer to opcode string */
  int regcode;                           /* register for +rb/+rw/+rd opcodes */
  int fpucode;                           /* register for +i opcodes */
  struct x86ModSibInfo msinfo;           /* ModR/M and SIB information */
  int exactMatch;                        /* set to 1 if we find exact match */
  unsigned char prefBytes;               /* number of bytes in prefix */
  int pret;                              /* return value from x86testPrefix() */
  int ii;                                /* looping */
  int foundBestMatch;                    /* did we find the best match? */
  int betterMatch;                       /* do we have a better match? */

  assert(ws && data && outbuf && bestmatch);

  midx = 0;

  prefBytes = x86processPrefix(ws, data);
  data += prefBytes;

  index = (unsigned char) *data;

  /*
   * We cannot immediately assign candidates to x86OpCodes[*data]
   * since the first byte of the opcode may have been modified
   * by adding an integer between 0-7 to indicate a register code
   * (+rb/+rw/+rd/+i in the IAS manual).
   *
   * If this was the case, x86OpCodes[*data] will be NULL (unless
   * intel has instructions which share the first opcode byte
   * but one of them added a register code to their real first
   * byte - I haven't found any of these).
   */
  while (!*x86OpCodes[index])
  {
    /*
     * Keep decrementing index until we find the real first
     * byte of the opcode - do this no more than 7 times.
     */
    --index;
    if (((unsigned char) *data - index) > 7)
    {
      /*
       * This should never happen - unless there exists
       * a string of 7+ consecutive numbers which aren't used
       * as the first byte of any opcode.
       */
      sprintf(outbuf,
              "x86findOpCode: indices of x86OpCodes[] ranging from %d to %d are \
               all NULL (looking for register code)",
              index,
              (unsigned char) *data);
      return (-1);
    }
  } /* while (!*x86OpCodes[index]) */

  /*
   * Now our instruction candidates are the array x86OpCodes[index]
   */
  candidates = x86OpCodes[index];

  for (OpPtr = candidates; *OpPtr; ++OpPtr)
  {
    exactMatch = 0;
    regcode = (-1);
    fpucode = (-1);
    memset(&msinfo, '\0', sizeof(struct x86ModSibInfo));

    /*
     * (*OpPtr)->mcode is the opcode string for the current
     * instruction we are checking
     */
    codeptr = (unsigned char *) (*OpPtr)->mcode;

    if (*(codeptr + 1) == '\0')
    {
      /*
       * We are dealing with a one byte opcode: this case
       * warrants special attention. If the instruction is
       * defined with +rb/+rw/+rd/+i we need to determine
       * if something between 0-7 was added to the first
       * byte.
       */
      if ((*OpPtr)->digit == REGCODE)        /* +rb/+rw/+rd */
        regcode = (unsigned char) *data - index;
      else if ((*OpPtr)->digit == FPUCODE)   /* +i */
        fpucode = (unsigned char) *data - index;
      else if (index != (unsigned char) *data)
      {
        /*
         * If index and *data do not match, it means our above loop
         * decremented index since OpCodes[*data] was empty. This
         * implies that the instruction we are disassembling is
         * defined with +rb/+rw/+rd/+i, but the current prospective
         * instruction is not defined this way, so it is a bad match.
         */
        continue;
      }
    }

    /*
     * We have matched the first byte of 'data' to an opcode so
     * set bytesMatched to 1
     */
    bytesMatched = 1;

    /*
     * If there are more bytes to the opcode, we must check them
     * against 'data'.
     */

    while (*++codeptr)
    {
      if (*codeptr == *(data + bytesMatched))
      {
        /*
         * We just matched another byte of the opcode
         */
        ++bytesMatched;

        /*
         * Check if this is the last opcode byte. If so, check
         * if this opcode has a +rb/+rw/+rd/+i flag. These flags
         * indicate that a value between 0-7 is added to the
         * last byte of the opcode. Since this is the last byte,
         * the value 0 must have been added.
         */
        if (*(codeptr + 1) == '\0')
        {
          if ((*OpPtr)->digit == REGCODE)
            regcode = 0;
          else if ((*OpPtr)->digit == FPUCODE)
            fpucode = 0;

          exactMatch = 1;
        }
      } /* if (*codeptr == *(data + bytesMatched)) */
      else if (*(codeptr + 1) == '\0')
      {
        /*
         * We failed to match a byte against 'data' however this
         * is the very last byte of the opcode, so it may have
         * been modified by adding an integer between 0-7 in the
         * case of +rb/+rw/+rd/+i opcodes - check if this is the
         * case.
         */

        if ((*OpPtr)->digit == REGCODE)
        {
          /*
           * If the 'digit' field of OpPtr is REGCODE *and* this
           * is the last byte of the opcode, it is possible that
           * the byte stored in 'data' is up to 7 numbers larger
           * than the opcode stored in OpPtr. This means that
           * the difference between the 'data' byte and the 'OpPtr'
           * byte is a special value corresponding to a specific
           * register. These registers are listed in Table 3.1 of
           * the Intel Instruction Set Reference. If we indeed find
           * the difference to be a number between 0 and 7, store
           * it into 'tmpreg' for future reference.
           */
          regcode = (unsigned char) *(data + bytesMatched) -
                    (unsigned char) *codeptr;

          if ((regcode >= 0) && (regcode <= 7))
          {
            /*
             * We have just found a good match on the last byte
             * of the opcode - therefore the data string matches
             * the stored opcode byte for byte - it is an exact
             * match
             */
            ++bytesMatched;
            exactMatch = 1;
          }
          else
          {
            /*
             * regcode is larger than 8, so this opcode does not
             * satisfy the +rb/+rw/+rd nomenclature - reset
             * regcode and BytesMatched.
             */
            regcode = (-1);
            bytesMatched = 0;

            break;
          }
        } /* if ((*OpPtr)->digit == REGCODE) */
        else if ((*OpPtr)->digit == FPUCODE)
        {
          /*
           * Since this is the last byte of the opcode, and since
           * 'digit' is FPUCODE, this last byte of the opcode may
           * have been altered by adding a number from 0-7, in
           * order to reflect an fpu stack register. Figure out
           * what the difference is, and assign it to tmpfpu for
           * later use.
           */
          fpucode = (unsigned char) *(data + bytesMatched) -
                    (unsigned char) *codeptr;

          if ((fpucode >= 0) && (fpucode <= 7))
          {
            ++bytesMatched;
            exactMatch = 1;
          }
          else
          {
            /*
             * fpucode is larger than 8, and so it cannot represent
             * a fpu stack register - reset fpucode and bytesMatched.
             */
            fpucode = (-1);
            bytesMatched = 0;

            break;
          }
        } /* if ((*OpPtr)->digit == FPUCODE) */
      } /* if (*(codeptr + 1) == '\0') */
      else
      {
        /*
         * We failed to match an opcode byte against 'data' and it
         * is not the last byte of the opcode, so this is not a
         * good match
         */
        bytesMatched = 0;
        break;
      }
    } /* while (*++codeptr) */

    if (bytesMatched < (*OpPtr)->oplen)
    {
      /*
       * We did not match all of the necessary bytes - bad match
       */
      continue;
    }

    /*
     * If the opcode is expecting a register code
     * and we do not have one, it is a bad match. The only
     * case I can think of in which this will happen is with
     * NOP and XCHG and we get a "66 90" to indicate
     * a 32 bit version of NOP. Since there is technically no
     * 32 bit version of NOP, we would normally move onto
     * XCHG (where there is a 32 bit version) and use it, but
     * we do not want to do that since 0x90 is specifically
     * NOP.
     */
    if ((regcode == (-1)) && ((*OpPtr)->digit == REGCODE))
      continue;

    if ((fpucode == (-1)) && ((*OpPtr)->digit == FPUCODE))
      continue;

    /*
     * If the current prospective match expects a ModR/M (and SIB)
     * byte, make sure that the corresponding byte(s) in our actual
     * data string matches up with the correct columns in
     * the ModR/M (and SIB) tables given in tables 2-1, 2-2, and 2-3
     * of the Intel Architecture Software Developers Manual, Vol 2.
     */
    if ((((*OpPtr)->digit >= 0) && ((*OpPtr)->digit <= 7)) ||
        ((*OpPtr)->digit == REGRM))
    {
      int ret;

      ret = x86processModSib(ws,
                             data + bytesMatched,
                             *OpPtr,
                             &msinfo);

      if (ret < 0)
        continue;  /* bad match */

      assert(msinfo.modptr != 0);

      bytesMatched += ret;
    }

    /*
     * Our opcode passed all of the tests, add it to our array
     * of possible matches - there may be more than one instruction
     * which matches the opcode, so we will store all matches and
     * sort it out later. One example is NOP and XCHG ax,ax both
     * of which have an opcode of 0x90. They both do the same thing,
     * but from our viewpoint, we would rather pick NOP as the final
     * instruction instead of XCHG ax,ax.
     */

    matches[midx].bytesMatched = bytesMatched;
    matches[midx].opPtr = *OpPtr;
    matches[midx].regcode = regcode;
    matches[midx].fpucode = fpucode;
    matches[midx].prefixPriority = 0;
    matches[midx].msinfo = msinfo;
    ++midx;

    if (midx >= MAXBUF)
    {
      sprintf(outbuf,
              "x86findOpCode: error: too many matches (>= %d)",
              MAXBUF);
      return (0);
    }
  } /* for (OpPtr = candidates; *OpPtr; ++OpPtr) */

#if 0
  printf("x86findOpCode: number of matches: %d\n", midx);
#endif

  /*
   * We now have a prospective list of matches, contained in the
   * array 'matches'. Each of these matches shares their opcode
   * with the opcode we are trying to disassemble, and also passed
   * a few sanity tests. There are two tests left to perform:
   *
   * 1. Prefix overrides: if there is an operand override then we
   *    may have stored both the 16 and 32 bit versions of the
   *    same instruction in our array 'matches'. In this case
   *    we need to pick out the right one depending upon what
   *    mode we are in (16 or 32 bit mode). This test could be
   *    done in the main loop above, but it would be extremely
   *    messy since we may hit the 16 bit version before the 32
   *    bit version and there would be some ugliness to figure out
   *    to throw one of them away. In the interests of elegance,
   *    I put this test after the main loop.
   * 2. If we are in 16 bit mode, and our potential match is marked
   *    as expecting 32 bits with no operands (example: INSD, IRETD).
   *    In this case, reject the potential match.
   */
  foundBestMatch = 0;
  for (ii = 0; ii < midx; ++ii)
  {
    pret = x86testPrefix(ws, matches[ii].opPtr);

    if (pret == 0)
      continue;

    if (foundBestMatch)
    {
      /*
       * If we have already found a match, we need
       * to check if this match is better than
       * the previous match.
       */

      betterMatch = 0;

      /*
       * Check if the prefix is a better match for this
       * instruction
       */
      if (pret > bestmatch->prefixPriority)
        betterMatch = 1;

      /*
       * This test is for the case of FADD. If we have two
       * matches, where one uses a ModR/M byte and the other
       * is defined with +rb/+rw/+rd/+i, then the latter is
       * chosen over the former. With FADD, there are two
       * separate opcodes (D8 /0 and D8 C0 +i). C0 is in column
       * 0, so it is possible to match D8 C0 against the wrong
       * opcode with the ModR/M.
       */
      if (x86UsesRegFPU(matches[ii].opPtr) &&
          x86UsesModRM(bestmatch->opPtr))
      {
        betterMatch = 1;
      }
      else if (x86UsesRegFPU(bestmatch->opPtr) &&
               x86UsesModRM(matches[ii].opPtr))
      {
        betterMatch = 0;
        continue;
      }
      else if (!x86UsesModRM(matches[ii].opPtr) &&
               x86UsesModRM(bestmatch->opPtr))
      {
        /*
         * If the previous match uses a ModR/M byte and the
         * current match does not, then the current match is
         * a better match. An example of this is FTST and
         * FLDENV. FTST is D9 E4, and FLDENV is D9 /4. E4 is
         * in column 4, so we must make sure we choose FTST
         * over FLDENV.
         */
        betterMatch = 1;
      }

      if (betterMatch)
      {
        matches[ii].prefixPriority = pret;
        *bestmatch = matches[ii];
      }
    } /* if (foundBestMatch) */
    else
    {
      /*
       * We have not yet found a match, and this one passed
       * the prefix requirements so record it.
       */

      matches[ii].prefixPriority = pret;
      *bestmatch = matches[ii];
      foundBestMatch = 1;
    }
  }

  if (foundBestMatch)
    return (bestmatch->bytesMatched + (long) prefBytes);
  else
    return (0);
} /* x86findOpCode() */
