# Status

The debugger compiles under current XCode.

The interface loads.

The debugger has been successfully compiled under CentOS Linux v.7  x86_64
and loads and successfully disassembles and runs 32 bit binaries.

But MOST of the features do not work yet:

- There's no MACHO support (i.e. no file loading).
- Only partial _ptrace()_ support - read/write/get _RIP_, maybe attach,
this has to be fixed.
- It's 32 bit. It has to be ported to amd64 yet
(i.e. the debugger and the disassembler).
- All the FIXMEs have to be fixed.

# About

Original source as taken from:
http://ald.sourceforge.net.

It's an attempt at a port to OSX.

The Assembly Language Debugger is a tool for debugging executable programs at the assembly level. It currently runs only on Intel x86 platforms. 
Operating systems supported: Linux, FreeBSD, NetBSD, OpenBSD.

Most recent version: 0.1.7 (10 October 2004)
 

# Features

    - Step into / Step over 
    - Breakpoints 
    - Powerful ELF format interpreter 
    - Easy memory manipulation 
    - Disassembler for intel x86 instructions 
    - Easy register manipulation 
