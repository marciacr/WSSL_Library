# README #

This repository summarize the content and has all the codes related to the Wireless Safety Layer from ADACORSA project.

### What is this repository for? ###

* Quick summary of what is being developed
* Codes for WSSL safety and security
* Quick tutorial to install and run WSSL
* [CISTER ADACORSA](http://cister-labs.pt/projects/adacorsa/)

## How to create libraries on Linux using C++ ##

Libraries make code shareable in a practical but private way. Anyone that you give the library file and header file to can use your library, but your actual source code remains private.

### Dynamic Library ###

-> Dynamic library files are also called Shared Object files. Linking your program with Dynamic library files makes all objects referenced by your program be verified but not copied into the final executable file. Thus, the executable file will be much smaller than Static libraries but the execution will be harder, since dynamic library files needs to be loaded into CPU together with your executable file.

* **Linux** has extension ".so";

### Static Library ###

-> Static library files are also called Archive files. Linking your program with static library files makes all objects referenced by your program be verified and copied into the final executable file. Thus the executable file will be much bigger than when using Dynamic Libraries but the execution will be easier, since static library files are no longer needed at the execution time.

* **Linux** has extension ".a";
* **Windows** has extension ".lib";
* To create a Static Library use command: 
* **ar rcs name_lib.a exe1.o exe2.o**
* This command create the lib if it doesn't exists, and replace if it already exists.
* Where 'name_lib' is the name of the static library;
* 'Exe1' and 'Exe2' are the executables ".o" (you can add as many as you want).


### Terminal commands ###

* **Complete commands to produce the static library** :
    g++ -c safety_entity_send.cpp -o safety_entity_send.o 
    g++ -c safety_entity_rcv.cpp -o safety_entity_rcv.o 
    ar rcs lib_wssl.a safety_entity_send.o safety_entity_rcv.o
    g++ -c caller.cpp -o caller.o
    g++ -o caller caller.o -L. -l_wssl
    ./caller

    * **"-llibrary"**:
        * Search the library named library when linking. The -l option is passed directly to the linker by GCC. **The general description below applies to the GNU linker**.
        * The linker searches a standard list of directories for the library. The directories searched include several standard system directories plus any that you specify with **-L**.
        * Static libraries are archives of object files, and have file names like liblibrary.a. Some targets also support shared libraries, which typically have names like liblibrary.so. If both static and shared libraries are found, the linker gives preference to linking with the shared library unless the -static option is used.
        * It makes a difference where in the command you write this option; the linker searches and processes libraries and object files in the order they are specified. Thus, ‘foo.o -lz bar.o’ searches library ‘z’ after file foo.o but before bar.o. If bar.o refers to functions in ‘z’, those functions may not be loaded.

    * **"-c" flag**:
        * Compile or assemble the source files, but do not link. The linking stage simply is not done. The ultimate output is in the form of an object file for each source file.
        * By default, the object file name for a source file is made by replacing the suffix ‘.c’, ‘.i’, ‘.s’, etc., with ‘.o’.
        * Unrecognized input files, not requiring compilation or assembly, are ignored.

    * **"-o" flag**: 
        * Place the primary output in file file. This applies to whatever sort of output is being produced, whether it be an executable file, an object file, an assembler file or preprocessed C code.
        * To produce an object file, use: g++ -c main.cpp -o main.o. 
        * If -o is not specified, the default is to put an executable file in a.out, the object file for source.suffix in source.o, its assembler file in source.s, a precompiled header file in source.suffix.gch, and all preprocessed C source on standard output.

    * **"ar" flag**:
        * The archiver, also known simply as ar, is a Unix utility that maintains groups of files as a single archive file. Today, ar is generally used only to create and update static library files that the link editor or linker uses and for generating .deb packages for the Debian family; it can be used to create archives for any purpose, but has been largely replaced by tar for purposes other than static libraries.

        * "rcs" : We are using the -c (create) option to create the library file, the -r (add with replace) option to add the files to the library file, and the -s (index) option to create an index of the files inside the library file. 
            * The -v (verbose) option makes the usually silent ar tell us what it has done. ar prints out confirmation, the “a” means “added.”
            * We can use the -t (rtable) option to see what modules are inside the library file.
            * Use -d (delete) option. Also use the -v (verbose) option, so that ar tells us what it has done and include the -s (index) option to update the index in the library file.

### Makefile ###

 * To compile and generate the library without the Vortex lib, use command: make
 * To clean all the **.o** **.a** and executable, use command: make clean
 
Example: 

By putting the object files *hellomake.o* and *hellofunc.o* in the dependency list and in the rule, make knows it must first compile the .c versions individually, and then build the executable hellomake.

> hellomake: hellomake.o hellofunc.o 
	$(CC) -o hellomake hellomake.o hellofunc.o 

Dependency on the include files. If you were to make a change to hellomake.h, for example, make would not recompile the .c files, even though they needed to be. In order to fix this, we need to tell make that all .c files depend on certain .h files. We can do this by writing a simple rule and adding it to the makefile.

> %.o: %.c $(DEPS)
    $(CC) -c -o $@ $< $(CFLAGS)

This addition first creates the macro DEPS, which is the set of .h files on which the .c files depend. Then we define a rule that applies to all files ending in the .o suffix. The rule says that the .o file depends upon the .c version of the file and the .h files included in the DEPS macro. The rule then says that to generate the .o file, make needs to compile the .c file using the compiler defined in the CC macro. The -c flag says to generate the object file, the -o $@ says to put the output of the compilation in the file named on the left side of the :, the $< is the first item in the dependencies list, and the CFLAGS macro is defined as above.

## How do I get set up? ##

* Environment configured with C++ compilators (g++);
* Install dependencies and third-party libraries;
* Build the library using Make and CMake;

### Make and CMake

To install Make and CMake in Ubuntu OS use the following commands:

> $sudo apt update
> $make -version

If make is not installed in Ubuntu, then install it:
> $sudo apt install make 

If nothing works, try this:
> $sudo apt install build-essential

https://linuxhint.com/install-make-ubuntu/

### VORTEX Library & WSSL

Go to the location of WSSL_Security&Safety and do the following:

**To include:**
 - Requires ```sodium```; can be installed via ```apt install libsodium-dev``` or similar installers, or through local building: https://libsodium.gitbook.io/doc/installation
 - Include on your projects build files CryptoLib and sodium to the CMakeList.txt file:
   - cmake: ```target_link_libraries(<project name> CryptoLib sodium)```

**To build:**
```cmake . && cmake --build .```

## Evaluation Tests

WSSL can be tested in different applications. 

### MQTT LIB Mosquitto.h


https://mosquitto.org/download/
sudo apt-add-repository ppa:mosquitto-dev/mosquitto-ppa
sudo apt-get update
apt-get install libmosquitto-dev


http://www.steves-internet-guide.com/install-mosquitto-linux/
sudo apt-get install mosquitto
sudo apt-get install mosquitto-clients
sudo apt clean

>#include <mosquitto.h>
