# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.23

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/cmake-3.23.2-linux-x86_64/bin/cmake

# The command to remove a file.
RM = /opt/cmake-3.23.2-linux-x86_64/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/marcia/wssl/Cryptopp

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/marcia/wssl/Cryptopp

# Include any dependencies generated for this target.
include CMakeFiles/Crypto_pub.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/Crypto_pub.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/Crypto_pub.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/Crypto_pub.dir/flags.make

CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.o: CMakeFiles/Crypto_pub.dir/flags.make
CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.o: Crypto_pub_mqtt.cpp
CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.o: CMakeFiles/Crypto_pub.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/marcia/wssl/Cryptopp/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.o -MF CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.o.d -o CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.o -c /home/marcia/wssl/Cryptopp/Crypto_pub_mqtt.cpp

CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/marcia/wssl/Cryptopp/Crypto_pub_mqtt.cpp > CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.i

CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/marcia/wssl/Cryptopp/Crypto_pub_mqtt.cpp -o CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.s

# Object files for target Crypto_pub
Crypto_pub_OBJECTS = \
"CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.o"

# External object files for target Crypto_pub
Crypto_pub_EXTERNAL_OBJECTS =

Crypto_pub: CMakeFiles/Crypto_pub.dir/Crypto_pub_mqtt.cpp.o
Crypto_pub: CMakeFiles/Crypto_pub.dir/build.make
Crypto_pub: libCryptoLib.a
Crypto_pub: libCryptoLib.a
Crypto_pub: CMakeFiles/Crypto_pub.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/marcia/wssl/Cryptopp/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable Crypto_pub"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/Crypto_pub.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/Crypto_pub.dir/build: Crypto_pub
.PHONY : CMakeFiles/Crypto_pub.dir/build

CMakeFiles/Crypto_pub.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/Crypto_pub.dir/cmake_clean.cmake
.PHONY : CMakeFiles/Crypto_pub.dir/clean

CMakeFiles/Crypto_pub.dir/depend:
	cd /home/marcia/wssl/Cryptopp && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/marcia/wssl/Cryptopp /home/marcia/wssl/Cryptopp /home/marcia/wssl/Cryptopp /home/marcia/wssl/Cryptopp /home/marcia/wssl/Cryptopp/CMakeFiles/Crypto_pub.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/Crypto_pub.dir/depend
