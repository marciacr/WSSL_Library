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
CMAKE_SOURCE_DIR = "/home/marcia/wssl/WSSL_Security&Safety"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "/home/marcia/wssl/WSSL_Security&Safety"

# Include any dependencies generated for this target.
include CMakeFiles/WSSL_Test.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/WSSL_Test.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/WSSL_Test.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/WSSL_Test.dir/flags.make

CMakeFiles/WSSL_Test.dir/caller.cpp.o: CMakeFiles/WSSL_Test.dir/flags.make
CMakeFiles/WSSL_Test.dir/caller.cpp.o: caller.cpp
CMakeFiles/WSSL_Test.dir/caller.cpp.o: CMakeFiles/WSSL_Test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="/home/marcia/wssl/WSSL_Security&Safety/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/WSSL_Test.dir/caller.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/WSSL_Test.dir/caller.cpp.o -MF CMakeFiles/WSSL_Test.dir/caller.cpp.o.d -o CMakeFiles/WSSL_Test.dir/caller.cpp.o -c "/home/marcia/wssl/WSSL_Security&Safety/caller.cpp"

CMakeFiles/WSSL_Test.dir/caller.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/WSSL_Test.dir/caller.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/home/marcia/wssl/WSSL_Security&Safety/caller.cpp" > CMakeFiles/WSSL_Test.dir/caller.cpp.i

CMakeFiles/WSSL_Test.dir/caller.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/WSSL_Test.dir/caller.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/home/marcia/wssl/WSSL_Security&Safety/caller.cpp" -o CMakeFiles/WSSL_Test.dir/caller.cpp.s

# Object files for target WSSL_Test
WSSL_Test_OBJECTS = \
"CMakeFiles/WSSL_Test.dir/caller.cpp.o"

# External object files for target WSSL_Test
WSSL_Test_EXTERNAL_OBJECTS =

WSSL_Test: CMakeFiles/WSSL_Test.dir/caller.cpp.o
WSSL_Test: CMakeFiles/WSSL_Test.dir/build.make
WSSL_Test: libwssl.a
WSSL_Test: libCryptoLib.a
WSSL_Test: CMakeFiles/WSSL_Test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir="/home/marcia/wssl/WSSL_Security&Safety/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable WSSL_Test"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/WSSL_Test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/WSSL_Test.dir/build: WSSL_Test
.PHONY : CMakeFiles/WSSL_Test.dir/build

CMakeFiles/WSSL_Test.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/WSSL_Test.dir/cmake_clean.cmake
.PHONY : CMakeFiles/WSSL_Test.dir/clean

CMakeFiles/WSSL_Test.dir/depend:
	cd "/home/marcia/wssl/WSSL_Security&Safety" && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" "/home/marcia/wssl/WSSL_Security&Safety" "/home/marcia/wssl/WSSL_Security&Safety" "/home/marcia/wssl/WSSL_Security&Safety" "/home/marcia/wssl/WSSL_Security&Safety" "/home/marcia/wssl/WSSL_Security&Safety/CMakeFiles/WSSL_Test.dir/DependInfo.cmake" --color=$(COLOR)
.PHONY : CMakeFiles/WSSL_Test.dir/depend
