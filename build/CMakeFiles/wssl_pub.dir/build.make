# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/marcia/Desktop/WSSL_Library

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/marcia/Desktop/WSSL_Library/build

# Include any dependencies generated for this target.
include CMakeFiles/wssl_pub.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/wssl_pub.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/wssl_pub.dir/flags.make

CMakeFiles/wssl_pub.dir/publisher.cpp.o: CMakeFiles/wssl_pub.dir/flags.make
CMakeFiles/wssl_pub.dir/publisher.cpp.o: ../publisher.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/marcia/Desktop/WSSL_Library/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/wssl_pub.dir/publisher.cpp.o"
	/usr/bin/g++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/wssl_pub.dir/publisher.cpp.o -c /home/marcia/Desktop/WSSL_Library/publisher.cpp

CMakeFiles/wssl_pub.dir/publisher.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/wssl_pub.dir/publisher.cpp.i"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/marcia/Desktop/WSSL_Library/publisher.cpp > CMakeFiles/wssl_pub.dir/publisher.cpp.i

CMakeFiles/wssl_pub.dir/publisher.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/wssl_pub.dir/publisher.cpp.s"
	/usr/bin/g++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/marcia/Desktop/WSSL_Library/publisher.cpp -o CMakeFiles/wssl_pub.dir/publisher.cpp.s

# Object files for target wssl_pub
wssl_pub_OBJECTS = \
"CMakeFiles/wssl_pub.dir/publisher.cpp.o"

# External object files for target wssl_pub
wssl_pub_EXTERNAL_OBJECTS =

wssl_pub: CMakeFiles/wssl_pub.dir/publisher.cpp.o
wssl_pub: CMakeFiles/wssl_pub.dir/build.make
wssl_pub: libwssl.a
wssl_pub: libCryptoLib.a
wssl_pub: CMakeFiles/wssl_pub.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/marcia/Desktop/WSSL_Library/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable wssl_pub"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/wssl_pub.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/wssl_pub.dir/build: wssl_pub

.PHONY : CMakeFiles/wssl_pub.dir/build

CMakeFiles/wssl_pub.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/wssl_pub.dir/cmake_clean.cmake
.PHONY : CMakeFiles/wssl_pub.dir/clean

CMakeFiles/wssl_pub.dir/depend:
	cd /home/marcia/Desktop/WSSL_Library/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/marcia/Desktop/WSSL_Library /home/marcia/Desktop/WSSL_Library /home/marcia/Desktop/WSSL_Library/build /home/marcia/Desktop/WSSL_Library/build /home/marcia/Desktop/WSSL_Library/build/CMakeFiles/wssl_pub.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/wssl_pub.dir/depend

