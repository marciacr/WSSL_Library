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
CMAKE_BINARY_DIR = /home/marcia/Desktop/WSSL_Library

# Include any dependencies generated for this target.
include CMakeFiles/CertificationAuthority.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/CertificationAuthority.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/CertificationAuthority.dir/flags.make

CMakeFiles/CertificationAuthority.dir/CertificationAuthority.cpp.o: CMakeFiles/CertificationAuthority.dir/flags.make
CMakeFiles/CertificationAuthority.dir/CertificationAuthority.cpp.o: CertificationAuthority.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/marcia/Desktop/WSSL_Library/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/CertificationAuthority.dir/CertificationAuthority.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/CertificationAuthority.dir/CertificationAuthority.cpp.o -c /home/marcia/Desktop/WSSL_Library/CertificationAuthority.cpp

CMakeFiles/CertificationAuthority.dir/CertificationAuthority.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/CertificationAuthority.dir/CertificationAuthority.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/marcia/Desktop/WSSL_Library/CertificationAuthority.cpp > CMakeFiles/CertificationAuthority.dir/CertificationAuthority.cpp.i

CMakeFiles/CertificationAuthority.dir/CertificationAuthority.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/CertificationAuthority.dir/CertificationAuthority.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/marcia/Desktop/WSSL_Library/CertificationAuthority.cpp -o CMakeFiles/CertificationAuthority.dir/CertificationAuthority.cpp.s

# Object files for target CertificationAuthority
CertificationAuthority_OBJECTS = \
"CMakeFiles/CertificationAuthority.dir/CertificationAuthority.cpp.o"

# External object files for target CertificationAuthority
CertificationAuthority_EXTERNAL_OBJECTS =

CertificationAuthority: CMakeFiles/CertificationAuthority.dir/CertificationAuthority.cpp.o
CertificationAuthority: CMakeFiles/CertificationAuthority.dir/build.make
CertificationAuthority: libCryptoLib.a
CertificationAuthority: CMakeFiles/CertificationAuthority.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/marcia/Desktop/WSSL_Library/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable CertificationAuthority"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/CertificationAuthority.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/CertificationAuthority.dir/build: CertificationAuthority

.PHONY : CMakeFiles/CertificationAuthority.dir/build

CMakeFiles/CertificationAuthority.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/CertificationAuthority.dir/cmake_clean.cmake
.PHONY : CMakeFiles/CertificationAuthority.dir/clean

CMakeFiles/CertificationAuthority.dir/depend:
	cd /home/marcia/Desktop/WSSL_Library && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/marcia/Desktop/WSSL_Library /home/marcia/Desktop/WSSL_Library /home/marcia/Desktop/WSSL_Library /home/marcia/Desktop/WSSL_Library /home/marcia/Desktop/WSSL_Library/CMakeFiles/CertificationAuthority.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/CertificationAuthority.dir/depend

