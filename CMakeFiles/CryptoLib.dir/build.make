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
CMAKE_SOURCE_DIR = /home/marcia/Desktop/Mestrado_ISEP/Repositories/wssl_library

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/marcia/Desktop/Mestrado_ISEP/Repositories/wssl_library

# Include any dependencies generated for this target.
include CMakeFiles/CryptoLib.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/CryptoLib.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/CryptoLib.dir/flags.make

CMakeFiles/CryptoLib.dir/src/CryptoIdentity.cpp.o: CMakeFiles/CryptoLib.dir/flags.make
CMakeFiles/CryptoLib.dir/src/CryptoIdentity.cpp.o: src/CryptoIdentity.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/marcia/Desktop/Mestrado_ISEP/Repositories/wssl_library/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/CryptoLib.dir/src/CryptoIdentity.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/CryptoLib.dir/src/CryptoIdentity.cpp.o -c /home/marcia/Desktop/Mestrado_ISEP/Repositories/wssl_library/src/CryptoIdentity.cpp

CMakeFiles/CryptoLib.dir/src/CryptoIdentity.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/CryptoLib.dir/src/CryptoIdentity.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/marcia/Desktop/Mestrado_ISEP/Repositories/wssl_library/src/CryptoIdentity.cpp > CMakeFiles/CryptoLib.dir/src/CryptoIdentity.cpp.i

CMakeFiles/CryptoLib.dir/src/CryptoIdentity.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/CryptoLib.dir/src/CryptoIdentity.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/marcia/Desktop/Mestrado_ISEP/Repositories/wssl_library/src/CryptoIdentity.cpp -o CMakeFiles/CryptoLib.dir/src/CryptoIdentity.cpp.s

# Object files for target CryptoLib
CryptoLib_OBJECTS = \
"CMakeFiles/CryptoLib.dir/src/CryptoIdentity.cpp.o"

# External object files for target CryptoLib
CryptoLib_EXTERNAL_OBJECTS =

libCryptoLib.a: CMakeFiles/CryptoLib.dir/src/CryptoIdentity.cpp.o
libCryptoLib.a: CMakeFiles/CryptoLib.dir/build.make
libCryptoLib.a: CMakeFiles/CryptoLib.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/marcia/Desktop/Mestrado_ISEP/Repositories/wssl_library/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libCryptoLib.a"
	$(CMAKE_COMMAND) -P CMakeFiles/CryptoLib.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/CryptoLib.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/CryptoLib.dir/build: libCryptoLib.a

.PHONY : CMakeFiles/CryptoLib.dir/build

CMakeFiles/CryptoLib.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/CryptoLib.dir/cmake_clean.cmake
.PHONY : CMakeFiles/CryptoLib.dir/clean

CMakeFiles/CryptoLib.dir/depend:
	cd /home/marcia/Desktop/Mestrado_ISEP/Repositories/wssl_library && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/marcia/Desktop/Mestrado_ISEP/Repositories/wssl_library /home/marcia/Desktop/Mestrado_ISEP/Repositories/wssl_library /home/marcia/Desktop/Mestrado_ISEP/Repositories/wssl_library /home/marcia/Desktop/Mestrado_ISEP/Repositories/wssl_library /home/marcia/Desktop/Mestrado_ISEP/Repositories/wssl_library/CMakeFiles/CryptoLib.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/CryptoLib.dir/depend
