# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.15

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
CMAKE_COMMAND = /home/tomy/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/192.6817.18/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/tomy/.local/share/JetBrains/Toolbox/apps/CLion/ch-0/192.6817.18/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/tomy/CLionProjects/SITema1

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/tomy/CLionProjects/SITema1/cmake-build-debug

# Include any dependencies generated for this target.
include Exercitiu2/CMakeFiles/exercitiul2.dir/depend.make

# Include the progress variables for this target.
include Exercitiu2/CMakeFiles/exercitiul2.dir/progress.make

# Include the compile flags for this target's objects.
include Exercitiu2/CMakeFiles/exercitiul2.dir/flags.make

Exercitiu2/CMakeFiles/exercitiul2.dir/exercitiul2.cpp.o: Exercitiu2/CMakeFiles/exercitiul2.dir/flags.make
Exercitiu2/CMakeFiles/exercitiul2.dir/exercitiul2.cpp.o: ../Exercitiu2/exercitiul2.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/tomy/CLionProjects/SITema1/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object Exercitiu2/CMakeFiles/exercitiul2.dir/exercitiul2.cpp.o"
	cd /home/tomy/CLionProjects/SITema1/cmake-build-debug/Exercitiu2 && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/exercitiul2.dir/exercitiul2.cpp.o -c /home/tomy/CLionProjects/SITema1/Exercitiu2/exercitiul2.cpp

Exercitiu2/CMakeFiles/exercitiul2.dir/exercitiul2.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/exercitiul2.dir/exercitiul2.cpp.i"
	cd /home/tomy/CLionProjects/SITema1/cmake-build-debug/Exercitiu2 && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/tomy/CLionProjects/SITema1/Exercitiu2/exercitiul2.cpp > CMakeFiles/exercitiul2.dir/exercitiul2.cpp.i

Exercitiu2/CMakeFiles/exercitiul2.dir/exercitiul2.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/exercitiul2.dir/exercitiul2.cpp.s"
	cd /home/tomy/CLionProjects/SITema1/cmake-build-debug/Exercitiu2 && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/tomy/CLionProjects/SITema1/Exercitiu2/exercitiul2.cpp -o CMakeFiles/exercitiul2.dir/exercitiul2.cpp.s

# Object files for target exercitiul2
exercitiul2_OBJECTS = \
"CMakeFiles/exercitiul2.dir/exercitiul2.cpp.o"

# External object files for target exercitiul2
exercitiul2_EXTERNAL_OBJECTS =

Exercitiu2/exercitiul2: Exercitiu2/CMakeFiles/exercitiul2.dir/exercitiul2.cpp.o
Exercitiu2/exercitiul2: Exercitiu2/CMakeFiles/exercitiul2.dir/build.make
Exercitiu2/exercitiul2: /usr/lib/x86_64-linux-gnu/libssl.so
Exercitiu2/exercitiul2: /usr/lib/x86_64-linux-gnu/libcrypto.so
Exercitiu2/exercitiul2: Exercitiu2/CMakeFiles/exercitiul2.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/tomy/CLionProjects/SITema1/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable exercitiul2"
	cd /home/tomy/CLionProjects/SITema1/cmake-build-debug/Exercitiu2 && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/exercitiul2.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
Exercitiu2/CMakeFiles/exercitiul2.dir/build: Exercitiu2/exercitiul2

.PHONY : Exercitiu2/CMakeFiles/exercitiul2.dir/build

Exercitiu2/CMakeFiles/exercitiul2.dir/clean:
	cd /home/tomy/CLionProjects/SITema1/cmake-build-debug/Exercitiu2 && $(CMAKE_COMMAND) -P CMakeFiles/exercitiul2.dir/cmake_clean.cmake
.PHONY : Exercitiu2/CMakeFiles/exercitiul2.dir/clean

Exercitiu2/CMakeFiles/exercitiul2.dir/depend:
	cd /home/tomy/CLionProjects/SITema1/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/tomy/CLionProjects/SITema1 /home/tomy/CLionProjects/SITema1/Exercitiu2 /home/tomy/CLionProjects/SITema1/cmake-build-debug /home/tomy/CLionProjects/SITema1/cmake-build-debug/Exercitiu2 /home/tomy/CLionProjects/SITema1/cmake-build-debug/Exercitiu2/CMakeFiles/exercitiul2.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : Exercitiu2/CMakeFiles/exercitiul2.dir/depend

