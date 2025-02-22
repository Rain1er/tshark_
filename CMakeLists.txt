cmake_minimum_required(VERSION 3.27)
project(tshark_)

set(CMAKE_CXX_STANDARD 17)

add_executable(main_app main.cpp)
add_executable(frame_app frame.cpp)