cmake_minimum_required(VERSION 3.21)
project(pra1xarxes C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(pra1xarxes
        client.c)
