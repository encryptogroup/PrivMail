add_executable(privmail privmail_main.cpp common/privmail.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(privmail
        MOTION::motion
        Boost::program_options
        yaml-cpp
        )
