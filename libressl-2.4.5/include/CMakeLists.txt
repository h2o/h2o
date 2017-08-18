install(DIRECTORY .
        DESTINATION include
        PATTERN "CMakeLists.txt" EXCLUDE
        PATTERN "compat" EXCLUDE
        PATTERN "Makefile*" EXCLUDE)
