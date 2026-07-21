# pdb.cpp #includes most TUs; merge.cpp is standalone; old.cpp is Windows-only.
set(_pdb_sources pdb.cpp merge.cpp pdb.hpp)
if(WIN32)
    list(APPEND _pdb_sources old.cpp)
endif()
ida_add_plugin(pdb SOURCES ${_pdb_sources})

set_source_files_properties(
    common.cpp
    misc.cpp
    msdia.cpp
    pdb_pdbida.cpp
    pdblocal.cpp
    pdbremote.cpp
    sip.cpp
    tilbuild.cpp
    PROPERTIES HEADER_FILE_ONLY TRUE
)

# Link DIA SDK (set by parent CMakeLists.txt)
target_include_directories(pdb PRIVATE ${DIA_SDK_INCLUDE_DIR})
target_link_libraries(pdb PRIVATE ${DIA_SDK_LIBRARY})

# Windows system libraries needed for DIA SDK
if(WIN32)
    target_link_libraries(pdb PRIVATE wininet ole32 oleaut32)
endif()

copy_cfg(pdb ${CMAKE_CURRENT_SOURCE_DIR}/pdb.cfg)
