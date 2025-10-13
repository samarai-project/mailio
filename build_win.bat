@echo off
cls
rd /s /q build
mkdir build
rem cmake -G "Visual Studio 17 2022" -A x64 -B "build" -DMAILIO_BUILD_DOCUMENTATION=OFF -DMAILIO_BUILD_EXAMPLES=OFF -DMAILIO_BUILD_TESTS=OFF

cmake -S . -B build -G "Visual Studio 17 2022" -A x64 ^
    -DVCPKG_TARGET_TRIPLET=x64-windows-static-md ^
    -DBUILD_SHARED_LIBS=OFF ^
    -DOPENSSL_USE_STATIC_LIBS=ON ^
    -DMAILIO_BUILD_DOCUMENTATION=OFF ^
    -DMAILIO_BUILD_EXAMPLES=OFF  ^
    -DMAILIO_BUILD_TESTS=OFF ^
    -DMAILIO_TEST_HOOKS=ON
    
cmake --build build --config Release