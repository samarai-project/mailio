cls
rd /s /q build
mkdir build
cmake -G "Visual Studio 17 2022" -A x64 -B "build" -DMAILIO_BUILD_DOCUMENTATION=OFF -DMAILIO_BUILD_EXAMPLES=OFF -DMAILIO_BUILD_TESTS=OFF
cmake --build build --config Release -- /m