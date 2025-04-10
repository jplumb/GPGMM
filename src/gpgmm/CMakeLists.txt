# Copyright 2020 The Dawn Authors
# Copyright 2022 The GPGMM Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

add_library(gpgmm)

target_compile_definitions(gpgmm PRIVATE "GPGMM_IMPLEMENTATION")
if (BUILD_SHARED_LIBS)
    target_compile_definitions(gpgmm PRIVATE "GPGMM_SHARED_LIBRARY")
endif()

target_link_libraries(gpgmm
    PUBLIC gpgmm_utils
           gpgmm_common
           gpgmm_common_config
)

# Only win32 app needs to link with user32.lib
# In UWP, all availiable APIs are defined in WindowsApp.lib
# and is automatically linked when WINDOWS_STORE set
if (WIN32 AND NOT WINDOWS_STORE)
    target_link_libraries(gpgmm PRIVATE user32.lib)
endif()

# DXGIGetDebugInterface1 is defined in dxgi.lib
# But this API is tagged as a development-only capability
# which implies that linking to this function will cause
# the application to fail Windows store certification
# So we only link to it in debug build when compiling for UWP.
# In win32 we load dxgi.dll using LoadLibrary
# so no need for static linking.
if (WINDOWS_STORE)
    target_link_libraries(gpgmm PRIVATE debug dxgi.lib)
endif()

if (MSVC)
  target_compile_options(gpgmm PRIVATE
    /wd4702
    /wd4245
    /wd4275
    /wd4251
  )
endif()

if (GPGMM_ENABLE_D3D12)
    target_sources(gpgmm PRIVATE
        "d3d12/BudgetUpdateDXGI.cpp"
        "d3d12/BudgetUpdateDXGI.h"
        "d3d12/BudgetUpdateD3D12.cpp"
        "d3d12/BudgetUpdateD3D12.h"
        "d3d12/BufferAllocatorD3D12.cpp"
        "d3d12/BufferAllocatorD3D12.h"
        "d3d12/DebugObjectD3D12.cpp"
        "d3d12/DebugObjectD3D12.h"
        "d3d12/ResourceAllocationTrackingAllocatorD3D12.cpp"
        "d3d12/ResourceAllocationTrackingAllocatorD3D12.h"
        "d3d12/CapsD3D12.cpp"
        "d3d12/CapsD3D12.h"
        "d3d12/ErrorD3D12.cpp"
        "d3d12/ErrorD3D12.h"
        "d3d12/EventMessageD3D12.h"
        "d3d12/FenceD3D12.cpp"
        "d3d12/FenceD3D12.h"
        "d3d12/ResidencyHeapD3D12.cpp"
        "d3d12/ResidencyHeapD3D12.h"
        "d3d12/JSONSerializerD3D12.cpp"
        "d3d12/JSONSerializerD3D12.h"
        "d3d12/LogD3D12.h"
        "d3d12/ResidencyListD3D12.cpp"
        "d3d12/ResidencyListD3D12.h"
        "d3d12/ResidencyManagerD3D12.cpp"
        "d3d12/ResidencyManagerD3D12.h"
        "d3d12/ResidencyManagerDXGI.cpp"
        "d3d12/ResidencyManagerDXGI.h"
        "d3d12/ResourceAllocationD3D12.cpp"
        "d3d12/ResourceAllocationD3D12.h"
        "d3d12/ResourceAllocatorD3D12.cpp"
        "d3d12/ResourceAllocatorD3D12.h"
        "d3d12/ResourceHeapAllocatorD3D12.cpp"
        "d3d12/ResourceHeapAllocatorD3D12.h"
        "d3d12/UnknownD3D12.cpp"
        "d3d12/UnknownD3D12.h"
        "d3d12/UtilsD3D12.cpp"
        "d3d12/UtilsD3D12.h"
        "d3d12/D3D12Platform.h"
    )
    target_link_libraries(gpgmm PRIVATE dxguid.lib)
endif()

if (GPGMM_ENABLE_VK)

  if (GPGMM_ENABLE_VK_STATIC_FUNCTIONS)
    target_compile_definitions(gpgmm PRIVATE "GPGMM_STATIC_VULKAN_FUNCTIONS")
  endif()

  target_sources(gpgmm PRIVATE
        "vk/CapsVk.cpp"
        "vk/CapsVk.h"
        "vk/DeviceMemoryAllocatorVk.cpp"
        "vk/DeviceMemoryAllocatorVk.h"
        "vk/DeviceMemoryVk.cpp"
        "vk/DeviceMemoryVk.h"
        "vk/ErrorVk.h"
        "vk/ResourceAllocatorVk.cpp"
        "vk/ResourceAllocatorVk.h"
        "vk/FunctionsVk.cpp"
        "vk/FunctionsVk.h"
        "vk/VKPlatform.h"
    )

    # Only link to Vulkan if static linking is used
    if (GPGMM_ENABLE_VK_STATIC_FUNCTIONS)
      if (GPGMM_ENABLE_VK_USE_SDK)
        target_link_libraries(gpgmm PRIVATE
          ${GPGMM_VK_LIBRARIES_DIR}
        )
      else()
        target_link_libraries(gpgmm PRIVATE
          Vulkan::Vulkan
        )
      endif()
    endif()

    if (GPGMM_ENABLE_VK_USE_SDK)
      target_include_directories(gpgmm PUBLIC ${GPGMM_VK_INCLUDE_DIR})
    else()
      target_link_libraries(gpgmm PUBLIC Vulkan-Headers)
    endif()

endif()

if (GPGMM_INSTRUMENT)
    target_compile_definitions(gpgmm PRIVATE -DINLINE_INSTR=1)
    target_include_directories(gpgmm PUBLIC 
        $<BUILD_INTERFACE:${GPGMM_INCLUDE_DIRS}>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>/build/
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>/src/common/concurrent/include/
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>/src/common/utility/include/
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>/src/common/instrumentation/include/
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>/src/layers/memory/
    )
else()
    target_include_directories(gpgmm PUBLIC 
        $<BUILD_INTERFACE:${GPGMM_INCLUDE_DIRS}>
    )
endif()

################################################################################
# Build subdirectories
################################################################################
add_subdirectory(utils)
add_subdirectory(common)
