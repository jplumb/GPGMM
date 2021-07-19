// Copyright 2019 The Dawn Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
#define GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_

#include "src/BuddyMemoryAllocator.h"
#include "src/PooledMemoryAllocator.h"
#include "src/ResourceAllocator.h"
#include "src/d3d12/HeapAllocatorD3D12.h"
#include "src/d3d12/ResourceAllocationD3D12.h"

#include <array>
#include <cstdint>

struct ID3D12Device;
struct IDXGIAdapter3;

namespace gpgmm { namespace d3d12 {

    class ResidencyManager;

    typedef enum ALLOCATOR_FLAGS {
        ALLOCATOR_ALWAYS_COMMITED = 0x1,
    } ALLOCATOR_FLAGS;

    struct ALLOCATOR_DESC {
        ALLOCATOR_FLAGS Flags;
        bool IsUMA;
        uint32_t ResourceHeapTier;
        Microsoft::WRL::ComPtr<ID3D12Device> Device;
        UINT64 PreferredBlockSize;
        Microsoft::WRL::ComPtr<IDXGIAdapter3> Adapter;
    };

    typedef enum ALLOCATION_FLAGS {} ALLOCATION_FLAGS;

    struct ALLOCATION_DESC {
        ALLOCATION_FLAGS Flags;
        D3D12_HEAP_TYPE HeapType;
    };

    // Resource heap types + flags combinations are named after the D3D constants.
    // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ne-d3d12-d3d12_heap_flags
    // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ne-d3d12-d3d12_heap_type
    enum ResourceHeapKind {

        // Resource heap tier 2
        // Allows resource heaps to contain all buffer and textures types.
        // This enables better heap re-use by avoiding the need for separate heaps and
        // also reduces fragmentation.
        Readback_AllBuffersAndTextures,
        Upload_AllBuffersAndTextures,
        Default_AllBuffersAndTextures,

        // Resource heap tier 1
        // Resource heaps only support types from a single resource category.
        Readback_OnlyBuffers,
        Upload_OnlyBuffers,
        Default_OnlyBuffers,

        Default_OnlyNonRenderableOrDepthTextures,
        Default_OnlyRenderableOrDepthTextures,

        EnumCount,
        InvalidEnum = EnumCount,
    };

    // Manages a list of resource allocators used by the device to create resources using
    // multiple allocation methods.
    class ResourceAllocator : public ResourceAllocatorBase {
      public:
        ResourceAllocator(const ALLOCATOR_DESC& descriptor);
        ~ResourceAllocator();

        HRESULT CreateResource(const ALLOCATION_DESC& allocationDescriptor,
                               const D3D12_RESOURCE_DESC& resourceDescriptor,
                               D3D12_RESOURCE_STATES initialUsage,
                               const D3D12_CLEAR_VALUE* clearValue,
                               ResourceAllocation** allocation);

        HRESULT CreateResource(ComPtr<ID3D12Resource> resource, ResourceAllocation** allocation);

        ResidencyManager* GetResidencyManager();

      private:
        friend HeapAllocator;
        friend ResourceAllocation;

        void FreePlacedResource(ResourceAllocation& allocation);
        void FreeResourceHeap(ResourceMemoryAllocation& allocation);

        HRESULT CreatePlacedResource(D3D12_HEAP_TYPE heapType,
                                     const D3D12_RESOURCE_DESC& requestedResourceDescriptor,
                                     const D3D12_CLEAR_VALUE* clearValue,
                                     D3D12_RESOURCE_STATES initialUsage,
                                     ResourceAllocation** allocation);

        HRESULT CreateCommittedResource(D3D12_HEAP_TYPE heapType,
                                        const D3D12_RESOURCE_DESC& resourceDescriptor,
                                        const D3D12_CLEAR_VALUE* clearValue,
                                        D3D12_RESOURCE_STATES initialUsage,
                                        ResourceAllocation** allocation);

        ComPtr<ID3D12Device> mDevice;

        bool mIsUMA;
        uint32_t mResourceHeapTier;
        bool mIsAlwaysCommitted;

        static constexpr uint64_t kMaxHeapSize = 32ll * 1024ll * 1024ll * 1024ll;  // 32GB
        static constexpr uint64_t kMinHeapSize = 4ll * 1024ll * 1024ll;            // 4MB

        std::array<std::unique_ptr<BuddyMemoryAllocator>, ResourceHeapKind::EnumCount>
            mSubAllocatedResourceAllocators;
        std::array<std::unique_ptr<HeapAllocator>, ResourceHeapKind::EnumCount> mHeapAllocators;

        std::array<std::unique_ptr<PooledMemoryAllocator>, ResourceHeapKind::EnumCount>
            mPooledHeapAllocators;

        std::unique_ptr<ResidencyManager> mResidencyManager;
    };

}}  // namespace gpgmm::d3d12

#endif  // GPGMM_D3D12_RESOURCEALLOCATORD3D12_H_
