// Copyright 2019 The Dawn Authors
// Copyright 2022 The GPGMM Authors
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

#include "gpgmm/d3d12/ResourceHeapAllocatorD3D12.h"

#include "gpgmm/common/EventMessage.h"
#include "gpgmm/common/SizeClass.h"
#include "gpgmm/d3d12/BackendD3D12.h"
#include "gpgmm/d3d12/ErrorD3D12.h"
#include "gpgmm/d3d12/HeapD3D12.h"
#include "gpgmm/d3d12/ResidencyManagerD3D12.h"
#include "gpgmm/d3d12/UtilsD3D12.h"
#include "gpgmm/utils/Limits.h"
#include "gpgmm/utils/Math.h"
#ifdef INLINE_INSTR
#include "memory-layer.h"
#include "instrumentation/gpa-secure.h"
#endif
namespace gpgmm::d3d12 {

    static const wchar_t* kResourceHeapDebugName = L"GPGMM Resource Heap";

    ResourceHeapAllocator::ResourceHeapAllocator(ResidencyManager* residencyManager,
                                                 ID3D12Device* device,
                                                 D3D12_HEAP_PROPERTIES heapProperties,
                                                 D3D12_HEAP_FLAGS heapFlags,
                                                 bool alwaysCreatedInBudget)
        : mResidencyManager(residencyManager),
          mDevice(device),
          mHeapProperties(heapProperties),
          mHeapFlags(heapFlags),
          mIsAlwaysCreatedInBudget(alwaysCreatedInBudget) {
    }

    ResultOrError<std::unique_ptr<MemoryAllocation>> ResourceHeapAllocator::TryAllocateMemory(
        const MemoryAllocationRequest& request) {
        TRACE_EVENT0(TraceEventCategory::kDefault, "ResourceHeapAllocator.TryAllocateMemory");

        std::lock_guard<std::mutex> lock(mMutex);

        if (request.NeverAllocate) {
            return {};
        }

        HEAP_DESC resourceHeapDesc = {};
        // D3D12 requests (but not requires) the heap size be always a multiple of
        // alignment to avoid wasting bytes.
        // https://docs.microsoft.com/en-us/windows/win32/api/d3d12/ns-d3d12-d3d12_HEAP_INFO
        resourceHeapDesc.SizeInBytes = AlignTo(request.SizeInBytes, request.Alignment);
        resourceHeapDesc.Alignment = request.Alignment;
        resourceHeapDesc.DebugName = kResourceHeapDebugName;

        const bool isResidencyEnabled = (mResidencyManager != nullptr);
        if (isResidencyEnabled) {
            resourceHeapDesc.Flags |= GetHeapFlags(mHeapFlags, mIsAlwaysCreatedInBudget);
            resourceHeapDesc.MemorySegmentGroup = GetMemorySegmentGroup(
                mHeapProperties.MemoryPoolPreference, mResidencyManager->IsUMA());
        }

        D3D12_HEAP_DESC heapDesc = {};
        heapDesc.Properties = mHeapProperties;
        heapDesc.SizeInBytes = resourceHeapDesc.SizeInBytes;
        heapDesc.Alignment = resourceHeapDesc.Alignment;
        heapDesc.Flags = mHeapFlags;

        CreateResourceHeapCallbackContext createResourceHeapCallbackContext(mDevice, &heapDesc);
        ComPtr<IHeap> resourceHeap;
        HRESULT hr = Heap::CreateHeap(resourceHeapDesc, mResidencyManager,
                                      CreateResourceHeapCallbackContext::CreateHeap,
                                      &createResourceHeapCallbackContext, &resourceHeap);
        if (FAILED(hr)) {
            return {static_cast<ErrorCodeType>(hr)};
        }

        if (resourceHeapDesc.SizeInBytes > request.SizeInBytes) {
            DebugEvent(this, MessageId::kAlignmentMismatch)
                << "Resource heap was larger then the requested size: "
                << resourceHeapDesc.SizeInBytes << " vs " << request.SizeInBytes << " bytes.";
        }

        mStats.UsedMemoryUsage += resourceHeapDesc.SizeInBytes;
        mStats.UsedMemoryCount++;

        return std::make_unique<MemoryAllocation>(this, static_cast<Heap*>(resourceHeap.Detach()),
                                                  request.SizeInBytes);
    }

    void ResourceHeapAllocator::DeallocateMemory(std::unique_ptr<MemoryAllocation> allocation) {
        std::lock_guard<std::mutex> lock(mMutex);

        TRACE_EVENT0(TraceEventCategory::kDefault, "ResourceHeapAllocator.DeallocateMemory");

        mStats.UsedMemoryUsage -= allocation->GetSize();
        mStats.UsedMemoryCount--;
        SafeRelease(allocation);
    }

    const char* ResourceHeapAllocator::GetTypename() const {
        return "ResourceHeapAllocator";
    }

    CreateResourceHeapCallbackContext::CreateResourceHeapCallbackContext(ID3D12Device* device,
                                                                         D3D12_HEAP_DESC* heapDesc)
        : mDevice(device), mHeapDesc(heapDesc) {
    }

    HRESULT CreateResourceHeapCallbackContext::CreateHeap(void* pContext,
                                                          ID3D12Pageable** ppPageableOut) {
        CreateResourceHeapCallbackContext* createResourceHeapCallbackContext =
            static_cast<CreateResourceHeapCallbackContext*>(pContext);

        return createResourceHeapCallbackContext->CreateHeap(ppPageableOut);
    }

    HRESULT CreateResourceHeapCallbackContext::CreateHeap(ID3D12Pageable** ppPageableOut) {
        // Non-custom heaps are not allowed to have the pool-specified.
        if (mHeapDesc->Properties.Type != D3D12_HEAP_TYPE_CUSTOM) {
            mHeapDesc->Properties.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
        }

#ifdef INLINE_INSTR
        static const HMODULE hMemoryLayer = gpa::secure::LoadLibrarySDL("memory-layer-x64.dll");
        gpa::memory_layer::MemoryUsage sMemUsage = {0};
        uint64_t TSC = 0;
        if (hMemoryLayer) {
            static const uint64_t (*pPre_GetMemUsage)(gpa::memory_layer::MemoryUsage&) =
                (const uint64_t (*)(gpa::memory_layer::MemoryUsage&))GetProcAddress(
                                                                    hMemoryLayer,
                                                                    "Pre_GetMemUsage");
            if (pPre_GetMemUsage) {
                TSC = pPre_GetMemUsage(sMemUsage);
            }
        }
#endif

        ComPtr<ID3D12Heap> heap;
        ReturnIfFailed(mDevice->CreateHeap(mHeapDesc, IID_PPV_ARGS(&heap)));

        *ppPageableOut = heap.Detach();
#ifdef INLINE_INSTR
        if (hMemoryLayer) {
            static const uint64_t (*pGetInterceptedCallOrdinal)() =
                (const uint64_t (*)())GetProcAddress(hMemoryLayer, "GetInterceptedCallOrdinal");
            static const void (*pPushHeap)(gpa::memory_layer::Heap) =
                (const void (*)(gpa::memory_layer::Heap))GetProcAddress(hMemoryLayer,
                                                                        "PushHeap");
            uint64_t callOrdinal = 0;
            if (pGetInterceptedCallOrdinal) {
                callOrdinal = pGetInterceptedCallOrdinal();
            }
            if (pPushHeap) {
                gpa::memory_layer::Heap h = {callOrdinal,
                                             (uint64_t)*ppPageableOut,
                                             mHeapDesc->SizeInBytes,
                                             mHeapDesc->Alignment,
                                             (uint64_t)mHeapDesc->Flags,
                                             TSC,
                                             GetCurrentThreadId(),
                                             (uint32_t)mHeapDesc->Properties.CreationNodeMask,
                                             (uint32_t)mHeapDesc->Properties.VisibleNodeMask,
                                             (uint8_t)mHeapDesc->Properties.Type,
                                             (uint8_t)mHeapDesc->Properties.CPUPageProperty,
                                             (uint8_t)mHeapDesc->Properties.MemoryPoolPreference,
                                             true};  // internal
                pPushHeap(h);
            }
            static const uint64_t (*pPost_CallAllocated)(
                const bool, const WCHAR*, const uint64_t, const uint64_t,
                const gpa::memory_layer::MemoryUsage, const uint64_t) =
                (const uint64_t (*)(const bool, const WCHAR*, const uint64_t, const uint64_t,
                                    const gpa::memory_layer::MemoryUsage,
                                    const uint64_t))GetProcAddress(hMemoryLayer,
                                                                   "Post_CallAllocated");
            if (pPost_CallAllocated) {
                const WCHAR* const name = L"ID3D12Device::CreateHeap";
                pPost_CallAllocated(true, name, callOrdinal, TSC, sMemUsage,
                                    (uint64_t)*ppPageableOut);
            }
        }
#endif
        return S_OK;
    }

}  // namespace gpgmm::d3d12
