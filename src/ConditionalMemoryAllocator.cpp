// Copyright 2021 The GPGMM Authors
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

#include "src/ConditionalMemoryAllocator.h"
#include "common/Assert.h"

namespace gpgmm {

    ConditionalMemoryAllocator::ConditionalMemoryAllocator(MemoryAllocator* firstAllocator,
                                                           MemoryAllocator* secondAllocator,
                                                           uint64_t conditionalSize)
        : mFirstAllocator(firstAllocator),
          mSecondAllocator(secondAllocator),
          mConditionalSize(conditionalSize) {
    }

    void ConditionalMemoryAllocator::ReleaseMemory() {
        mFirstAllocator->ReleaseMemory();
        mSecondAllocator->ReleaseMemory();
    }

    MemoryAllocation ConditionalMemoryAllocator::SubAllocateMemory(uint64_t size,
                                                                   uint64_t alignment) {
        if (size < mConditionalSize) {
            return mFirstAllocator->SubAllocateMemory(size, alignment);
        } else {
            return mSecondAllocator->SubAllocateMemory(size, alignment);
        }
    }

    void ConditionalMemoryAllocator::AllocateMemory(MemoryAllocation** ppAllocation) {
        ASSERT(false);
    }

    void ConditionalMemoryAllocator::DeallocateMemory(MemoryAllocation* pAllocation) {
        pAllocation->GetAllocator()->DeallocateMemory(pAllocation);
    }

    uint64_t ConditionalMemoryAllocator::GetMemorySize() const {
        return kInvalidSize;
    }

    uint64_t ConditionalMemoryAllocator::GetMemoryAlignment() const {
        return kInvalidOffset;
    }

}  // namespace gpgmm