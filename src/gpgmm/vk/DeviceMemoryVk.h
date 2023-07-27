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

#ifndef SRC_GPGMM_VK_DEVICEMEMORYVK_H_
#define SRC_GPGMM_VK_DEVICEMEMORYVK_H_

#include "gpgmm/common/Memory.h"

#include "gpgmm/vk/VKPlatform.h"

namespace gpgmm::vk {

    class DeviceMemory final : public MemoryBase {
      public:
        DeviceMemory(VkDeviceMemory memory,
                     uint32_t memoryTypeIndex,
                     uint64_t size,
                     uint64_t alignment);
        ~DeviceMemory() override = default;

        VkDeviceMemory GetDeviceMemory() const;
        uint32_t GetMemoryTypeIndex() const;

      private:
        VkDeviceMemory mMemory = VK_NULL_HANDLE;
        uint32_t mMemoryTypeIndex = 0;
    };

}  // namespace gpgmm::vk

#endif  // SRC_GPGMM_VK_DEVICEMEMORYVK_H_
