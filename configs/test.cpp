/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <android-base/result.h>
#include <android/content/pm/IPackageManagerNative.h>
#include <binder/IServiceManager.h>
#include <gtest/gtest.h>
#include <jsonpb/json_schema_test.h>
#include <utils/String16.h>
#include <utils/StrongPointer.h>

#include "schema.pb.h"

using ::android::jsonpb::JsonSchemaTest;

namespace android::os::dma_heap {

namespace {
android::base::Result<bool> HasFeature(const std::string& name) {
    sp<IServiceManager> sm(defaultServiceManager());
    sp<IBinder> binder(sm->waitForService(String16("package_native")));
    if (binder == nullptr) {
        return android::base::Error() << "waitForService package_native failed";
    }
    sp<android::content::pm::IPackageManagerNative> package_mgr =
            interface_cast<android::content::pm::IPackageManagerNative>(binder);
    if (package_mgr == nullptr) {
        return android::base::Error() << "package_native is not a PackageManagerNative";
    }
    bool has_feature = false;
    auto status = package_mgr->hasSystemFeature(String16(name.c_str()), 0, &has_feature);
    if (!status.isOk()) {
        return android::base::Error() << "hasSystemFeature('" << name << "') failed: " << status;
    }
    return has_feature;
}
}  // namespace

class DmaHeapTestConfig : public jsonpb::AbstractJsonSchemaTestConfig<DmaHeapsInfo> {
  public:
    DmaHeapTestConfig(const std::string& path)
        : jsonpb::AbstractJsonSchemaTestConfig<DmaHeapsInfo>(path) {}
    // Failure if:
    // - Can't talk to package manager
    // - The feature android.hardware.npu is enabled but the file is missing
    // - Regardless of the feature, the file is present but not conforming to the schema.
    bool optional() const override {
        auto has_feature_result = HasFeature("android.hardware.npu");
        EXPECT_RESULT_OK(has_feature_result);
        auto required = has_feature_result.value_or(false);
        return !required;
    }
};

jsonpb::JsonSchemaTestConfigFactory MakeTestParam(const std::string& path) {
    return [path]() { return std::make_unique<DmaHeapTestConfig>(path); };
}

// Test suite instantiations.
// The test verifies if the npu.json file follows the schema.
// The file is optional, as not all devices will have this configuration.
INSTANTIATE_TEST_SUITE_P(DmaHeapConfig, JsonSchemaTest,
                         ::testing::Values(MakeTestParam("/vendor/etc/dma_heap.json")));

}  // namespace android::os::dma_heap

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
