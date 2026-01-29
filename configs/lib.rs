/*
 * Copyright (C) 2026 The Android Open Source Project
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
 *
 */

//! Helper to read /vendor/etc/dma_heap.json file.

use dma_heap_config_proto::schema::DmaHeapsInfo;
use std::fs;
use std::sync::LazyLock;

const CONFIG_PATH: &str = "/vendor/etc/dma_heap.json";

static INSTANCE: LazyLock<Option<DmaHeapsInfo>> = LazyLock::new(|| {
    match fs::read_to_string(CONFIG_PATH) {
        Ok(content) => protobuf_json_mapping::parse_from_str(&content)
            .map_err(|e| log::error!("Unable to parse {CONFIG_PATH}: {e}"))
            .ok(),
        // On legacy devices where the config file does not exist, assume an empty config.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(DmaHeapsInfo::new()),
        // If the file exists but can't be read (e.g. permission issues), propagate the error.
        Err(e) => {
            log::error!("Unable to read {CONFIG_PATH}: {e}");
            None
        }
    }
});

/// # Returns
///
/// Returns a singleton DmaHeapsInfo object if the configuration file exists and is valid,
/// or if it doesn't exist (on legacy devices).
/// Returns None if the file exists but can't be read or is malformed.
pub fn get() -> Option<&'static DmaHeapsInfo> {
    INSTANCE.as_ref()
}
