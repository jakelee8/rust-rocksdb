// Copyright 2014 Tyler Neely
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
extern crate libc;

pub use ffi as rocksdb_ffi;
pub use ffi::{DBCompactionStyle, DBComparator};
pub use rocksdb::{DB, DBIterator, DBVector, Direction, IteratorMode, Writable,
                  WriteBatch};
pub use rocksdb_options::{BlockBasedOptions, Options, WriteOptions};
pub use merge_operator::MergeOperands;

pub mod ffi;
pub mod rocksdb;
pub mod rocksdb_options;
pub mod merge_operator;
pub mod comparator;

pub fn new_bloom_filter(bits: libc::c_int) -> ffi::DBFilterPolicy {
    unsafe { ffi::rocksdb_filterpolicy_create_bloom(bits) as *const _ }
}

pub fn new_cache(capacity: libc::size_t) -> ffi::DBCache {
    unsafe { ffi::rocksdb_cache_create_lru(capacity) as *const _ }
}
