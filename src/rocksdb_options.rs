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

use libc::*;
use std::ffi::CString;
use std::mem;

use rocksdb_ffi;
use merge_operator::{self, MergeOperands, MergeOperatorCallback,
                     full_merge_callback, partial_merge_callback};
use comparator::{self, ComparatorCallback, compare_callback};

pub struct BlockBasedOptions {
    inner: rocksdb_ffi::DBBlockBasedTableOptions,
}

pub struct Options {
    pub inner: rocksdb_ffi::DBOptions,
}

pub struct WriteOptions {
    pub inner: rocksdb_ffi::DBWriteOptions,
}

impl Drop for Options {
    fn drop(&mut self) {
        unsafe {
            rocksdb_ffi::rocksdb_options_destroy(self.inner as *mut _);
        }
    }
}

impl Drop for BlockBasedOptions {
    fn drop(&mut self) {
        unsafe {
            rocksdb_ffi::rocksdb_block_based_options_destroy(self.inner as *mut _);
        }
    }
}

impl Drop for WriteOptions {
    fn drop(&mut self) {
        unsafe {
            rocksdb_ffi::rocksdb_writeoptions_destroy(self.inner as *mut _);
        }
    }
}

impl BlockBasedOptions {
    pub fn new() -> BlockBasedOptions {
        let block_opts = unsafe {
            rocksdb_ffi::rocksdb_block_based_options_create()
        };
        if block_opts.is_null() {
            panic!("Could not create rocksdb block based options".to_string());
        }
        BlockBasedOptions { inner: block_opts }
    }

    pub fn set_block_size(&mut self, size: usize) {
        unsafe {
            rocksdb_ffi::rocksdb_block_based_options_set_block_size(self.inner as *mut _,
                                                                    size as size_t);
        }
    }
}

// TODO figure out how to create these in a Rusty way
// /pub fn set_filter(&mut self, filter: rocksdb_ffi::DBFilterPolicy) {
// /    unsafe {
// /        rocksdb_ffi::rocksdb_block_based_options_set_filter_policy(
// /            self.inner, filter);
// /    }
// /}

/// /pub fn set_cache(&mut self, cache: rocksdb_ffi::DBCache) {
/// /    unsafe {
/// /        rocksdb_ffi::rocksdb_block_based_options_set_block_cache(
/// /            self.inner, cache);
/// /    }
/// /}

/// /pub fn set_cache_compressed(&mut self, cache: rocksdb_ffi::DBCache) {
/// /    unsafe {
/// /        rocksdb_ffi::
/// rocksdb_block_based_options_set_block_cache_compressed(
/// /            self.inner, cache);
/// /    }
/// /}


impl Options {
    pub fn new() -> Options {
        unsafe {
            let opts = rocksdb_ffi::rocksdb_options_create();
            if opts.is_null() {
                panic!("Could not create rocksdb options".to_string());
            }
            Options { inner: opts }
        }
    }

    pub fn increase_parallelism(&mut self, parallelism: i32) {
        unsafe {
            rocksdb_ffi::rocksdb_options_increase_parallelism(self.inner as *mut _,
                                                              parallelism as c_int);
        }
    }

    pub fn optimize_level_style_compaction(&mut self,
                                           memtable_memory_budget: u64) {
        unsafe {
            rocksdb_ffi::rocksdb_options_optimize_level_style_compaction(
                self.inner as *mut _, memtable_memory_budget as uint64_t);
        }
    }

    pub fn create_if_missing(&mut self, create_if_missing: bool) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_create_if_missing(
                self.inner as *mut _, create_if_missing as c_uchar);
        }
    }

    pub fn add_merge_operator<'a>(&mut self,
                                  name: &str,
                                  merge_fn: fn(&[u8],
                                               Option<&[u8]>,
                                               &mut MergeOperands)
                                               -> Vec<u8>) {
        let cb = Box::new(MergeOperatorCallback {
            name: CString::new(name.as_bytes()).unwrap(),
            merge_fn: merge_fn,
        });

        unsafe {
            let mo = rocksdb_ffi::rocksdb_mergeoperator_create(
                mem::transmute(Box::into_raw(cb)),
                Some(merge_operator::destructor_callback),
                Some(full_merge_callback),
                Some(partial_merge_callback),
                None,
                Some(merge_operator::name_callback));
            rocksdb_ffi::rocksdb_options_set_merge_operator(self.inner as *mut _, mo);
        }
    }

    pub fn add_comparator<'a>(&mut self,
                              name: &str,
                              compare_fn: fn(&[u8], &[u8]) -> i32) {
        let cb = Box::new(ComparatorCallback {
            name: CString::new(name.as_bytes()).unwrap(),
            f: compare_fn,
        });

        unsafe {
            let cmp = rocksdb_ffi::rocksdb_comparator_create(
                mem::transmute(Box::into_raw(cb)),
                Some(comparator::destructor_callback),
                Some(compare_callback),
                Some(comparator::name_callback));
            rocksdb_ffi::rocksdb_options_set_comparator(self.inner as *mut _,
                                                        cmp);
        }
    }


    pub fn set_block_cache_size_mb(&mut self, cache_size: u64) {
        unsafe {
            rocksdb_ffi::rocksdb_options_optimize_for_point_lookup(self.inner as *mut _,
                                                                   cache_size as uint64_t);
        }
    }

    pub fn set_max_open_files(&mut self, nfiles: i32) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_max_open_files(self.inner as *mut _,
                                                            nfiles as c_int);
        }
    }

    pub fn set_use_fsync(&mut self, useit: bool) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_use_fsync(self.inner as *mut _,
                                                       useit as c_int);
        }
    }

    pub fn set_bytes_per_sync(&mut self, nbytes: u64) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_bytes_per_sync(self.inner as *mut _,
                                                            nbytes as uint64_t);
        }
    }

    pub fn set_disable_data_sync(&mut self, disable: bool) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_disable_data_sync(
                        self.inner as *mut _, disable as c_int);
        }
    }

    pub fn set_table_cache_num_shard_bits(&mut self, nbits: i32) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_table_cache_numshardbits(self.inner as *mut _,
                                                                      nbits as c_int);
        }
    }

    pub fn set_min_write_buffer_number(&mut self, nbuf: i32) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_min_write_buffer_number_to_merge(
                self.inner as *mut _, nbuf as c_int);
        }
    }

    pub fn set_max_write_buffer_number(&mut self, nbuf: i32) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_max_write_buffer_number(self.inner as *mut _,
                                                                     nbuf as c_int);
        }
    }

    pub fn set_write_buffer_size(&mut self, size: usize) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_write_buffer_size(self.inner as *mut _,
                                                               size as size_t);
        }
    }

    pub fn set_min_write_buffer_number_to_merge(&mut self, to_merge: i32) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_min_write_buffer_number_to_merge(
                self.inner as *mut _, to_merge as c_int);
        }
    }

    pub fn set_num_levels(&mut self, n: i32) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_num_levels(self.inner as *mut _,
                                                        n as c_int);
        }
    }

    pub fn set_level0_file_num_compaction_trigger(&mut self, n: i32) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_level0_file_num_compaction_trigger(
                self.inner as *mut _, n as c_int);
        }
    }

    pub fn set_level_zero_file_num_compaction_trigger(&mut self, n: i32) {
        self.set_level0_file_num_compaction_trigger(n);
    }

    pub fn set_level0_slowdown_writes_trigger(&mut self, n: i32) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_level0_slowdown_writes_trigger(
                self.inner as *mut _, n as c_int);
        }
    }

    pub fn set_level_zero_slowdown_writes_trigger(&mut self, n: i32) {
        self.set_level0_slowdown_writes_trigger(n);
    }

    pub fn set_level0_stop_writes_trigger(&mut self, n: i32) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_level0_stop_writes_trigger(
                self.inner as *mut _, n as c_int);
        }
    }

    pub fn set_level_zero_stop_writes_trigger(&mut self, n: i32) {
        self.set_level0_stop_writes_trigger(n);
    }

    pub fn set_target_file_size_base(&mut self, size: u64) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_target_file_size_base(
                self.inner as *mut _, size as uint64_t);
        }
    }

    pub fn set_target_file_size_multiplier(&mut self, size: i32) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_target_file_size_multiplier(
                self.inner as *mut _, size as c_int);
        }
    }

    pub fn set_max_bytes_for_level_base(&mut self, size: u64) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_max_bytes_for_level_base(
                self.inner as *mut _, size as uint64_t);
        }
    }

    pub fn set_max_bytes_for_level_multiplier(&mut self, size: i32) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_max_bytes_for_level_multiplier(
                self.inner as *mut _, size as c_int);
        }
    }

    pub fn set_compaction_style(&mut self,
                                style: rocksdb_ffi::DBCompactionStyle) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_compaction_style(self.inner as *mut _,
                                                              style as c_int);
        }
    }

    pub fn set_max_background_compactions(&mut self, n: i32) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_max_background_compactions(
                self.inner as *mut _, n as c_int);
        }
    }

    pub fn set_max_background_flushes(&mut self, n: i32) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_max_background_flushes(self.inner as *mut _,
                                                                    n as c_int);
        }
    }

    pub fn set_filter_deletes(&mut self, filter: bool) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_filter_deletes(self.inner as *mut _,
                                                            filter as c_uchar);
        }
    }

    pub fn set_disable_auto_compactions(&mut self, disable: bool) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_disable_auto_compactions(
                        self.inner as *mut _, disable as c_int);
        }
    }

    pub fn set_block_based_table_factory(&mut self,
                                         factory: &BlockBasedOptions) {
        unsafe {
            rocksdb_ffi::rocksdb_options_set_block_based_table_factory(
                self.inner as *mut _, factory.inner as *mut _);
        }
    }
}

impl WriteOptions {
    pub fn new() -> WriteOptions {
        let write_opts = unsafe { rocksdb_ffi::rocksdb_writeoptions_create() };
        if write_opts.is_null() {
            panic!("Could not create rocksdb write options".to_string());
        }
        WriteOptions { inner: write_opts }
    }
    pub fn set_sync(&mut self, sync: bool) {
        unsafe {
            rocksdb_ffi::rocksdb_writeoptions_set_sync(self.inner as *mut _,
                                                       sync as c_uchar);
        }
    }
}
