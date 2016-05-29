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

use std::ffi::CStr;
use std::str::from_utf8;

use libc::*;

pub fn error_message(ptr: *const i8) -> String {
    let c_str = unsafe { CStr::from_ptr(ptr as *const _) };
    let s = from_utf8(c_str.to_bytes()).unwrap().to_owned();
    unsafe {
        libc::free(ptr as *mut libc::c_void);
    }
    s
}

pub enum DBInstanceOpaque {}
pub enum DBBackupEngineOpaque {}
pub enum DBBackupEngineInfoOpaque {}
pub enum DBRestoreOptionsOpaque {}
pub enum DBCacheOpaque {}
pub enum DBCompactionFilterOpaque {}
pub enum DBCompactionFilterContextOpaque {}
pub enum DBCompactionFilterFactoryOpaque {}
pub enum DBComparatorOpaque {}
pub enum DBEnvOpaque {}
pub enum DBFifoCompactionOptionsOpaque {}
pub enum DBFileLockOpaque {}
pub enum DBFilterPolicyOpaque {}
pub enum DBFlushOptionsOpaque {}
pub enum DBIteratorOpaque {}
pub enum DBLoggerOpaque {}
pub enum DBMergeOperatorOpaque {}
pub enum DBOptionsOpaque {}
pub enum DBBlockBasedTableOptionsOpaque {}
pub enum DBCuckooTableOptionsOpaque {}
pub enum DBRandomFileOpaque {}
pub enum DBReadOptionsOpaque {}
pub enum DBSeqFileOpaque {}
pub enum DBSliceTransformOpaque {}
pub enum DBSnapshotOpaque {}
pub enum DBWritableFileOpaque {}
pub enum DBWriteBatchOpaque {}
pub enum DBWriteOptionsOpaque {}
pub enum DBUniversalCompactionOptionsOpaque {}
pub enum DBLiveFilesOpaque {}
pub enum DBCFHandleOpaque {}

pub type DBInstance = *const DBInstanceOpaque;
pub type DBBackupEngine = *const DBBackupEngineOpaque;
pub type DBBackupEngineInfo = *const DBBackupEngineInfoOpaque;
pub type DBRestoreOptions = *const DBRestoreOptionsOpaque;
pub type DBCache = *const DBCacheOpaque;
pub type DBCompactionFilter = *const DBCompactionFilterOpaque;
pub type DBCompactionFilterContext = *const DBCompactionFilterContextOpaque;
pub type DBCompactionFilterFactory = *const DBCompactionFilterFactoryOpaque;
pub type DBComparator = *const DBComparatorOpaque;
pub type DBEnv = *const DBEnvOpaque;
pub type DBFifoCompactionOptions = *const DBFifoCompactionOptionsOpaque;
pub type DBFileLock = *const DBFileLockOpaque;
pub type DBFilterPolicy = *const DBFilterPolicyOpaque;
pub type DBFlushOptions = *const DBFlushOptionsOpaque;
pub type DBIterator = *const DBIteratorOpaque;
pub type DBLogger = *const DBLoggerOpaque;
pub type DBMergeOperator = *const DBMergeOperatorOpaque;
pub type DBOptions = *const DBOptionsOpaque;
pub type DBBlockBasedTableOptions = *const DBBlockBasedTableOptionsOpaque;
pub type DBCuckooTableOptions = *const DBCuckooTableOptionsOpaque;
pub type DBRandomFile = *const DBRandomFileOpaque;
pub type DBReadOptions = *const DBReadOptionsOpaque;
pub type DBSeqFile = *const DBSeqFileOpaque;
pub type DBSliceTransform = *const DBSliceTransformOpaque;
pub type DBSnapshot = *const DBSnapshotOpaque;
pub type DBWritableFile = *const DBWritableFileOpaque;
pub type DBWriteBatch = *const DBWriteBatchOpaque;
pub type DBWriteOptions = *const DBWriteOptionsOpaque;
pub type DBUniversalCompactionOptions =
    *const DBUniversalCompactionOptionsOpaque;
pub type DBLiveFiles = *const DBLiveFilesOpaque;
pub type DBCFHandle = *const DBCFHandleOpaque;

#[repr(C)]
pub enum DBBlockBasedTableIndexType {
    DBBinarySearch = 0,
    DBHashSearch = 1,
}

#[repr(C)]
pub enum DBCompressionType {
    DBNoCompression = 0,
    DBSnappyCompression = 1,
    DBZlibCompression = 2,
    DBBz2Compression = 3,
    DBLz4Compression = 4,
    DBLz4hcCompression = 5,
}

#[repr(C)]
pub enum DBCompactionStyle {
    DBLevelCompaction = 0,
    DBUniversalCompaction = 1,
    DBFifoCompaction = 2,
}

#[repr(C)]
pub enum DBUniversalCompactionStyle {
    SimilarSizeCompactionStopStyle = 0,
    TotalSizeCompactionStopStyle = 1,
}

pub type DBGetNameFn = extern "C" fn(*mut c_void) -> *const c_char;
pub type DBCompareFn = extern "C" fn(*mut c_void,
                                     *const c_char,
                                     size_t,
                                     *const c_char,
                                     size_t)
                                     -> c_int;
pub type DBDeleteFn = extern "C" fn(*mut c_void, *const c_char, size_t);
pub type DBDestructFn = extern "C" fn(*mut c_void);

pub type DBWriteBatchPutFn = extern "C" fn(*mut c_void,
                                           *const c_char,
                                           size_t,
                                           *const c_char,
                                           size_t);

pub type DBCompactionFilterFn = extern "C" fn(*mut c_void,
                                              c_int,
                                              *const c_char,
                                              size_t,
                                              *const c_char,
                                              size_t,
                                              *mut *const c_char,
                                              *mut size_t,
                                              *mut c_uchar)
                                              -> c_uchar;
pub type DBCompactionFilterFactoryFn =
    extern "C" fn(*mut c_void, *mut DBCompactionFilterContextOpaque)
                  -> *mut DBCompactionFilterOpaque;

pub type DBFilterPolicyFactoryFn = extern "C" fn(*mut c_void,
                                                 *const *const c_char,
                                                 *const size_t,
                                                 c_int,
                                                 *mut size_t)
                                                 -> *mut c_char;
pub type DBFilterPolicyKeyMayMatchFn = extern "C" fn(*mut c_void,
                                                     *const c_char,
                                                     size_t,
                                                     *const c_char,
                                                     size_t)
                                                     -> c_uchar;

pub type DBSliceTransformFn = extern "C" fn(*mut c_void,
                                            *const c_char,
                                            size_t,
                                            *mut size_t)
                                            -> *mut c_char;
pub type DBSliceFilterFn = extern "C" fn(*mut c_void, *const c_char, size_t)
                                         -> c_uchar;

pub type DBMergeFullMergeFn = extern "C" fn(*mut c_void,
                                            *const c_char,
                                            size_t,
                                            *const c_char,
                                            size_t,
                                            *const *const c_char,
                                            *const size_t,
                                            c_int,
                                            *mut c_uchar,
                                            *mut size_t)
                                            -> *mut c_char;
pub type DBMergePartialMergeFn = extern "C" fn(*mut c_void,
                                               *const c_char,
                                               size_t,
                                               *const *const c_char,
                                               *const size_t,
                                               c_int,
                                               *mut c_uchar,
                                               *mut size_t)
                                               -> *mut c_char;

#[link(name = "rocksdb")]
extern "C" {
    pub fn rocksdb_open(options: *const DBOptionsOpaque,
                        name: *const c_char,
                        errptr: *mut *const c_char)
                        -> *mut DBInstanceOpaque;
    pub fn rocksdb_open_for_read_only(options: *const DBOptionsOpaque,
                                      name: *const c_char,
                                      error_if_log_file_exist: c_uchar,
                                      errptr: *mut *const c_char)
                                      -> *mut DBInstanceOpaque;
    pub fn rocksdb_backup_engine_open(options: *const DBOptionsOpaque,
                                      path: *const c_char,
                                      errptr: *mut *const c_char)
                                      -> *mut DBBackupEngineOpaque;
    pub fn rocksdb_backup_engine_create_new_backup(be: *mut DBBackupEngineOpaque,
                                                   db: *mut DBInstanceOpaque,
                                                   errptr: *mut *const c_char);
    pub fn rocksdb_backup_engine_purge_old_backups(be: *mut DBBackupEngineOpaque,
                                                   num_backups_to_keep: uint32_t,
                                                   errptr: *mut *const c_char);
    pub fn rocksdb_restore_options_create() -> *mut DBRestoreOptionsOpaque;
    pub fn rocksdb_restore_options_destroy(opt: *mut DBRestoreOptionsOpaque);
    pub fn rocksdb_restore_options_set_keep_log_files(opt: *mut DBRestoreOptionsOpaque, v: c_int);
    pub fn rocksdb_backup_engine_restore_db_from_latest_backup(be: *mut DBBackupEngineOpaque,
                                                               db_dir: *const c_char,
                                                               wal_dir: *const c_char,
                                                               restore_options: *const DBRestoreOptionsOpaque,
                                                               errptr: *mut *const c_char);
    pub fn rocksdb_backup_engine_get_backup_info
        (be: *mut DBBackupEngineOpaque)
         -> *const DBBackupEngineInfoOpaque;
    pub fn rocksdb_backup_engine_info_count(info: *const DBBackupEngineInfoOpaque) -> c_int;
    pub fn rocksdb_backup_engine_info_timestamp(info: *const DBBackupEngineInfoOpaque, index: c_int) -> int64_t;
    pub fn rocksdb_backup_engine_info_backup_id(info: *const DBBackupEngineInfoOpaque, index: c_int) -> uint32_t;
    pub fn rocksdb_backup_engine_info_size(info: *const DBBackupEngineInfoOpaque, index: c_int) -> uint64_t;
    pub fn rocksdb_backup_engine_info_number_files(info: *const DBBackupEngineInfoOpaque,
                                                   index: c_int)
                                                   -> uint32_t;
    pub fn rocksdb_backup_engine_info_destroy(info: *const DBBackupEngineInfoOpaque);
    pub fn rocksdb_backup_engine_close(be: *mut DBBackupEngineOpaque);
    pub fn rocksdb_open_column_families(options: *const DBOptionsOpaque,
                                        name: *const c_char,
                                        num_column_families: c_int,
                                        column_family_names: *const *const c_char,
                                        column_family_options: *const *const DBOptionsOpaque,
                                        column_family_handles: *mut *mut DBCFHandleOpaque,
                                        errptr: *mut *const c_char)
                                        -> *mut DBInstanceOpaque;
    pub fn rocksdb_open_for_read_only_column_families
        (options: *const DBOptionsOpaque,
         name: *const c_char,
         num_column_families: c_int,
         column_family_names: *const *const c_char,
         column_family_options: *const *const DBOptionsOpaque,
         column_family_handles: *mut *mut DBCFHandleOpaque,
         error_if_log_file_exist: c_uchar,
         errptr: *mut *const c_char)
         -> *mut DBInstanceOpaque;
    pub fn rocksdb_list_column_families(options: *const DBOptionsOpaque,
                                        name: *const c_char,
                                        lencf: *mut size_t,
                                        errptr: *mut *const c_char)
                                        -> *mut *const c_char;
    pub fn rocksdb_list_column_families_destroy(list: *mut *const c_char,
                                                len: size_t);
    pub fn rocksdb_create_column_family
        (db: *mut DBInstanceOpaque,
         column_family_options: *const DBOptionsOpaque,
         column_family_name: *const c_char,
         errptr: *mut *const c_char)
         -> *mut DBCFHandleOpaque;
    pub fn rocksdb_drop_column_family(db: *mut DBInstanceOpaque,
                                      handle: *mut DBCFHandleOpaque,
                                      errptr: *mut *const c_char);
    pub fn rocksdb_column_family_handle_destroy(arg1: *mut DBCFHandleOpaque);
    pub fn rocksdb_close(db: *mut DBInstanceOpaque);
    pub fn rocksdb_put(db: *mut DBInstanceOpaque,
                       options: *const DBWriteOptionsOpaque,
                       key: *const c_char,
                       keylen: size_t,
                       val: *const c_char,
                       vallen: size_t,
                       errptr: *mut *const c_char);
    pub fn rocksdb_put_cf(db: *mut DBInstanceOpaque,
                          options: *const DBWriteOptionsOpaque,
                          column_family: *mut DBCFHandleOpaque,
                          key: *const c_char,
                          keylen: size_t,
                          val: *const c_char,
                          vallen: size_t,
                          errptr: *mut *const c_char);
    pub fn rocksdb_delete(db: *mut DBInstanceOpaque,
                          options: *const DBWriteOptionsOpaque,
                          key: *const c_char,
                          keylen: size_t,
                          errptr: *mut *const c_char);
    pub fn rocksdb_delete_cf(db: *mut DBInstanceOpaque,
                             options: *const DBWriteOptionsOpaque,
                             column_family: *mut DBCFHandleOpaque,
                             key: *const c_char,
                             keylen: size_t,
                             errptr: *mut *const c_char);
    pub fn rocksdb_merge(db: *mut DBInstanceOpaque,
                         options: *const DBWriteOptionsOpaque,
                         key: *const c_char,
                         keylen: size_t,
                         val: *const c_char,
                         vallen: size_t,
                         errptr: *mut *const c_char);
    pub fn rocksdb_merge_cf(db: *mut DBInstanceOpaque,
                            options: *const DBWriteOptionsOpaque,
                            column_family: *mut DBCFHandleOpaque,
                            key: *const c_char,
                            keylen: size_t,
                            val: *const c_char,
                            vallen: size_t,
                            errptr: *mut *const c_char);
    pub fn rocksdb_write(db: *mut DBInstanceOpaque,
                         options: *const DBWriteOptionsOpaque,
                         batch: *mut DBWriteBatchOpaque,
                         errptr: *mut *const c_char);
    pub fn rocksdb_get(db: *mut DBInstanceOpaque,
                       options: *const DBReadOptionsOpaque,
                       key: *const c_char,
                       keylen: size_t,
                       vallen: *mut size_t,
                       errptr: *mut *const c_char)
                       -> *mut c_char;
    pub fn rocksdb_get_cf(db: *mut DBInstanceOpaque,
                          options: *const DBReadOptionsOpaque,
                          column_family: *mut DBCFHandleOpaque,
                          key: *const c_char,
                          keylen: size_t,
                          vallen: *mut size_t,
                          errptr: *mut *const c_char)
                          -> *mut c_char;
    pub fn rocksdb_multi_get(db: *mut DBInstanceOpaque,
                             options: *const DBReadOptionsOpaque,
                             num_keys: size_t,
                             keys_list: *const *const c_char,
                             keys_list_sizes: *const size_t,
                             values_list: *mut *const c_char,
                             values_list_sizes: *mut size_t,
                             errs: *mut *const c_char);
    pub fn rocksdb_multi_get_cf(db: *mut DBInstanceOpaque,
                                options: *const DBReadOptionsOpaque,
                                column_families: *const *const DBCFHandleOpaque,
                                num_keys: size_t,
                                keys_list: *const *const c_char,
                                keys_list_sizes: *const size_t,
                                values_list: *mut *const c_char,
                                values_list_sizes: *mut size_t,
                                errs: *mut *const c_char);
    pub fn rocksdb_create_iterator(db: *mut DBInstanceOpaque,
                                   options: *const DBReadOptionsOpaque)
                                   -> *mut DBIteratorOpaque;
    pub fn rocksdb_create_iterator_cf(db: *mut DBInstanceOpaque,
                                      options: *const DBReadOptionsOpaque,
                                      column_family: *mut DBCFHandleOpaque)
                                      -> *mut DBIteratorOpaque;
    pub fn rocksdb_create_iterators(db: *mut DBInstanceOpaque,
                                    opts: *mut DBReadOptionsOpaque,
                                    column_families: *mut *mut DBCFHandleOpaque,
                                    iterators: *mut *mut DBIteratorOpaque,
                                    size: size_t,
                                    errptr: *mut *const c_char);
    pub fn rocksdb_create_snapshot(db: *mut DBInstanceOpaque)
                                   -> *const DBSnapshotOpaque;
    pub fn rocksdb_release_snapshot(db: *mut DBInstanceOpaque,
                                    snapshot: *const DBSnapshotOpaque);
    pub fn rocksdb_property_value(db: *mut DBInstanceOpaque,
                                  propname: *const c_char)
                                  -> *mut c_char;
    pub fn rocksdb_property_value_cf(db: *mut DBInstanceOpaque,
                                     column_family: *mut DBCFHandleOpaque,
                                     propname: *const c_char)
                                     -> *mut c_char;
    pub fn rocksdb_approximate_sizes(db: *mut DBInstanceOpaque,
                                     num_ranges: c_int,
                                     range_start_key: *const *const c_char,
                                     range_start_key_len: *const size_t,
                                     range_limit_key: *const *const c_char,
                                     range_limit_key_len: *const size_t,
                                     sizes: *mut uint64_t);
    pub fn rocksdb_approximate_sizes_cf(db: *mut DBInstanceOpaque,
                                        column_family: *mut DBCFHandleOpaque,
                                        num_ranges: c_int,
                                        range_start_key: *const *const c_char,
                                        range_start_key_len: *const size_t,
                                        range_limit_key: *const *const c_char,
                                        range_limit_key_len: *const size_t,
                                        sizes: *mut uint64_t);
    pub fn rocksdb_compact_range(db: *mut DBInstanceOpaque,
                                 start_key: *const c_char,
                                 start_key_len: size_t,
                                 limit_key: *const c_char,
                                 limit_key_len: size_t);
    pub fn rocksdb_compact_range_cf(db: *mut DBInstanceOpaque,
                                    column_family: *mut DBCFHandleOpaque,
                                    start_key: *const c_char,
                                    start_key_len: size_t,
                                    limit_key: *const c_char,
                                    limit_key_len: size_t);
    pub fn rocksdb_delete_file(db: *mut DBInstanceOpaque,
                               name: *const c_char);
    pub fn rocksdb_livefiles(db: *mut DBInstanceOpaque)
                             -> *const DBLiveFilesOpaque;
    pub fn rocksdb_flush(db: *mut DBInstanceOpaque,
                         options: *const DBFlushOptionsOpaque,
                         errptr: *mut *const c_char);
    pub fn rocksdb_disable_file_deletions(db: *mut DBInstanceOpaque,
                                          errptr: *mut *const c_char);
    pub fn rocksdb_enable_file_deletions(db: *mut DBInstanceOpaque,
                                         force: c_uchar,
                                         errptr: *mut *const c_char);
    pub fn rocksdb_destroy_db(options: *const DBOptionsOpaque,
                              name: *const c_char,
                              errptr: *mut *const c_char);
    pub fn rocksdb_repair_db(options: *const DBOptionsOpaque,
                             name: *const c_char,
                             errptr: *mut *const c_char);
    pub fn rocksdb_iter_destroy(arg1: *mut DBIteratorOpaque);
    pub fn rocksdb_iter_valid(arg1: *const DBIteratorOpaque) -> c_uchar;
    pub fn rocksdb_iter_seek_to_first(arg1: *mut DBIteratorOpaque);
    pub fn rocksdb_iter_seek_to_last(arg1: *mut DBIteratorOpaque);
    pub fn rocksdb_iter_seek(arg1: *mut DBIteratorOpaque,
                             k: *const c_char,
                             klen: size_t);
    pub fn rocksdb_iter_next(arg1: *mut DBIteratorOpaque);
    pub fn rocksdb_iter_prev(arg1: *mut DBIteratorOpaque);
    pub fn rocksdb_iter_key(arg1: *const DBIteratorOpaque,
                            klen: *mut size_t)
                            -> *const c_char;
    pub fn rocksdb_iter_value(arg1: *const DBIteratorOpaque,
                              vlen: *mut size_t)
                              -> *const c_char;
    pub fn rocksdb_iter_get_error(arg1: *const DBIteratorOpaque,
                                  errptr: *mut *const c_char);
    pub fn rocksdb_writebatch_create() -> *mut DBWriteBatchOpaque;
    pub fn rocksdb_writebatch_create_from(rep: *const c_char,
                                          size: size_t)
                                          -> *mut DBWriteBatchOpaque;
    pub fn rocksdb_writebatch_destroy(arg1: *mut DBWriteBatchOpaque);
    pub fn rocksdb_writebatch_clear(arg1: *mut DBWriteBatchOpaque);
    pub fn rocksdb_writebatch_count(arg1: *mut DBWriteBatchOpaque) -> c_int;
    pub fn rocksdb_writebatch_put(arg1: *mut DBWriteBatchOpaque,
                                  key: *const c_char,
                                  klen: size_t,
                                  val: *const c_char,
                                  vlen: size_t);
    pub fn rocksdb_writebatch_put_cf(arg1: *mut DBWriteBatchOpaque,
                                     column_family: *mut DBCFHandleOpaque,
                                     key: *const c_char,
                                     klen: size_t,
                                     val: *const c_char,
                                     vlen: size_t);
    pub fn rocksdb_writebatch_putv(b: *mut DBWriteBatchOpaque,
                                   num_keys: c_int,
                                   keys_list: *const *const c_char,
                                   keys_list_sizes: *const size_t,
                                   num_values: c_int,
                                   values_list: *const *const c_char,
                                   values_list_sizes: *const size_t);
    pub fn rocksdb_writebatch_putv_cf(b: *mut DBWriteBatchOpaque,
                                      column_family: *mut DBCFHandleOpaque,
                                      num_keys: c_int,
                                      keys_list: *const *const c_char,
                                      keys_list_sizes: *const size_t,
                                      num_values: c_int,
                                      values_list: *const *const c_char,
                                      values_list_sizes: *const size_t);
    pub fn rocksdb_writebatch_merge(arg1: *mut DBWriteBatchOpaque,
                                    key: *const c_char,
                                    klen: size_t,
                                    val: *const c_char,
                                    vlen: size_t);
    pub fn rocksdb_writebatch_merge_cf(arg1: *mut DBWriteBatchOpaque,
                                       column_family: *mut DBCFHandleOpaque,
                                       key: *const c_char,
                                       klen: size_t,
                                       val: *const c_char,
                                       vlen: size_t);
    pub fn rocksdb_writebatch_mergev(b: *mut DBWriteBatchOpaque,
                                     num_keys: c_int,
                                     keys_list: *const *const c_char,
                                     keys_list_sizes: *const size_t,
                                     num_values: c_int,
                                     values_list: *const *const c_char,
                                     values_list_sizes: *const size_t);
    pub fn rocksdb_writebatch_mergev_cf(b: *mut DBWriteBatchOpaque,
                                        column_family: *mut DBCFHandleOpaque,
                                        num_keys: c_int,
                                        keys_list: *const *const c_char,
                                        keys_list_sizes: *const size_t,
                                        num_values: c_int,
                                        values_list: *const *const c_char,
                                        values_list_sizes: *const size_t);
    pub fn rocksdb_writebatch_delete(arg1: *mut DBWriteBatchOpaque,
                                     key: *const c_char,
                                     klen: size_t);
    pub fn rocksdb_writebatch_delete_cf(arg1: *mut DBWriteBatchOpaque,
                                        column_family: *mut DBCFHandleOpaque,
                                        key: *const c_char,
                                        klen: size_t);
    pub fn rocksdb_writebatch_deletev(b: *mut DBWriteBatchOpaque,
                                      num_keys: c_int,
                                      keys_list: *const *const c_char,
                                      keys_list_sizes: *const size_t);
    pub fn rocksdb_writebatch_deletev_cf(b: *mut DBWriteBatchOpaque,
                                         column_family: *mut DBCFHandleOpaque,
                                         num_keys: c_int,
                                         keys_list: *const *const c_char,
                                         keys_list_sizes: *const size_t);
    pub fn rocksdb_writebatch_put_log_data(arg1: *mut DBWriteBatchOpaque,
                                           blob: *const c_char,
                                           len: size_t);
    pub fn rocksdb_writebatch_iterate(arg1: *mut DBWriteBatchOpaque,
                                      state: *mut c_void,
                                      put: Option<DBWriteBatchPutFn>,
                                      deleted: Option<DBDeleteFn>);
    pub fn rocksdb_writebatch_data(arg1: *mut DBWriteBatchOpaque,
                                   size: *mut size_t)
                                   -> *const c_char;
    pub fn rocksdb_block_based_options_create
        ()
        -> *mut DBBlockBasedTableOptionsOpaque;
    pub fn rocksdb_block_based_options_destroy(options: *mut DBBlockBasedTableOptionsOpaque);
    pub fn rocksdb_block_based_options_set_block_size(options: *mut DBBlockBasedTableOptionsOpaque,
                                                      block_size: size_t);
    pub fn rocksdb_block_based_options_set_block_size_deviation(options: *mut DBBlockBasedTableOptionsOpaque,
                                                                block_size_deviation: c_int);
    pub fn rocksdb_block_based_options_set_block_restart_interval(options: *mut DBBlockBasedTableOptionsOpaque,
                                                                  block_restart_interval: c_int);
    pub fn rocksdb_block_based_options_set_filter_policy(options: *mut DBBlockBasedTableOptionsOpaque,
                                                         filter_policy: *mut DBFilterPolicyOpaque);
    pub fn rocksdb_block_based_options_set_no_block_cache(options: *mut DBBlockBasedTableOptionsOpaque,
                                                          no_block_cache: c_uchar);
    pub fn rocksdb_block_based_options_set_block_cache(options: *mut DBBlockBasedTableOptionsOpaque,
                                                       block_cache: *mut DBCacheOpaque);
    pub fn rocksdb_block_based_options_set_block_cache_compressed(options: *mut DBBlockBasedTableOptionsOpaque,
                                                                  block_cache_compressed: *mut DBCacheOpaque);
    pub fn rocksdb_block_based_options_set_whole_key_filtering(arg1: *mut DBBlockBasedTableOptionsOpaque,
                                                               arg2: c_uchar);
    pub fn rocksdb_block_based_options_set_format_version(arg1: *mut DBBlockBasedTableOptionsOpaque,
                                                          arg2: c_int);
    pub fn rocksdb_block_based_options_set_index_type(arg1: *mut DBBlockBasedTableOptionsOpaque, arg2: c_int);
    pub fn rocksdb_block_based_options_set_hash_index_allow_collision(arg1: *mut DBBlockBasedTableOptionsOpaque,
                                                                      arg2: c_uchar);
    pub fn rocksdb_block_based_options_set_cache_index_and_filter_blocks(arg1: *mut DBBlockBasedTableOptionsOpaque,
                                                                         arg2: c_uchar);
    pub fn rocksdb_block_based_options_set_pin_l0_filter_and_index_blocks_in_cache
        (arg1: *mut DBBlockBasedTableOptionsOpaque,
         arg2: c_uchar);
    pub fn rocksdb_block_based_options_set_skip_table_builder_flush(options: *mut DBBlockBasedTableOptionsOpaque,
                                                                    arg1: c_uchar);
    pub fn rocksdb_options_set_block_based_table_factory(opt: *mut DBOptionsOpaque,
                                                         table_options: *mut DBBlockBasedTableOptionsOpaque);
    pub fn rocksdb_cuckoo_options_create() -> *mut DBCuckooTableOptionsOpaque;
    pub fn rocksdb_cuckoo_options_destroy(options: *mut DBCuckooTableOptionsOpaque);
    pub fn rocksdb_cuckoo_options_set_hash_ratio(options: *mut DBCuckooTableOptionsOpaque, v: c_double);
    pub fn rocksdb_cuckoo_options_set_max_search_depth(options: *mut DBCuckooTableOptionsOpaque, v: uint32_t);
    pub fn rocksdb_cuckoo_options_set_cuckoo_block_size(options: *mut DBCuckooTableOptionsOpaque, v: uint32_t);
    pub fn rocksdb_cuckoo_options_set_identity_as_first_hash(options: *mut DBCuckooTableOptionsOpaque,
                                                             v: c_uchar);
    pub fn rocksdb_cuckoo_options_set_use_module_hash(options: *mut DBCuckooTableOptionsOpaque, v: c_uchar);
    pub fn rocksdb_options_set_cuckoo_table_factory(opt: *mut DBOptionsOpaque,
                                                    table_options: *mut DBCuckooTableOptionsOpaque);
    pub fn rocksdb_options_create() -> *mut DBOptionsOpaque;
    pub fn rocksdb_options_destroy(arg1: *mut DBOptionsOpaque);
    pub fn rocksdb_options_increase_parallelism(opt: *mut DBOptionsOpaque,
                                                total_threads: c_int);
    pub fn rocksdb_options_optimize_for_point_lookup(opt: *mut DBOptionsOpaque, block_cache_size_mb: uint64_t);
    pub fn rocksdb_options_optimize_level_style_compaction(opt: *mut DBOptionsOpaque,
                                                           memtable_memory_budget: uint64_t);
    pub fn rocksdb_options_optimize_universal_style_compaction(opt: *mut DBOptionsOpaque,
                                                               memtable_memory_budget: uint64_t);
    pub fn rocksdb_options_set_compaction_filter(arg1: *mut DBOptionsOpaque, arg2: *mut DBCompactionFilterOpaque);
    pub fn rocksdb_options_set_compaction_filter_factory(arg1: *mut DBOptionsOpaque,
                                                         arg2: *mut DBCompactionFilterFactoryOpaque);
    pub fn rocksdb_options_compaction_readahead_size(arg1: *mut DBOptionsOpaque,
                                                     arg2: size_t);
    pub fn rocksdb_options_set_comparator(arg1: *mut DBOptionsOpaque,
                                          arg2: *mut DBComparatorOpaque);
    pub fn rocksdb_options_set_merge_operator(arg1: *mut DBOptionsOpaque,
                                              arg2: *mut DBMergeOperatorOpaque);
    pub fn rocksdb_options_set_uint64add_merge_operator(arg1: *mut DBOptionsOpaque);
    pub fn rocksdb_options_set_compression_per_level(opt: *mut DBOptionsOpaque,
                                                     level_values: *mut c_int,
                                                     num_levels: size_t);
    pub fn rocksdb_options_set_create_if_missing(arg1: *mut DBOptionsOpaque,
                                                 arg2: c_uchar);
    pub fn rocksdb_options_set_create_missing_column_families(arg1: *mut DBOptionsOpaque, arg2: c_uchar);
    pub fn rocksdb_options_set_error_if_exists(arg1: *mut DBOptionsOpaque,
                                               arg2: c_uchar);
    pub fn rocksdb_options_set_paranoid_checks(arg1: *mut DBOptionsOpaque,
                                               arg2: c_uchar);
    pub fn rocksdb_options_set_env(arg1: *mut DBOptionsOpaque,
                                   arg2: *mut DBEnvOpaque);
    pub fn rocksdb_options_set_info_log(arg1: *mut DBOptionsOpaque,
                                        arg2: *mut DBLoggerOpaque);
    pub fn rocksdb_options_set_info_log_level(arg1: *mut DBOptionsOpaque,
                                              arg2: c_int);
    pub fn rocksdb_options_set_write_buffer_size(arg1: *mut DBOptionsOpaque,
                                                 arg2: size_t);
    pub fn rocksdb_options_set_db_write_buffer_size(arg1: *mut DBOptionsOpaque,
                                                    arg2: size_t);
    pub fn rocksdb_options_set_max_open_files(arg1: *mut DBOptionsOpaque,
                                              arg2: c_int);
    pub fn rocksdb_options_set_max_total_wal_size(opt: *mut DBOptionsOpaque,
                                                  n: uint64_t);
    pub fn rocksdb_options_set_compression_options(arg1: *mut DBOptionsOpaque,
                                                   arg2: c_int,
                                                   arg3: c_int,
                                                   arg4: c_int,
                                                   arg5: c_int);
    pub fn rocksdb_options_set_prefix_extractor(arg1: *mut DBOptionsOpaque, arg2: *mut DBSliceTransformOpaque);
    pub fn rocksdb_options_set_num_levels(arg1: *mut DBOptionsOpaque,
                                          arg2: c_int);
    pub fn rocksdb_options_set_level0_file_num_compaction_trigger(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_level0_slowdown_writes_trigger(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_level0_stop_writes_trigger(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_max_mem_compaction_level(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_target_file_size_base(arg1: *mut DBOptionsOpaque,
                                                     arg2: uint64_t);
    pub fn rocksdb_options_set_target_file_size_multiplier(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_max_bytes_for_level_base(arg1: *mut DBOptionsOpaque, arg2: uint64_t);
    pub fn rocksdb_options_set_max_bytes_for_level_multiplier(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_expanded_compaction_factor(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_max_grandparent_overlap_factor(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_max_bytes_for_level_multiplier_additional(arg1: *mut DBOptionsOpaque,
                                                                         level_values: *mut c_int,
                                                                         num_levels: size_t);
    pub fn rocksdb_options_enable_statistics(arg1: *mut DBOptionsOpaque);
    pub fn rocksdb_options_statistics_get_string(opt: *mut DBOptionsOpaque)
                                                 -> *mut c_char;
    pub fn rocksdb_options_set_max_write_buffer_number(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_min_write_buffer_number_to_merge(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_max_write_buffer_number_to_maintain(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_max_background_compactions(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_max_background_flushes(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_max_log_file_size(arg1: *mut DBOptionsOpaque,
                                                 arg2: size_t);
    pub fn rocksdb_options_set_log_file_time_to_roll(arg1: *mut DBOptionsOpaque,
                                                     arg2: size_t);
    pub fn rocksdb_options_set_keep_log_file_num(arg1: *mut DBOptionsOpaque,
                                                 arg2: size_t);
    pub fn rocksdb_options_set_recycle_log_file_num(arg1: *mut DBOptionsOpaque,
                                                    arg2: size_t);
    pub fn rocksdb_options_set_soft_rate_limit(arg1: *mut DBOptionsOpaque,
                                               arg2: c_double);
    pub fn rocksdb_options_set_hard_rate_limit(arg1: *mut DBOptionsOpaque,
                                               arg2: c_double);
    pub fn rocksdb_options_set_rate_limit_delay_max_milliseconds(arg1: *mut DBOptionsOpaque, arg2: c_uint);
    pub fn rocksdb_options_set_max_manifest_file_size(arg1: *mut DBOptionsOpaque, arg2: size_t);
    pub fn rocksdb_options_set_table_cache_numshardbits(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_table_cache_remove_scan_count_limit(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_arena_block_size(arg1: *mut DBOptionsOpaque,
                                                arg2: size_t);
    pub fn rocksdb_options_set_use_fsync(arg1: *mut DBOptionsOpaque,
                                         arg2: c_int);
    pub fn rocksdb_options_set_db_log_dir(arg1: *mut DBOptionsOpaque,
                                          arg2: *const c_char);
    pub fn rocksdb_options_set_wal_dir(arg1: *mut DBOptionsOpaque,
                                       arg2: *const c_char);
    pub fn rocksdb_options_set_WAL_ttl_seconds(arg1: *mut DBOptionsOpaque,
                                               arg2: uint64_t);
    pub fn rocksdb_options_set_WAL_size_limit_MB(arg1: *mut DBOptionsOpaque,
                                                 arg2: uint64_t);
    pub fn rocksdb_options_set_manifest_preallocation_size(arg1: *mut DBOptionsOpaque, arg2: size_t);
    pub fn rocksdb_options_set_purge_redundant_kvs_while_flush(arg1: *mut DBOptionsOpaque, arg2: c_uchar);
    pub fn rocksdb_options_set_allow_os_buffer(arg1: *mut DBOptionsOpaque,
                                               arg2: c_uchar);
    pub fn rocksdb_options_set_allow_mmap_reads(arg1: *mut DBOptionsOpaque,
                                                arg2: c_uchar);
    pub fn rocksdb_options_set_allow_mmap_writes(arg1: *mut DBOptionsOpaque,
                                                 arg2: c_uchar);
    pub fn rocksdb_options_set_is_fd_close_on_exec(arg1: *mut DBOptionsOpaque,
                                                   arg2: c_uchar);
    pub fn rocksdb_options_set_skip_log_error_on_recovery(arg1: *mut DBOptionsOpaque, arg2: c_uchar);
    pub fn rocksdb_options_set_stats_dump_period_sec(arg1: *mut DBOptionsOpaque,
                                                     arg2: c_uint);
    pub fn rocksdb_options_set_advise_random_on_open(arg1: *mut DBOptionsOpaque,
                                                     arg2: c_uchar);
    pub fn rocksdb_options_set_access_hint_on_compaction_start(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_use_adaptive_mutex(arg1: *mut DBOptionsOpaque,
                                                  arg2: c_uchar);
    pub fn rocksdb_options_set_bytes_per_sync(arg1: *mut DBOptionsOpaque,
                                              arg2: uint64_t);
    pub fn rocksdb_options_set_verify_checksums_in_compaction(arg1: *mut DBOptionsOpaque, arg2: c_uchar);
    pub fn rocksdb_options_set_filter_deletes(arg1: *mut DBOptionsOpaque,
                                              arg2: c_uchar);
    pub fn rocksdb_options_set_max_sequential_skip_in_iterations(arg1: *mut DBOptionsOpaque, arg2: uint64_t);
    pub fn rocksdb_options_set_disable_data_sync(arg1: *mut DBOptionsOpaque,
                                                 arg2: c_int);
    pub fn rocksdb_options_set_disable_auto_compactions(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_set_delete_obsolete_files_period_micros(arg1: *mut DBOptionsOpaque, arg2: uint64_t);
    pub fn rocksdb_options_set_source_compaction_factor(arg1: *mut DBOptionsOpaque, arg2: c_int);
    pub fn rocksdb_options_prepare_for_bulk_load(arg1: *mut DBOptionsOpaque);
    pub fn rocksdb_options_set_memtable_vector_rep(arg1: *mut DBOptionsOpaque);
    pub fn rocksdb_options_set_hash_skip_list_rep(arg1: *mut DBOptionsOpaque,
                                                  arg2: size_t,
                                                  arg3: int32_t,
                                                  arg4: int32_t);
    pub fn rocksdb_options_set_hash_link_list_rep(arg1: *mut DBOptionsOpaque,
                                                  arg2: size_t);
    pub fn rocksdb_options_set_plain_table_factory(arg1: *mut DBOptionsOpaque,
                                                   arg2: uint32_t,
                                                   arg3: c_int,
                                                   arg4: c_double,
                                                   arg5: size_t);
    pub fn rocksdb_options_set_min_level_to_compress(opt: *mut DBOptionsOpaque,
                                                     level: c_int);
    pub fn rocksdb_options_set_memtable_prefix_bloom_bits(arg1: *mut DBOptionsOpaque, arg2: uint32_t);
    pub fn rocksdb_options_set_memtable_prefix_bloom_probes(arg1: *mut DBOptionsOpaque, arg2: uint32_t);
    pub fn rocksdb_options_set_memtable_prefix_bloom_huge_page_tlb_size(arg1: *mut DBOptionsOpaque, arg2: size_t);
    pub fn rocksdb_options_set_max_successive_merges(arg1: *mut DBOptionsOpaque,
                                                     arg2: size_t);
    pub fn rocksdb_options_set_min_partial_merge_operands(arg1: *mut DBOptionsOpaque, arg2: uint32_t);
    pub fn rocksdb_options_set_bloom_locality(arg1: *mut DBOptionsOpaque,
                                              arg2: uint32_t);
    pub fn rocksdb_options_set_inplace_update_support(arg1: *mut DBOptionsOpaque, arg2: c_uchar);
    pub fn rocksdb_options_set_inplace_update_num_locks(arg1: *mut DBOptionsOpaque, arg2: size_t);
    pub fn rocksdb_options_set_report_bg_io_stats(arg1: *mut DBOptionsOpaque,
                                                  arg2: c_int);
    pub fn rocksdb_options_set_compression(arg1: *mut DBOptionsOpaque,
                                           arg2: c_int);
    pub fn rocksdb_options_set_compaction_style(arg1: *mut DBOptionsOpaque,
                                                arg2: c_int);
    pub fn rocksdb_options_set_universal_compaction_options(arg1: *mut DBOptionsOpaque,
                                                            arg2: *mut DBUniversalCompactionOptionsOpaque);
    pub fn rocksdb_options_set_fifo_compaction_options(opt: *mut DBOptionsOpaque,
                                                       fifo: *mut DBFifoCompactionOptionsOpaque);
    pub fn rocksdb_compactionfilter_create(state: *mut c_void,
                                           destructor: Option<DBDestructFn>,
                                           filter: Option<DBCompactionFilterFn>,
                                           name: Option<DBGetNameFn>)
                                           -> *mut DBCompactionFilterOpaque;
    pub fn rocksdb_compactionfilter_destroy(arg1: *mut DBCompactionFilterOpaque);
    pub fn rocksdb_compactionfiltercontext_is_full_compaction(context: *mut DBCompactionFilterContextOpaque) -> c_uchar;
    pub fn rocksdb_compactionfiltercontext_is_manual_compaction(context: *mut DBCompactionFilterContextOpaque)
                                                                -> c_uchar;
    pub fn rocksdb_compactionfilterfactory_create
        (state: *mut c_void,
         destructor: Option<DBDestructFn>,
         create_compaction_filter: Option<DBCompactionFilterFactoryFn>,
         name: Option<DBGetNameFn>)
         -> *mut DBCompactionFilterFactoryOpaque;
    pub fn rocksdb_compactionfilterfactory_destroy(arg1: *mut DBCompactionFilterFactoryOpaque);
    pub fn rocksdb_comparator_create(state: *mut c_void,
                                     destructor: Option<DBDestructFn>,
                                     compare: Option<DBCompareFn>,
                                     name: Option<DBGetNameFn>)
                                     -> *mut DBComparatorOpaque;
    pub fn rocksdb_comparator_destroy(arg1: *mut DBComparatorOpaque);
    pub fn rocksdb_filterpolicy_create(state: *mut c_void,
                                       destructor: Option<DBDestructFn>,
                                       create_filter: Option<DBFilterPolicyFactoryFn>,
                                       key_may_match: Option<DBFilterPolicyKeyMayMatchFn>,
                                       delete_filter: Option<DBDeleteFn>,
                                       name: Option<DBGetNameFn>)
                                       -> *mut DBFilterPolicyOpaque;
    pub fn rocksdb_filterpolicy_destroy(arg1: *mut DBFilterPolicyOpaque);
    pub fn rocksdb_filterpolicy_create_bloom(bits_per_key: c_int)
                                             -> *mut DBFilterPolicyOpaque;
    pub fn rocksdb_filterpolicy_create_bloom_full
        (bits_per_key: c_int)
         -> *mut DBFilterPolicyOpaque;
    pub fn rocksdb_mergeoperator_create(state: *mut c_void,
                                        destructor: Option<DBDestructFn>,
                                        full_merge: Option<DBMergeFullMergeFn>,
                                        partial_merge: Option<DBMergePartialMergeFn>,
                                        delete_value: Option<DBDeleteFn>,
                                        name: Option<DBGetNameFn>)
                                        -> *mut DBMergeOperatorOpaque;
    pub fn rocksdb_mergeoperator_destroy(arg1: *mut DBMergeOperatorOpaque);
    pub fn rocksdb_readoptions_create() -> *mut DBReadOptionsOpaque;
    pub fn rocksdb_readoptions_destroy(arg1: *mut DBReadOptionsOpaque);
    pub fn rocksdb_readoptions_set_verify_checksums(arg1: *mut DBReadOptionsOpaque, arg2: c_uchar);
    pub fn rocksdb_readoptions_set_fill_cache(arg1: *mut DBReadOptionsOpaque,
                                              arg2: c_uchar);
    pub fn rocksdb_readoptions_set_snapshot(arg1: *mut DBReadOptionsOpaque,
                                            arg2: *const DBSnapshotOpaque);
    pub fn rocksdb_readoptions_set_iterate_upper_bound(arg1: *mut DBReadOptionsOpaque,
                                                       key: *const c_char,
                                                       keylen: size_t);
    pub fn rocksdb_readoptions_set_read_tier(arg1: *mut DBReadOptionsOpaque,
                                             arg2: c_int);
    pub fn rocksdb_readoptions_set_tailing(arg1: *mut DBReadOptionsOpaque,
                                           arg2: c_uchar);
    pub fn rocksdb_writeoptions_create() -> *mut DBWriteOptionsOpaque;
    pub fn rocksdb_writeoptions_destroy(arg1: *mut DBWriteOptionsOpaque);
    pub fn rocksdb_writeoptions_set_sync(arg1: *mut DBWriteOptionsOpaque,
                                         arg2: c_uchar);
    pub fn rocksdb_writeoptions_disable_WAL(opt: *mut DBWriteOptionsOpaque,
                                            disable: c_int);
    pub fn rocksdb_flushoptions_create() -> *mut DBFlushOptionsOpaque;
    pub fn rocksdb_flushoptions_destroy(arg1: *mut DBFlushOptionsOpaque);
    pub fn rocksdb_flushoptions_set_wait(arg1: *mut DBFlushOptionsOpaque,
                                         arg2: c_uchar);
    pub fn rocksdb_cache_create_lru(capacity: size_t) -> *mut DBCacheOpaque;
    pub fn rocksdb_cache_destroy(cache: *mut DBCacheOpaque);
    pub fn rocksdb_create_default_env() -> *mut DBEnvOpaque;
    pub fn rocksdb_create_mem_env() -> *mut DBEnvOpaque;
    pub fn rocksdb_env_set_background_threads(env: *mut DBEnvOpaque,
                                              n: c_int);
    pub fn rocksdb_env_set_high_priority_background_threads(env: *mut DBEnvOpaque, n: c_int);
    pub fn rocksdb_env_join_all_threads(env: *mut DBEnvOpaque);
    pub fn rocksdb_env_destroy(arg1: *mut DBEnvOpaque);
    pub fn rocksdb_slicetransform_create(state: *mut c_void,
                                         destructor: Option<DBDestructFn>,
                                         transform: Option<DBSliceTransformFn>,
                                         in_domain: Option<DBSliceFilterFn>,
                                         in_range: Option<DBSliceFilterFn>,
                                         name: Option<DBGetNameFn>)
                                         -> *mut DBSliceTransformOpaque;
    pub fn rocksdb_slicetransform_create_fixed_prefix
        (arg1: size_t)
         -> *mut DBSliceTransformOpaque;
    pub fn rocksdb_slicetransform_create_noop
        ()
        -> *mut DBSliceTransformOpaque;
    pub fn rocksdb_slicetransform_destroy(arg1: *mut DBSliceTransformOpaque);
    pub fn rocksdb_universal_compaction_options_create
        ()
        -> *mut DBUniversalCompactionOptionsOpaque;
    pub fn rocksdb_universal_compaction_options_set_size_ratio(arg1: *mut DBUniversalCompactionOptionsOpaque,
                                                               arg2: c_int);
    pub fn rocksdb_universal_compaction_options_set_min_merge_width(arg1: *mut DBUniversalCompactionOptionsOpaque,
                                                                    arg2: c_int);
    pub fn rocksdb_universal_compaction_options_set_max_merge_width(arg1: *mut DBUniversalCompactionOptionsOpaque,
                                                                    arg2: c_int);
    pub fn rocksdb_universal_compaction_options_set_max_size_amplification_percent
        (arg1: *mut DBUniversalCompactionOptionsOpaque,
         arg2: c_int);
    pub fn rocksdb_universal_compaction_options_set_compression_size_percent
        (arg1: *mut DBUniversalCompactionOptionsOpaque,
         arg2: c_int);
    pub fn rocksdb_universal_compaction_options_set_stop_style(arg1: *mut DBUniversalCompactionOptionsOpaque,
                                                               arg2: c_int);
    pub fn rocksdb_universal_compaction_options_destroy(arg1: *mut DBUniversalCompactionOptionsOpaque);
    pub fn rocksdb_fifo_compaction_options_create
        ()
        -> *mut DBFifoCompactionOptionsOpaque;
    pub fn rocksdb_fifo_compaction_options_set_max_table_files_size(fifo_opts: *mut DBFifoCompactionOptionsOpaque,
                                                                    size: uint64_t);
    pub fn rocksdb_fifo_compaction_options_destroy(fifo_opts: *mut DBFifoCompactionOptionsOpaque);
    pub fn rocksdb_livefiles_count(arg1: *const DBLiveFilesOpaque) -> c_int;
    pub fn rocksdb_livefiles_name(arg1: *const DBLiveFilesOpaque,
                                  index: c_int)
                                  -> *const c_char;
    pub fn rocksdb_livefiles_level(arg1: *const DBLiveFilesOpaque,
                                   index: c_int)
                                   -> c_int;
    pub fn rocksdb_livefiles_size(arg1: *const DBLiveFilesOpaque,
                                  index: c_int)
                                  -> size_t;
    pub fn rocksdb_livefiles_smallestkey(arg1: *const DBLiveFilesOpaque,
                                         index: c_int,
                                         size: *mut size_t)
                                         -> *const c_char;
    pub fn rocksdb_livefiles_largestkey(arg1: *const DBLiveFilesOpaque,
                                        index: c_int,
                                        size: *mut size_t)
                                        -> *const c_char;
    pub fn rocksdb_livefiles_destroy(arg1: *const DBLiveFilesOpaque);
    pub fn rocksdb_get_options_from_string(base_options: *const DBOptionsOpaque,
                                           opts_str: *const c_char,
                                           new_options: *mut DBOptionsOpaque,
                                           errptr: *mut *const c_char);
    pub fn rocksdb_delete_file_in_range(db: *mut DBInstanceOpaque,
                                        start_key: *const c_char,
                                        start_key_len: size_t,
                                        limit_key: *const c_char,
                                        limit_key_len: size_t,
                                        errptr: *mut *const c_char);
    pub fn rocksdb_delete_file_in_range_cf(db: *mut DBInstanceOpaque,
                                           column_family: *mut DBCFHandleOpaque,
                                           start_key: *const c_char,
                                           start_key_len: size_t,
                                           limit_key: *const c_char,
                                           limit_key_len: size_t,
                                           errptr: *mut *const c_char);
    pub fn rocksdb_free(ptr: *mut c_void);
}

#[test]
fn internal() {
    unsafe {
        use std::ffi::CString;
        let opts = rocksdb_options_create();
        assert!(!opts.is_null());

        rocksdb_options_increase_parallelism(opts, 0);
        rocksdb_options_optimize_level_style_compaction(opts, 0);
        rocksdb_options_set_create_if_missing(opts, 1);

        let rustpath = "_rust_rocksdb_internaltest";
        let cpath = CString::new(rustpath).unwrap();
        let cpath_ptr = cpath.as_ptr();

        let mut err: *const i8 = 0 as *const i8;
        let err_ptr: *mut *const i8 = &mut err;
        let db = rocksdb_open(opts, cpath_ptr as *const _, err_ptr);
        if !err.is_null() {
            println!("failed to open rocksdb: {}", error_message(err));
        }
        assert!(err.is_null());

        let writeopts = rocksdb_writeoptions_create();
        assert!(!writeopts.is_null());

        let key = b"name\x00";
        let val = b"spacejam\x00";
        rocksdb_put(db,
                    writeopts.clone(),
                    key.as_ptr() as *const c_char,
                    4,
                    val.as_ptr() as *const c_char,
                    8,
                    err_ptr);
        rocksdb_writeoptions_destroy(writeopts);
        assert!(err.is_null());

        let readopts = rocksdb_readoptions_create();
        assert!(!readopts.is_null());

        let val_len: size_t = 0;
        let val_len_ptr = &val_len as *const size_t;
        rocksdb_get(db,
                    readopts.clone(),
                    key.as_ptr() as *const c_char,
                    4,
                    val_len_ptr as *mut size_t,
                    err_ptr);
        rocksdb_readoptions_destroy(readopts);
        assert!(err.is_null());
        rocksdb_close(db);
        rocksdb_destroy_db(opts, cpath_ptr as *const _, err_ptr);
        assert!(err.is_null());
    }
}
