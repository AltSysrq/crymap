//-
// Copyright (c) 2023, Jason Lingle
//
// This file is part of Crymap.
//
// Crymap is free software: you can  redistribute it and/or modify it under the
// terms of  the GNU General Public  License as published by  the Free Software
// Foundation, either version  3 of the License, or (at  your option) any later
// version.
//
// Crymap is distributed  in the hope that  it will be useful,  but WITHOUT ANY
// WARRANTY; without  even the implied  warranty of MERCHANTABILITY  or FITNESS
// FOR  A PARTICULAR  PURPOSE.  See the  GNU General  Public  License for  more
// details.
//
// You should have received a copy of the GNU General Public License along with
// Crymap. If not, see <http://www.gnu.org/licenses/>.

//! The SQLite XEX encryption shim VFS layer.

use std::cell::UnsafeCell;
use std::convert::TryFrom;
use std::ffi::{CStr, CString, OsStr};
use std::mem::{self, ManuallyDrop};
use std::os::raw::{c_char, c_int, c_void};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use libsqlite3_sys::*;
use log::error;

use crate::{
    crypt::{master_key::MasterKey, xex},
    support::error::Error,
};

/// A SQLite VFS layer for XEX encryption.
///
/// Each `XexVfs` instance holds on to a single `MasterKey` which is used for
/// all derivative operations. The name of the VFS is generated using a simple
/// numeric sequence, so that SQLite URLs do not contain secrets.
///
/// The VFS is unregistered when the `XexVfs` is dropped and all files are
/// closed.
pub struct XexVfs {
    wrapper: Arc<VfsWrapper>,
}

impl XexVfs {
    /// Sets up a new XEX VFS using the given master key for encryption.
    pub fn new(master_key: Arc<MasterKey>) -> Result<Self, Error> {
        let delegate_vfs = unsafe { sqlite3_vfs_find(ptr::null()) };
        if delegate_vfs.is_null() {
            return Err(Error::Sqlite(SQLITE_NOTFOUND));
        }

        // Safety: we now know that the VFS is non-null.
        let delegate_vfs = unsafe { &mut *delegate_vfs };

        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let name = CString::new(format!("xex{seq}")).unwrap();

        // There are no possible panics between this and making `VfsWrapper`
        // the owner of the box (via `pAppData`).
        let app_data = Box::into_raw(Box::new(VfsAppData {
            master_key,
            wrapper: Weak::new(),
            delegate_vfs,
        }));

        let raw_vfs = sqlite3_vfs {
            iVersion: 2, // Everything but the system call API
            szOsFile: mem::size_of::<File>() as c_int,
            mxPathname: delegate_vfs.mxPathname,
            pNext: ptr::null_mut(),
            zName: name.as_ptr(),
            pAppData: app_data.cast(),
            xOpen: Some(vfs_open),
            xDelete: Some(vfs_delete),
            xAccess: Some(vfs_access),
            xFullPathname: Some(vfs_full_pathname),
            xDlOpen: None,
            xDlError: None,
            xDlSym: None,
            xDlClose: None,
            xRandomness: delegate_vfs
                .xRandomness
                .is_some()
                .then_some(vfs_randomness),
            xSleep: delegate_vfs.xSleep.is_some().then_some(vfs_sleep),
            xCurrentTime: delegate_vfs
                .xCurrentTime
                .is_some()
                .then_some(vfs_current_time),
            xGetLastError: delegate_vfs
                .xGetLastError
                .is_some()
                .then_some(vfs_get_last_error),
            xCurrentTimeInt64: delegate_vfs
                .xCurrentTimeInt64
                .is_some()
                .then_some(vfs_current_time_int64),
            xSetSystemCall: None,
            xGetSystemCall: None,
            xNextSystemCall: None,
        };

        let wrapper = Arc::new(VfsWrapper {
            vfs: UnsafeCell::new(raw_vfs),
            name,
        });

        // Safety: The box isn't dropped until `wrapper`'s inner value is.
        unsafe {
            (*app_data).wrapper = Arc::downgrade(&wrapper);
        }

        // Safety: wrapper.vfs won't move since it's behind an Arc, and
        // VfsWrapper only unregisters itself when dropped, at which point we
        // know that SQLite has no remaining paths to the VFS.
        let err = unsafe {
            sqlite3_vfs_register(UnsafeCell::raw_get(&wrapper.vfs), 0)
        };
        if 0 != err {
            return Err(Error::Sqlite(err));
        }

        Ok(Self { wrapper })
    }

    /// Returns the VFS name of this instance.
    pub fn name(&self) -> &str {
        self.wrapper.name.to_str().unwrap()
    }
}

/// Wraps a `sqlite3_vfs`, adding some convenience methods and unregistering
/// the VFS when it is dropped.
///
/// It must be inside an `Arc` so that it is not dropped until all references
/// are gone.
struct VfsWrapper {
    vfs: UnsafeCell<sqlite3_vfs>,
    /// The SQLite name of the VFS. `vfs` holds a raw pointer to the content.
    name: CString,
}

// Safety: None of this code accesses any of the fields under `vfs` except
// those which are constant post-construction, and those fields are Send +
// Sync.
unsafe impl Send for VfsWrapper {}
unsafe impl Sync for VfsWrapper {}

/// The content of `sqlite3_vfs::pAppData` (inside a `Box`).
struct VfsAppData {
    master_key: Arc<MasterKey>,
    /// A pointer back to the `VfsWrapper`. Each file opened promotes this to a
    /// strong reference to ensure the VFS is not deleted if there are still
    /// open files.
    wrapper: Weak<VfsWrapper>,
    /// The default SQLite VFS used as a delegate.
    delegate_vfs: *mut sqlite3_vfs,
}

/// A subclass of `sqlite3_file` produced by our VFS.
#[repr(C)]
struct File {
    base_class: sqlite3_file,
    delegate_file: *mut sqlite3_file,
    delegate_vfs: *mut sqlite3_vfs,
    xex: xex::Xex,
    /// Ensure the VFS does not get dropped while the file is open.
    vfs_wrapper: Arc<VfsWrapper>,
}

impl Drop for VfsWrapper {
    fn drop(&mut self) {
        unsafe {
            let vfs = UnsafeCell::raw_get(&self.vfs);
            sqlite3_vfs_unregister(vfs);
            if !(*vfs).pAppData.is_null() {
                let _ = Box::<VfsAppData>::from_raw((*vfs).pAppData.cast());
            }
        }
    }
}

macro_rules! invoke_file_delegate {
    ($this:ident->$method:ident($($arg:expr),* $(,)*)) => {{
        let delegate: &mut sqlite3_file = &mut *$this.delegate_file;
        let io_methods: &sqlite3_io_methods = &*delegate.pMethods;
        if let Some(f) = io_methods.$method {
            f(delegate $(,$arg)*)
        } else {
            0
        }
    }}
}

macro_rules! invoke_vfs_delegate {
    ($this:ident->$method:ident($($arg:expr),* $(,)*)) => {{
        let delegate: &mut sqlite3_vfs = &mut *$this.delegate_vfs;
        if let Some(f) = delegate.$method {
            f(delegate $(,$arg)*)
        } else {
            SQLITE_NOTFOUND
        }
    }}
}

struct DelegateBacking {
    delegate_file: *mut sqlite3_file,
}

impl xex::Backing for DelegateBacking {
    type Error = c_int;

    fn read(&mut self, dst: &mut [u8], offset: u64) -> Result<(), c_int> {
        let dst_len =
            c_int::try_from(dst.len()).map_err(|_| SQLITE_IOERR_READ)?;
        let offset = i64::try_from(offset).map_err(|_| SQLITE_IOERR_SEEK)?;

        unsafe {
            zero_or_err(invoke_file_delegate!(self->xRead(
                dst.as_mut_ptr().cast(),
                dst_len,
                offset,
            )))
        }
    }

    fn write(&mut self, src: &[u8], offset: u64) -> Result<(), c_int> {
        let src_len =
            c_int::try_from(src.len()).map_err(|_| SQLITE_IOERR_WRITE)?;
        let offset = i64::try_from(offset).map_err(|_| SQLITE_IOERR_SEEK)?;

        unsafe {
            zero_or_err(invoke_file_delegate!(self->xWrite(
                src.as_ptr().cast(),
                src_len,
                offset,
            )))
        }
    }

    fn len(&mut self) -> Result<u64, c_int> {
        let mut size = 0i64;
        unsafe {
            zero_or_err(invoke_file_delegate!(self->xFileSize(&mut size)))?;
        }

        u64::try_from(size).map_err(|_| SQLITE_IOERR_FSTAT)
    }

    fn encryption_error() -> c_int {
        SQLITE_IOERR_AUTH
    }
}

fn zero_or_err(rc: c_int) -> Result<(), c_int> {
    if 0 == rc {
        Ok(())
    } else {
        Err(rc)
    }
}

unsafe fn vfs_app_data<'a>(vfs: *mut sqlite3_vfs) -> &'a VfsAppData {
    &*(*vfs).pAppData.cast()
}

unsafe extern "C" fn vfs_open(
    vfs: *mut sqlite3_vfs,
    name: *const c_char,
    file: *mut sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    let app_data = vfs_app_data(vfs);
    let Some(vfs_wrapper) = app_data.wrapper.upgrade() else {
        error!("BUG: File opened after VfsWrapper dropped");
        return SQLITE_IOERR_CONVPATH;
    };

    let Some(name_str) = CStr::from_ptr(name.cast())
        .to_str()
        .ok()
        .map(Path::new)
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
    else {
        return SQLITE_IOERR_CONVPATH;
    };

    let xex = match xex::Xex::new(&app_data.master_key, name_str) {
        Ok(xex) => xex,
        Err(err) => {
            error!("BUG: Failed to init XEX: {err:?}");
            return SQLITE_IOERR_AUTH;
        },
    };

    let child_file: *mut sqlite3_file =
        sqlite3_malloc((*app_data.delegate_vfs).szOsFile).cast();

    if child_file.is_null() {
        return SQLITE_NOMEM;
    }

    let err = invoke_vfs_delegate!(
        app_data->xOpen(name, child_file, flags, out_flags));
    if 0 != err {
        sqlite3_free(child_file.cast());
        return err;
    }

    ptr::write(
        file.cast(),
        File {
            base_class: sqlite3_file {
                pMethods: &FILE_IO_METHODS,
            },
            delegate_file: child_file,
            delegate_vfs: app_data.delegate_vfs,
            xex,
            vfs_wrapper,
        },
    );

    0
}

unsafe extern "C" fn vfs_delete(
    vfs: *mut sqlite3_vfs,
    name: *const c_char,
    sync_dir: c_int,
) -> c_int {
    let app_data = vfs_app_data(vfs);
    invoke_vfs_delegate!(app_data->xDelete(name, sync_dir))
}

unsafe extern "C" fn vfs_access(
    vfs: *mut sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    let app_data = vfs_app_data(vfs);
    invoke_vfs_delegate!(app_data->xAccess(name, flags, out))
}

unsafe extern "C" fn vfs_full_pathname(
    vfs: *mut sqlite3_vfs,
    name: *const c_char,
    nout: c_int,
    out: *mut c_char,
) -> c_int {
    let app_data = vfs_app_data(vfs);
    invoke_vfs_delegate!(app_data->xFullPathname(name, nout, out))
}

unsafe extern "C" fn vfs_randomness(
    vfs: *mut sqlite3_vfs,
    n: c_int,
    out: *mut c_char,
) -> c_int {
    let app_data = vfs_app_data(vfs);
    invoke_vfs_delegate!(app_data->xRandomness(n, out))
}

unsafe extern "C" fn vfs_sleep(vfs: *mut sqlite3_vfs, us: c_int) -> c_int {
    let app_data = vfs_app_data(vfs);
    invoke_vfs_delegate!(app_data->xSleep(us))
}

unsafe extern "C" fn vfs_current_time(
    vfs: *mut sqlite3_vfs,
    out: *mut f64,
) -> c_int {
    let app_data = vfs_app_data(vfs);
    invoke_vfs_delegate!(app_data->xCurrentTime(out))
}

unsafe extern "C" fn vfs_get_last_error(
    vfs: *mut sqlite3_vfs,
    arg2: c_int,
    arg3: *mut c_char,
) -> c_int {
    let app_data = vfs_app_data(vfs);
    invoke_vfs_delegate!(app_data->xGetLastError(arg2, arg3))
}

unsafe extern "C" fn vfs_current_time_int64(
    vfs: *mut sqlite3_vfs,
    out: *mut i64,
) -> c_int {
    let app_data = vfs_app_data(vfs);
    invoke_vfs_delegate!(app_data->xCurrentTimeInt64(out))
}

impl Drop for File {
    fn drop(&mut self) {
        unsafe {
            sqlite3_free(self.delegate_file.cast());
        }
        self.delegate_file = ptr::null_mut();
    }
}

unsafe extern "C" fn file_close(f: *mut sqlite3_file) -> c_int {
    let f: &mut ManuallyDrop<File> = &mut *f.cast();
    let err = invoke_file_delegate!(f->xClose());
    ManuallyDrop::drop(f);
    err
}

unsafe extern "C" fn file_read(
    f: *mut sqlite3_file,
    dst: *mut c_void,
    len: c_int,
    offset: i64,
) -> c_int {
    let f: &mut File = &mut *f.cast();
    let Ok(len) = usize::try_from(len) else {
        return SQLITE_IOERR_READ;
    };
    let Ok(offset) = u64::try_from(offset) else {
        return SQLITE_IOERR_SEEK;
    };

    let dst = std::slice::from_raw_parts_mut(dst.cast::<u8>(), len);

    let mut backing = DelegateBacking {
        delegate_file: f.delegate_file,
    };

    match f.xex.read(&mut backing, dst, offset) {
        Ok(()) => 0,
        Err(SQLITE_IOERR_SHORT_READ) => {
            // This is an awkward case. SQLite expects to be able to use the
            // prefix of the data that was read, but there's no way for us to
            // actually know where the data ends. Why, exactly, they decided
            // that xRead shouldn't return the amount read is unclear. In any
            // case, manually determine how much should have been read and make
            // another attempt to read just that amount.
            //
            // (We can't use the same trick SQLite does of just looking where
            // the data seems to end, because that would require distinguishing
            // a block of zeroes from encrypted data.)
            let Ok(file_len) = xex::Backing::len(&mut backing) else {
                return SQLITE_IOERR_SEEK;
            };

            let read_amount = usize::try_from(file_len.saturating_sub(offset))
                .unwrap_or(dst.len())
                .min(dst.len());
            if let Err(err) =
                f.xex.read(&mut backing, &mut dst[..read_amount], offset)
            {
                // SHORT_READ is entirely unexpected here. If we get it, we
                // can't fulfil our duties, so give up entirely.
                if SQLITE_IOERR_SHORT_READ == err {
                    return SQLITE_IOERR_READ;
                } else {
                    return err;
                }
            }

            // Special-case requirement for SHORT_READ: fill the unread portion
            // of the buffer with zeroes.
            dst[read_amount..].fill(0);
            SQLITE_IOERR_SHORT_READ
        },
        Err(err) => err,
    }
}

unsafe extern "C" fn file_write(
    f: *mut sqlite3_file,
    src: *const c_void,
    len: c_int,
    offset: i64,
) -> c_int {
    let f: &mut File = &mut *f.cast();
    let Ok(len) = usize::try_from(len) else {
        return SQLITE_IOERR_WRITE;
    };
    let Ok(offset) = u64::try_from(offset) else {
        return SQLITE_IOERR_SEEK;
    };

    let src = std::slice::from_raw_parts(src.cast::<u8>(), len);

    let mut backing = DelegateBacking {
        delegate_file: f.delegate_file,
    };

    f.xex.write(&mut backing, src, offset).err().unwrap_or(0)
}

unsafe extern "C" fn file_truncate(
    f: *mut sqlite3_file,
    mut size: i64,
) -> c_int {
    // We can't truncate into the middle of a block; round up.
    let block_size = crate::crypt::AES_BLOCK as i64;
    size = (size + block_size - 1) / block_size * block_size;

    let f: &mut File = &mut *f.cast();
    invoke_file_delegate!(f->xTruncate(size))
}

unsafe extern "C" fn file_sync(f: *mut sqlite3_file, flags: c_int) -> c_int {
    let f: &mut File = &mut *f.cast();
    invoke_file_delegate!(f->xSync(flags))
}

unsafe extern "C" fn file_file_size(
    f: *mut sqlite3_file,
    dst: *mut i64,
) -> c_int {
    let f: &mut File = &mut *f.cast();
    invoke_file_delegate!(f->xFileSize(dst))
}

unsafe extern "C" fn file_lock(f: *mut sqlite3_file, i: c_int) -> c_int {
    let f: &mut File = &mut *f.cast();
    invoke_file_delegate!(f->xLock(i))
}

unsafe extern "C" fn file_unlock(f: *mut sqlite3_file, i: c_int) -> c_int {
    let f: &mut File = &mut *f.cast();
    invoke_file_delegate!(f->xUnlock(i))
}

unsafe extern "C" fn file_check_reserved_lock(
    f: *mut sqlite3_file,
    out: *mut c_int,
) -> c_int {
    let f: &mut File = &mut *f.cast();
    invoke_file_delegate!(f->xCheckReservedLock(out))
}

unsafe extern "C" fn file_file_control(
    f: *mut sqlite3_file,
    op: c_int,
    arg: *mut c_void,
) -> c_int {
    let f: &mut File = &mut *f.cast();

    match op {
        SQLITE_FCNTL_LOCKSTATE
        | SQLITE_FCNTL_SIZE_HINT
        | SQLITE_FCNTL_SIZE_LIMIT
        | SQLITE_FCNTL_CHUNK_SIZE
        | SQLITE_FCNTL_SYNC
        | SQLITE_FCNTL_COMMIT_PHASETWO
        | SQLITE_FCNTL_WIN32_AV_RETRY
        | SQLITE_FCNTL_PERSIST_WAL
        | SQLITE_FCNTL_POWERSAFE_OVERWRITE
        | SQLITE_FCNTL_OVERWRITE
        | SQLITE_FCNTL_PRAGMA
        | SQLITE_FCNTL_BUSYHANDLER
        | SQLITE_FCNTL_TRACE
        | SQLITE_FCNTL_HAS_MOVED
        | SQLITE_FCNTL_WAL_BLOCK
        | SQLITE_FCNTL_BEGIN_ATOMIC_WRITE
        | SQLITE_FCNTL_COMMIT_ATOMIC_WRITE
        | SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE
        | SQLITE_FCNTL_LOCK_TIMEOUT
        | SQLITE_FCNTL_CKPT_START
        | SQLITE_FCNTL_CKPT_DONE
        | SQLITE_FCNTL_EXTERNAL_READER => {
            invoke_file_delegate!(f->xFileControl(op, arg))
        },

        SQLITE_FCNTL_VFS_POINTER => {
            *arg.cast::<*mut sqlite3_vfs>() = f.delegate_vfs;
            0
        },

        SQLITE_FCNTL_VFSNAME => {
            // Implementing this would be extremely complicated for basically
            // no benefit. It basically involves doing reallocation + strcat to
            // tack our own name onto the end, except that the delegate is not
            // guaranteed to implement this, so there's extra branches for
            // that. The code also ends up grosser because SQLite likes to use
            // `int` instead of `size_t`.
            SQLITE_NOTFOUND
        },

        _ => SQLITE_NOTFOUND,
    }
}

unsafe extern "C" fn file_sector_size(f: *mut sqlite3_file) -> c_int {
    let f: &mut File = &mut *f.cast();
    invoke_file_delegate!(f->xSectorSize())
}

unsafe extern "C" fn file_device_characteristics(
    f: *mut sqlite3_file,
) -> c_int {
    let f: &mut File = &mut *f.cast();
    let mut dc = invoke_file_delegate!(f->xDeviceCharacteristics());
    // Only writes a multiple of the AES block size can be atomic.
    if 0 != dc & SQLITE_IOCAP_ATOMIC {
        dc &= !SQLITE_IOCAP_ATOMIC;
        dc |= SQLITE_IOCAP_ATOMIC512;
    }

    dc
}

unsafe extern "C" fn file_shm_map(
    f: *mut sqlite3_file,
    pg: c_int,
    pgsz: c_int,
    arg: c_int,
    out: *mut *mut c_void,
) -> c_int {
    let f: &mut File = &mut *f.cast();
    invoke_file_delegate!(f->xShmMap(pg, pgsz, arg, out))
}

unsafe extern "C" fn file_shm_lock(
    f: *mut sqlite3_file,
    offset: c_int,
    n: c_int,
    flags: c_int,
) -> c_int {
    let f: &mut File = &mut *f.cast();
    invoke_file_delegate!(f->xShmLock(offset, n, flags))
}

unsafe extern "C" fn file_shm_barrier(f: *mut sqlite3_file) {
    let f: &mut File = &mut *f.cast();
    let delegate: &mut sqlite3_file = &mut *f.delegate_file;
    let io_methods: &sqlite3_io_methods = &*delegate.pMethods;
    if let Some(f) = io_methods.xShmBarrier {
        f(delegate);
    }
}

unsafe extern "C" fn file_shm_unmap(
    f: *mut sqlite3_file,
    delete_flag: c_int,
) -> c_int {
    let f: &mut File = &mut *f.cast();
    invoke_file_delegate!(f->xShmUnmap(delete_flag))
}

static FILE_IO_METHODS: sqlite3_io_methods = sqlite3_io_methods {
    // Only version 2 because we don't implement fetch.
    iVersion: 2,
    xClose: Some(file_close),
    xRead: Some(file_read),
    xWrite: Some(file_write),
    xTruncate: Some(file_truncate),
    xSync: Some(file_sync),
    xFileSize: Some(file_file_size),
    xLock: Some(file_lock),
    xUnlock: Some(file_unlock),
    xCheckReservedLock: Some(file_check_reserved_lock),
    xFileControl: Some(file_file_control),
    xSectorSize: Some(file_sector_size),
    xDeviceCharacteristics: Some(file_device_characteristics),
    // For the SHM methods, our behaviour of "do nothing and return 0"  if the
    // delegate doesn't implement the method isn't really correct.
    //
    // Also, it's unclear whether this does anything sensible anyway, since the
    // mapped memory will reveal different bytes than the basic I/O methods.
    // We'll cross that bridge if we get there.
    //
    // We're also blindly assuming that the delegate is at least version 2,
    // which it should be for the default VFS.
    xShmMap: Some(file_shm_map),
    xShmLock: Some(file_shm_lock),
    xShmBarrier: Some(file_shm_barrier),
    xShmUnmap: Some(file_shm_unmap),
    // Fetch and Unfetch are unsupported because there's no way for us to do
    // memory-mapped I/O.
    xFetch: None,
    xUnfetch: None,
};
