
use std::fmt::Debug;

#[allow(dead_code)]
pub fn index_to_name(index: InterfaceId) -> Result<String, std::io::Error> {
    let index = if let Some(index) = index.inner() {
        index
    } else {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "interface index is unspecified"));
    };
    let ifname_buf = [0u8; libc::IFNAMSIZ];
    let ret = unsafe { libc::if_indextoname(index, ifname_buf.as_ptr() as *mut libc::c_char) };
    if ret.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    
    let name = unsafe { std::ffi::CStr::from_ptr(ret) }.to_str().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?.to_owned();
    Ok(name)
}

pub fn name_to_index(name: &str) -> Result<InterfaceId, std::io::Error> {
    let name = std::ffi::CString::new(name).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr() as *const libc::c_char ) };
    if index == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(InterfaceId::new(index))
}

#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq)]
pub struct InterfaceId {
    if_index: libc::c_uint,
}

#[allow(dead_code)]
impl InterfaceId {
    pub const UNSPECIFIED: Self = Self { if_index: 0 };

    pub(crate) fn new(if_index: libc::c_uint) -> Self {
        Self { if_index }
    }

    pub(crate) fn inner_unchecked(&self) -> libc::c_uint {
        self.if_index
    }

    pub(crate) fn inner(&self) -> Option<libc::c_uint> {
        if self.if_index == 0 {
            None
        } else {
            Some(self.if_index)
        }
    }

    pub fn is_unspecified(&self) -> bool {
        self.if_index == 0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Interface {
    pub if_id: InterfaceId,
    pub if_name: String,
}
