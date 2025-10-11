//! Module to handle information about network interfaces.

use std::fmt::Debug;

/// Converts an network interface index to the name.
/// 
/// This function just uses libc. May be a blocking call.
pub fn index_to_name(index: InterfaceId) -> Result<String, std::io::Error> {
    let index = if let Some(index) = index.inner() {
        index
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface index is unspecified",
        ));
    };
    let ifname_buf = [0u8; libc::IFNAMSIZ];
    let ret = unsafe { libc::if_indextoname(index, ifname_buf.as_ptr() as *mut libc::c_char) };
    if ret.is_null() {
        return Err(std::io::Error::last_os_error());
    }

    let name = unsafe { std::ffi::CStr::from_ptr(ret) }
        .to_str()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
        .to_owned();
    Ok(name)
}

/// Converts a network interface name to the index.
/// 
/// This function just uses libc. May be a blocking call.
pub fn name_to_index(name: &str) -> Result<InterfaceId, std::io::Error> {
    let name = std::ffi::CString::new(name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr() as *const libc::c_char) };
    if index == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(InterfaceId::new(Some(index)))
}

#[derive(Clone, Copy, PartialEq, Hash, Eq)]
pub struct InterfaceId {
    if_index: libc::c_uint,
}

impl InterfaceId {
    pub const UNSPECIFIED: Self = Self { if_index: 0 };

    pub fn new(if_index: Option<libc::c_uint>) -> Self {
        Self { if_index: if_index.unwrap_or(0) }
    }

    pub fn inner(&self) -> Option<libc::c_uint> {
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

impl Debug for InterfaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(id) = self.inner() {
            f.write_str(&format!("InterfaceId({id})"))
        } else {
            f.write_str(&format!("InterfaceId(UNSPECIFIED)"))
        }
    }
}

/// Network interface with its index and name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Interface {
    pub if_id: InterfaceId,
    pub if_name: String,
}

impl Interface {
    pub fn new(if_id: Option<libc::c_uint>, if_name: String) -> Self {
        Self {
            if_id: InterfaceId::new(if_id),
            if_name,
        }
    }
}
