#![no_std]

pub mod vlan {
    /// VLAN ID 0 is for the remote IPv6 address of the native VLAN
    pub const VLAN_ID_NATIVE: u16 = 0;

    /// VLAN IDs 1-4094 are for remote IPv6 addresses of the bridged VLANs
    pub const VLAN_ID_MIN: u16 = 1;

    /// VLAN IDs 1-4094 are for remote IPv6 addresses of the bridged VLANs
    pub const VLAN_ID_MAX: u16 = 4094;

    /// 'VLAN ID' 4095 is reserved for the local IPv6 address
    pub const VLAN_ID_LOCAL: u16 = 4095;
}

pub mod iface {
    pub const IF_INDEX_INNER: u32 = 1;
    pub const IF_INDEX_OUTER: u32 = 2;
}

pub mod mac {
    /// MAC address of the local interface
    pub const MAC_ADDR_LOCAL: u32 = 1;

    /// MAC address of the next hop
    pub const MAC_ADDR_GATEWAY: u32 = 2;

    pub fn to_u64(mac: &[u8; 6]) -> u64 {
        let mut mac_u64 = 0u64;
        for i in 0..6 {
            mac_u64 |= (mac[i] as u64) << (i * 8);
        }
        mac_u64
    }

    pub fn from_u64(mac: u64) -> [u8; 6] {
        let mut mac_arr = [0u8; 6];
        for i in 0..6 {
            mac_arr[i] = ((mac >> (i * 8)) & 0xff) as u8;
        }
        mac_arr
    }
}

pub mod ipv6 {
    pub fn to_u128(addr: [u8; 16]) -> u128 {
        u128::from_be_bytes(addr)
    }

    pub fn from_u128(addr: u128) -> [u8; 16] {
        addr.to_be_bytes()
    }
}
