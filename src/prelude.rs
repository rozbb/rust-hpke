//
// Use these dummy mods as a trick to re-export multiple traits at once
//

#[cfg(not(feature = "std"))]
mod reexports {
    pub use alloc::string::String;
    pub use alloc::vec::Vec;
}

#[cfg(feature = "std")]
mod reexports {
    pub use std::string::String;
    pub use std::vec::Vec;
}

pub use self::reexports::*;
