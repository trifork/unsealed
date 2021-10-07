# unsealed
An alternative to the seal.java library, but for modern VMs and with no 3rd party dependencies

# Supported exchange operations
- idcard -> signed idcard OK
- signed idcard -> oiosaml token (SBO token) OK
- oiosaml token -> idcard OK
- bootstrap token -> idws token (newlogin bst -> idws) OK
- jwt token -> idws token NYI
- jwt token -> oiosaml token NYI

