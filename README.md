# Unsealed

Unsealed is an alternative to the seal.java library, but for modern VMs and with no 3rd party dependencies (i.e., Unsealed is based _directly_
on the Java Cryptography API bundled with Java - no 3rd party xml security or saml library is used). 

The focus of Unsealed is to facilitate calling the ticket exchange services that are offered by SOSI STS for use in the danish healthcare sector. 
These are typically needed by web service clients that calls DGWS and IDWS enabled SOAP services. Unsealed provides
a simplified way of invoking the ticket exchange services through an easy-to-use builder pattern. 

NOTE: There is currently very limited support for server side validation!

# Supported exchange operations
- _NewSecurityTokenService_: SOSI Idcard -> STS signed Idcard
- _Sosi2OIOSaml_: STS signed Idcard -> OIOSAML token (SBO token)
- _OIOSaml2Sosi_: OIOSAML token -> idcard
- _BST2SOSI_: Bootstrap token -> OIOSAML token
- _Bst2Idws_: Bootstrap token -> IDWS token 
- _JWT2Idws_: JWT token -> IDWS token
- _JWT2OIOSaml_: JWT token -> OIOSAML token (not yet implemented)

A seconday use of Unsealed is for issuing OIOSAML assertions and bootstrap tokens (OIOSAMLTokenIssuer+BootstrapTokenIssuer). This is primarily intended for test purposes..

# Example usages
See src/test/java/com/trifork/unsealed/*Test.java
