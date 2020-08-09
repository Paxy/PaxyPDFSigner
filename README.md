# PaxyPDFSigner
Simple PDF Signer with PKCS#11 library

PKCS#11 library for PDF signature with JDK14 with all dependances.

Releases: https://github.com/Paxy/PaxyPDFSigner/releases

Usage:
* Extract current version of JAR and CFG file.
* Verify is PKCS#11 library present at the location configured in pkcs11.cfg
* Run signer with 
java -jar PaxyPDFSigner.jar 'path to PDF file'

