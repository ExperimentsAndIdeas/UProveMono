The U-Prove Extensions SDK implements extensions to the U-Prove Cryptographic Specification [1]. The U-Prove C# SDK [2] is needed to compile the extensions; it must be obtained and referenced by each project. 

The solution contains the following extensions:
o	ID Escrow: allows an Auditor to de-anonymize a fraudulent user by decrypting a user-provided verifiably-encrypted identity.
o	Accumulator designated-verifier revocation: provides efficient constant-size and time revocation.
o	Collaborative issuance: allows the issuance of attributes unknown to the Issuer, which can be copied from another token.
o	PolyProof: provides more flexible proof types, allowing a user to prove that an undisclosed attribute is part of a set, part of an interval, is equal to another undisclosed value (which could be an attribute from a different token), or is not equal to a target value.

For more information about the extensions and the U-Prove technology, please visit http://www.microsoft.com/uprove. 

[1] http://research.microsoft.com/apps/pubs/default.aspx?id=166969
[2] https://uprovecsharp.codeplex.com/
