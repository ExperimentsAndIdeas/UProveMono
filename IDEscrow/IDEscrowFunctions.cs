//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

using System;

using UProveCrypto;
using UProveCrypto.Math;

namespace IDEscrow
{

    /// <summary>
    /// Class of static functions for creating ID escrow ciphertexts (with proof),
    /// verifying proofs, and decrypting ciphertexts.
    /// Data types used here are defined in <c>IEDataTypes.cs</c>.
    /// </summary>
    public static class IDEscrowFunctions
    {
        #region Main functions (public)

        /// <summary>
        /// Specifies the random data for the ID escrow proof generation, if provided externally.
        /// </summary>
        public class IDEscrowProofGenerationRandomData
        {
            private FieldZqElement r;
            private FieldZqElement xbPrime;
            private FieldZqElement rPrime;
            private FieldZqElement obPrime;

            /// <summary>
            /// Constructs a new <code>IDEscrowProofGenerationRandomData</code> instance.
            /// </summary>
            /// <param name="r">The <code>r</code> value.</param>
            /// <param name="xbPrime">The <code>xbPrime</code> values.</param>
            /// <param name="rPrime">The <code>rPrime</code> value.</param>
            /// <param name="obPrime">The <code>obPrime</code> value.</param>
            public IDEscrowProofGenerationRandomData(FieldZqElement r, FieldZqElement xbPrime, FieldZqElement rPrime, FieldZqElement obPrime)
            {
                this.r = r;
                this.xbPrime = xbPrime;
                this.rPrime = rPrime;
                this.obPrime = obPrime;
            }

            /// <summary>
            /// Gets the <code>r</code> value.
            /// </summary>
            public FieldZqElement R
            {
                get { return r; }
            }

            /// <summary>
            /// Gets the <code>xbPrime</code> values.
            /// </summary>
            public FieldZqElement XbPrime
            {
                get { return xbPrime; }
            }

            /// <summary>
            /// Gets the <code>rPrime</code> value.
            /// </summary>
            public FieldZqElement RPrime
            {
                get { return rPrime; }
            }

            /// <summary>
            /// Gets the <code>obPrime</code> value.
            /// </summary>
            public FieldZqElement ObPrime
            {
                get { return obPrime; }
            }

            /// <summary>
            /// Clears the object.  Note that this does *not* securely zero the memory.
            /// </summary>
            public void Clear()
            {
                // TODO: This should zero the memory rather than just setting to null.
                //       Challening to do this in C#, so we will need to make this change
                //       as part of a comprehensive future change throughout the library.
                r = null;
                xbPrime = null;
                rPrime = null;
                obPrime = null;
            }

            /// <summary>
            /// Generates a <code>IDEscrowProofGenerationRandomData</code> instance using the internal RNG.
            /// </summary>
            /// <param name="Zq">Field Zq</param>
            /// <returns>A pregenerated set of random values.</returns>
            internal static IDEscrowProofGenerationRandomData Generate(FieldZq Zq)
            {
                return new IDEscrowProofGenerationRandomData(
                    Zq.GetRandomElement(false),
                    Zq.GetRandomElement(false),
                    Zq.GetRandomElement(false),
                    Zq.GetRandomElement(false)
                    );
            }

            public bool HasNullValue()
            {
                if (r == null || rPrime == null || xbPrime == null || obPrime == null)
                    return true;
                else
                    return false;
            }
        }


        /// <summary>
        /// Create a verifiable encryption of a pseudonym based on a U-Prove presentation proof.  This is a wrapper
        /// of <c>VerifiableEncrypt</c>.
        ///
        /// </summary>
        /// <param name="escrowParams"> Parameters of the ID escrow scheme</param>
        /// <param name="escrowPublicKey">  Public key of the Auditor (the authority who can decrypt the output ciphertex).</param>
        /// <param name="token"> The U-Prove token corresponding to the <c>proof</c>. </param>
        /// <param name="additionalInfo">See documentation of <c>VerifiableEncrypt</c></param>
        /// <param name="proof">A U-Prove prsentation proof.</param>
        /// <param name="cpv">Commitment opening information, output when generating <c>proof</c>.</param>
        /// <param name="idAttributeIndex"> Index of the attribute to use for identity escrow (1-based indexing). This attribute <b>must be</b> 
        ///                                 the first commited attribute (take care if using multiple extensions). </param>
        /// <param name="attributes"> Attributes in <c>token</c>.</param>
        
        /// <returns></returns>
        public static IDEscrowCiphertext UProveVerifableEncrypt(IDEscrowParams escrowParams, IDEscrowPublicKey escrowPublicKey, 
            UProveToken token, byte[] additionalInfo, PresentationProof proof, 
            CommitmentPrivateValues cpv, int idAttributeIndex, byte[][] attributes)
        {
            if(token == null || escrowParams == null || proof == null || cpv == null)
                throw new ArgumentNullException("null input to UProveVerifiableEncrypt");

            if (proof.Commitments == null || proof.Commitments.Length < 1
                || attributes.Length < idAttributeIndex || cpv.TildeO == null || cpv.TildeO.Length < 1)
            {
                throw new InvalidUProveArtifactException("invalid inputs to UProveVerifiableEncrypt");
            }


            byte[] tokenId = ProtocolHelper.ComputeTokenID(escrowParams.ip, token);
            GroupElement Cx1 = proof.Commitments[0].TildeC; // x1 is the first committed attribute
            FieldZqElement x1 = ProtocolHelper.ComputeXi(escrowParams.ip, idAttributeIndex - 1, attributes[idAttributeIndex - 1]); // arrays are 0-based
            FieldZqElement tildeO1 = cpv.TildeO[0];
            return IDEscrowFunctions.VerifiableEncrypt(escrowParams, escrowPublicKey, tokenId, Cx1, x1, tildeO1, additionalInfo);
        }

        /// <summary>
        /// Create a verifiable encryption of a pseudonym.  The output IECiphertext
        /// object will contain the ciphertext and proof that it was formed correctly. 
        /// The pseudonym that is encrypted is (param.Ge)^(x_b), where x_b is an attribute
        /// from the token.
        /// </summary>
        /// <param name="param"> Paramters of the ID escrow scheme.</param>
        /// <param name="pk"> Public key of the Auditor (the authority who can decrypt the output ciphertex).</param>
        /// <param name="tokenID"> The ID of the U-Prove token this ciphertext is assocaited with.</param>
        /// <param name="Cxb"> The commitment value (commitment to x_b, with bases g, g1).</param>
        /// <param name="x_b"> The attributed commited to by <c>Cxb</c></param>
        /// <param name="o_b"> The randomizer value used to create <c>Cxb</c></param>
        /// <param name="additionalInfo"> Arbitrary data that will be cryptographically bound to the ciphertext, 
        ///   but <b>NOT</b> encrypted, and will be included with the output ciphertext. 
        ///   The integrity of the <c>additionalInfo</c> is protected, i.e., modifying
        ///   the <c>additionalInfo</c> included in the ciphertext will cause verification/decryption to fail.
        ///   The <c>additionalInfo</c> field is sometimes referred to in the cryptographic literature
        ///   as a <i>label</i>. </param>
        /// <param name="preGenRandom">Optional pre-generated random values to be used in the protocol.
        /// Set to <c>null</c> if unused.  The primary use of this field is for testing with test vectors.</param>
        /// <returns>An <c>IECiphertext</c> object with the ciphertext and proof.</returns>
        /// <remarks> 
        /// The additionalInfo field may be null to signify that there is no input, all other input
        /// paramters must be non-null. 
        /// 
        /// Input validation is limited to checking for non-null. We assume that all group & field elements are consistent 
        /// with the parameters specified by the IdEscrowParams.
        /// </remarks>
        public static IDEscrowCiphertext VerifiableEncrypt(IDEscrowParams param, IDEscrowPublicKey pk, byte[] tokenID, GroupElement Cxb, 
            FieldZqElement x_b, FieldZqElement o_b, byte[] additionalInfo, IDEscrowProofGenerationRandomData preGenRandom = null)
        {
            // Notation & numbering follows draft spec -- subject to change.
            GroupElement g = param.ip.Gq.G; // first base for commitment Cxb
            GroupElement g1 = param.ip.G[1]; // second base for Cxb

            if (param == null || pk == null || tokenID == null || Cxb == null || g == null || g1 == null || x_b == null || o_b == null)
                throw new ArgumentNullException("Null input to VerifiableEncrypt");
            if (tokenID.Length == 0)
                throw new ArgumentOutOfRangeException("tokenID has length 0");

            Group G = param.G;
            FieldZq F = param.Zq;

            if(preGenRandom == null || preGenRandom.HasNullValue())
                preGenRandom = IDEscrowProofGenerationRandomData.Generate(F);
            
            // [1.] Encrypt
            // Compute E1
            FieldZqElement r = preGenRandom.R;
            GroupElement E1 = param.Ge.Exponentiate(r);         // E1 = (g_e)^r

            // Compute E2 = (g_e)^x_b * H^r
            GroupElement E2 = G.MultiExponentiate(new GroupElement[] { pk.H, param.Ge }, new FieldZqElement[] { r, x_b });

            // [2.] Generate proof of correctness
            // [2.a] 
            FieldZqElement xbPrime = preGenRandom.XbPrime;
            FieldZqElement rPrime = preGenRandom.RPrime;
            FieldZqElement obPrime = preGenRandom.ObPrime;

            // [2.b]
            GroupElement CxbPrime = G.MultiExponentiate(new GroupElement[] { g, g1 }, new FieldZqElement[] { xbPrime, obPrime }); // Cxb' = (g^xb')*(g1^ob')
            GroupElement E1Prime = param.Ge.Exponentiate(rPrime);  // E1' = (ge)^r'
            GroupElement E2Prime = G.MultiExponentiate(new GroupElement[] { param.Ge, pk.H }, new FieldZqElement[] { xbPrime, rPrime }); // E2' = ((g_e)^xb')*(H^r')

            // [2.c] 
            FieldZqElement c = ComputeChallenge(param.ip, tokenID, pk, Cxb, E1, E2, CxbPrime, E1Prime, E2Prime, additionalInfo);

            // [2.d]
            FieldZqElement rXb = ComputeResponse(xbPrime, c, x_b);
            FieldZqElement rR = ComputeResponse(rPrime, c, r);
            FieldZqElement rOb = ComputeResponse(obPrime, c, o_b);

            IDEscrowProof proof = new IDEscrowProof(c, rXb, rR, rOb);
            IDEscrowCiphertext ctext = new IDEscrowCiphertext(E1, E2, proof, additionalInfo);

            return ctext;
        }

        /// <summary>
        ///  Verifies that an <c>IECiphertext</c> was computed correctly. 
        ///  This is a wrapper around <c>IEFunctions.Verify</c> for use with U-Prove.
        /// </summary>
        /// <param name="escrowParams">Parameters of the ID escrow scheme</param>
        /// <param name="ctext">A ciphertext created with <c>param</c> and <c>pk</c>. </param>
        /// <param name="proof">The associated U-Prove presentation proof.</param>
        /// <param name="token">The associated U-Prove token.</param>
        /// <param name="pk">The auditor's public key</param>
        /// <returns> True if the ciphertext is valid, false if it is invalid.</returns>
        /// <remarks>The identity <b>must be</b> the first committed attribute in the proof (as 
        /// in <c>UProveVerifiableEncrypt</c>).</remarks>
        public static bool UProveVerify(IDEscrowParams escrowParams, IDEscrowCiphertext ctext, PresentationProof proof, UProveToken token, IDEscrowPublicKey pk)
        {
            if (escrowParams == null || ctext == null || proof == null || token == null || pk == null)
                throw new ArgumentException("null input to UProveVerify");

            if (proof.Commitments == null || proof.Commitments.Length < 1)
                throw new InvalidUProveArtifactException("invalid inputs to UProveVerifiableEncrypt");

            GroupElement Cx1 = proof.Commitments[0].TildeC;
            byte[] tokenId = ProtocolHelper.ComputeTokenID(escrowParams.ip, token);
            return IDEscrowFunctions.Verify(escrowParams, ctext, tokenId, pk, Cx1);
        }

        /// <summary>
        /// Verifies that an <c>IECiphertext</c> was computed correctly. 
        /// </summary>
        /// <param name="param">Paramters of the ID escrow scheme.</param>
        /// <param name="ctext"> A ciphertext created with <c>param</c> and <c>pk</c>.</param>
        /// <param name="tokenID">The ID of the U-Prove token this ciphertext is assocaited with.</param>
        /// <param name="pk">Public key of the Auditor (the authority who can decrypt <c>ctext</c>).</param>
        /// <param name="Cxb"> The commitment value (commitment to x_b, with bases g, g1).</param>
        /// <returns><c>true</c> if the ciphertext is valid, and <c>false</c> otherwise.</returns>
        /// <remarks> 
        /// The input <c>pk</c> is assumed to be valid, coming from a 
        /// trusted source (e.g., a certificate or a trusted store of parameters), and that they
        /// are consistent with the group specified by <c>param</c>.
        /// </remarks>
        public static bool Verify(IDEscrowParams param, IDEscrowCiphertext ctext, byte[] tokenID, IDEscrowPublicKey pk, GroupElement Cxb)
        {
            GroupElement g = param.ip.Gq.G;    // first base for commitment
            GroupElement g1 = param.ip.G[1];   // second base for commitment
            
            if(param == null || ctext == null || tokenID == null ||  pk == null || Cxb == null || g == null || g1 == null)
                throw new ArgumentNullException("null input to Verify");
            if(tokenID.Length == 0)
                throw new ArgumentOutOfRangeException("tokenID has length 0");

            Group G = param.ip.Gq;
            FieldZq F = param.Zq;
            IDEscrowProof proof = ctext.proof;

            // [1.]Checks on inputs.  These should be done during deserialization -- but we do 
            // them explicitly anyway, in case they were missed
            if (!IsGroupElement(G, ctext.E1) || !IsGroupElement(G, ctext.E2) || !IsGroupElement(G, Cxb))
                return false;

            if (!F.IsElement(proof.c) || !F.IsElement(proof.rOb) ||
                !F.IsElement(proof.rR) || !F.IsElement(proof.rXb))
            {
                return false;
            }

            // [2.] Recompute inputs to hash (using tilde{x} instead of x'' for this section.)
            GroupElement tildeCxb = G.MultiExponentiate(
                new GroupElement[] { g, g1, Cxb }, 
                new FieldZqElement[] { proof.rXb, proof.rOb, proof.c }); // tildeCxb = (g^rXb)*(g1^rOb)*(Cxb^c)


            GroupElement tildeE1 = G.MultiExponentiate(
                new GroupElement[] { param.Ge, ctext.E1 },
                new FieldZqElement[] { proof.rR, proof.c }); // tildeE1 = (E1^c)*(ge^rR)

            GroupElement tildeE2 = G.MultiExponentiate(
                new GroupElement[] { param.Ge, pk.H, ctext.E2},
                new FieldZqElement[] { proof.rXb, proof.rR, proof.c }); // tildeE2 = (ge^rXb)*(H^rR)*(E2^c)
                
            // [3.] 
            FieldZqElement cPrime = ComputeChallenge(param.ip, tokenID, pk, Cxb, ctext.E1, ctext.E2, tildeCxb, tildeE1, tildeE2, ctext.additionalInfo);

            // [4.] 
            if (cPrime.Equals(proof.c))
                return true;

            return false;
        }


        /// <summary>
        /// Decrypts an ID escrow ciphertext without verifying the proof. 
        /// The proof must be verified by <c>IEFunctions.Verify</c> before decryption.
        /// The IEVerifier verification step also checks the validity of 
        /// the ciphertext.  
        /// </summary>
        /// <param name="ctext">Ciphertext to be decrypted</param>
        /// <param name="sk"> Decryption key.</param>
        /// <param name="ip"> Issuer paramters associated with the ID escrow scheme.</param>
        /// <returns></returns>
        /// <remarks>    
        /// Semantic verification of the label (the <c>additionalInfo</c> field of <c>ctext</c>),
        /// i.e., whether it makes sense for the application is assumed to be done out-of-band.
        /// For example, the application may check that the label includes a timestamp, and that
        /// this timestamp falls within a given interval.
        /// 
        /// The IssuerParameters for decryption should match the issuer paramters used to create
        /// the IEParam object used for decryption (i.e., IEParam.ip).
        /// </remarks>
        public static GroupElement Decrypt(IDEscrowParams param, IDEscrowCiphertext ctext, IDEscrowPrivateKey sk)
        {
            if (ctext == null || sk == null || param == null)
                throw new ArgumentNullException("null input to Decrypt");

            Group G = param.ip.Gq;
            if (!IsGroupElement(G,ctext.E1) || !IsGroupElement(G, ctext.E2))   // this should never fail if Verify is called first, but we check again anyway.
                throw new ArgumentException("E1 or E2 is not a valid group element in Decrypt");

            GroupElement PE = ctext.E1.Exponentiate(sk.X.Negate());   // PE = E1^(-x) = H^(-r)
            PE = PE.Multiply(ctext.E2);                               // PE = E2/E1^(x)
            return PE;
        }

        #endregion //Main functions

        #region Helper functions (private)

        // return r - c*x
        private static FieldZqElement ComputeResponse(FieldZqElement r, FieldZqElement c, FieldZqElement x)
        {
            return r.Add(c.Multiply(x).Negate());
        }

        // Compute c = H(IP, T, H, Cxb, E1, E2, Cxb', E1', E2', additionalInfo)
        private static FieldZqElement ComputeChallenge(IssuerParameters ip, byte[] tokenID, IDEscrowPublicKey pk, GroupElement Cxb, GroupElement E1, GroupElement E2, GroupElement CxbPrime, GroupElement E1Prime, GroupElement E2Prime, byte[] additionalInfo)
        {
            HashFunction hasher = ip.HashFunction;
            FieldZq F = ip.Zq;

            hasher.Hash(ip.UidP);
            hasher.Hash(tokenID);
            hasher.Hash(pk.H);
            hasher.Hash(Cxb);
            hasher.Hash(E1);
            hasher.Hash(E2);
            hasher.Hash(CxbPrime);
            hasher.Hash(E1Prime);
            hasher.Hash(E2Prime);
            hasher.Hash(additionalInfo);   // additionalInfo may be null, and Hash() will handle this correctly.

            return F.GetElementFromDigest(hasher.Digest);
        }

        // Wrapper to avoid try/catch blocks elsewhere
        private static bool IsGroupElement(Group G, GroupElement g)
        {
            try
            {
                G.ValidateGroupElement(g);
            }
            catch
            {
                return false;
            }

            return true;
        }

        #endregion

    }


}