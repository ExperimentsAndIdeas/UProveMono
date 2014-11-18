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
using System.Runtime.Serialization;
using System.Collections;

namespace UProveCrypto.PolyProof
{
    [DataContract]
    public class RangeProof : GroupParameterizedSerializer
    {
        /// <summary>
        /// UProve integration proof
        /// </summary>
        [DataMember(Name = "UPIProof", EmitDefaultValue = false, Order = 1)]
        public UProveIntegrationProof UPIProof;


        /// <summary>
        /// Commitments to a[0]....a[n-1], the bit decomposition of integerA
        /// </summary>
        private GroupElement[] A;

        /// <summary>
        /// Commitments to to b[0]...b[n-1], the bit decomposition of integerB.
        /// May be null in case integerB is known to verifier.
        /// </summary>
        private GroupElement[] B;

        /// <summary>
        /// Commitments to (a[i]-b[i])^2
        /// </summary>
        private GroupElement[] X;

        /// <summary>
        /// Commitments to d[0],...,d[n-1], where d[i] in {-1,0,1} compares i-bit prefix 
        /// of integer1 to integer2: a[0]a[1]...a[i] to b[0]b[1]...b[i]
        /// </summary>
        private GroupElement[] D;

        /// <summary>
        /// Proof showing that A is a valid bit decomposition of integer A
        /// </summary>
        [DataMember(Name = "BitProofA", EmitDefaultValue = false)]
        private BitDecompositionProof ProofBitDecompositionOfA;

        /// <summary>
        /// Proof showing that B is a valid bit decomposition of integer B
        /// May be null if integer B is known to the verifier.
        /// </summary>
        [DataMember(Name = "BitProofB", EmitDefaultValue = false)]
        private BitDecompositionProof ProofBitDecompositionOfB;

        /// <summary>
        /// Body of the range proof
        /// </summary>
        [DataMember(Name = "FullRangeProof", EmitDefaultValue = false)]
        private EqualityProof FullRangeProof;

        /// <summary>
        /// Additional proof for GREATER_THAN_OR_EQUAL_TO and LESS_THAN_OR_EQUAL_TO
        /// </summary>
        [DataMember(Name = "OrEqualProof", EmitDefaultValue = false)]
        private SetMembershipProof OrEqualToProof;

        /// <summary>
        /// Additional proof for GREATER_THAN and LESS_THAN
        /// </summary>
        [DataMember(Name = "StrictProof", EmitDefaultValue = false)]
        private EqualityProof StrictlyThanProof;


        /// <summary>
        /// Returns the number of bits needed to represent the committed value in ClosedIntegerA
        /// and ClosedIntegerB.  This is computed  ceiling(log_2 MaxValue-MinValue)
        /// </summary>
        /// <param name="verifier"></param>
        /// <returns></returns>
       private static int ComputeDecompositionLength(VerifierRangeProofParameters verifier)
        {
            int range = verifier.MaxValue - verifier.MinValue;
            double exactBits = System.Math.Log(range, 2.0);
            return (int) System.Math.Ceiling(exactBits);
        }

        /// <summary>
        /// Creates a RangeProof given the parameters.  Throws an ArgumentException on error.
        /// </summary>
        /// <param name="prover"></param>
        public RangeProof(ProverRangeProofParameters prover)
        {
            ConstructorHelper(prover);
        }

        public void ConstructorHelper(ProverRangeProofParameters prover)
        {
            try
            {
                // verify prover parameters
                if (!prover.Verify())
                {
                    throw new ArgumentException("RangeProof: could not create RangeProof because prover parameters are invalid.");
                }


                // set group
                this.Group = prover.Group;
                this.IsGroupSerializable = true;

                // set up the bit decomposition proof and compute helper values
                DLRepOfGroupElement[] openAdivB = CreateBitDecompositionProofs(prover);
                if (this.ProofBitDecompositionOfA != null)
                {
                    this.ProofBitDecompositionOfA.IsGroupSerializable = false;
                }
                if (this.ProofBitDecompositionOfB != null)
                {
                    this.ProofBitDecompositionOfB.IsGroupSerializable = false;
                }
                DLRepOfGroupElement[] openD = ComputeOpenD(prover, openAdivB);
                
                DLRepOfGroupElement[] openX = ComputeOpenX(prover, openAdivB);
                DLRepOfGroupElement[] openE = ComputeOpenE(prover, openD, openX, openAdivB);

                // compute RangeProof
                DLRepOfGroupElement[] allOpenDL = CombineAllOpenDLReps(openD, openAdivB, openX, openE);
                EqualityMap map = ComputeEqualityMap(prover, A.Length);
                ProverEqualityParameters peParams = new ProverEqualityParameters(
                    allOpenDL,
                    map,
                    prover);
                this.FullRangeProof = new EqualityProof(peParams);
                this.FullRangeProof.IsGroupSerializable = false;

                // set X and D
                this.SetX(openX);
                this.SetD(openD);

                // create additional proofs based on proof type
                PedersenCommitment LastD = (PedersenCommitment)openD[openD.Length - 1];
                switch (prover.RangeProofType)
                {
                    case VerifierRangeProofParameters.ProofType.GREATER_THAN:
                    // Prove that D is a commitment to 1
                    case VerifierRangeProofParameters.ProofType.LESS_THAN:
                        // Prove that D is a commitment to -1
                        DLRepOfGroupElement equation = new DLRepOfGroupElement(
                            new GroupElement[1] { prover.H },
                            new FieldZqElement[1] { LastD.ExponentAtIndex(1) },
                            prover.Group);
                        ProverEqualityParameters strictProver = new ProverEqualityParameters(
                            equation,
                            prover);
                        this.StrictlyThanProof = new EqualityProof(strictProver);
                        this.StrictlyThanProof.IsGroupSerializable = false;
                        break;
                    case VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO:
                        // Prove that D is a commitment to either 0 or 1
                        ProverSetMembershipParameters greaterEqualProver = new ProverSetMembershipParameters(
                             LastD,
                             new FieldZqElement[] { prover.FieldZq.Zero, prover.FieldZq.One },
                             prover);
                        this.OrEqualToProof = new SetMembershipProof(greaterEqualProver);
                        this.OrEqualToProof.IsGroupSerializable = false;
                        break;
                    case VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO:
                        // Prove that D is a commitment to either 0 or -1
                        ProverSetMembershipParameters lessEqualProver = new ProverSetMembershipParameters(
                             LastD,
                             new FieldZqElement[] { prover.FieldZq.Zero, prover.FieldZq.One.Negate() },
                             prover);
                        this.OrEqualToProof = new SetMembershipProof(lessEqualProver);
                        this.OrEqualToProof.IsGroupSerializable = false;
                        break;
                }
            }
            catch (Exception e)
            {
                throw new Exception("RangeProof: Could not create range proof.", e);
            }
        }

        /// <summary>
        /// Verifies the RangeProof.  Returns true if it is valid, false otherwise.
        /// </summary>
        /// <param name="verifier">Verifier parameters.</param>
        /// <returns></returns>
        public bool Verify(VerifierRangeProofParameters verifier)
        {
            try
            {
                // Verify parameters
                if (!verifier.Verify())
                {
                    return false;
                }

                // verify bit decomposition proofs
                if (!VerifyBitDecompositionProofs(verifier, this.A, this.B, ProofBitDecompositionOfA, ProofBitDecompositionOfB))
                {
                    return false;
                }

                // verify FullRangeProof
                GroupElement[] closedAdivB = ComputeClosedAdivB(verifier, this.A, this.B);
                this.D[0] = closedAdivB[0];
                ClosedDLRepOfGroupElement[] closedX = ComputeClosedX(verifier, this.X, closedAdivB);
                ClosedDLRepOfGroupElement[] closedE = ComputeClosedE(verifier, this.X, this.D, closedAdivB);
                ClosedDLRepOfGroupElement[] allClosedDL = CombineAllClosedDLReps(this.D, closedAdivB, closedX, closedE, verifier);
                EqualityMap map = ComputeEqualityMap(verifier, A.Length);
                VerifierEqualityParameters veParameters = new VerifierEqualityParameters(
                    allClosedDL,
                    map,
                    verifier);

                bool success = this.FullRangeProof.Verify(veParameters);
                if (!success)
                {
                    return false;
                }

                // verify additional proof based on proof type
                GroupElement LastD = this.D[this.D.Length - 1];
                switch (verifier.RangeProofType)
                {
                    case VerifierRangeProofParameters.ProofType.GREATER_THAN:
                        ClosedDLRepOfGroupElement gtEquation = new ClosedDLRepOfGroupElement(
                            new GroupElement[1] { verifier.H },
                            LastD * verifier.G.Exponentiate(verifier.FieldZq.One.Negate()),
                            verifier.Group);
                        VerifierEqualityParameters greaterThanVerifier = new VerifierEqualityParameters(
                            gtEquation,
                            verifier);
                        return StrictlyThanProof.Verify(greaterThanVerifier);
                    case VerifierRangeProofParameters.ProofType.LESS_THAN:
                        ClosedDLRepOfGroupElement ltEquation = new ClosedDLRepOfGroupElement(
                            new GroupElement[1] { verifier.H },
                            LastD * verifier.G,
                            verifier.Group);
                        VerifierEqualityParameters lessThanVerifier = new VerifierEqualityParameters(
                            ltEquation,
                            verifier);
                        return StrictlyThanProof.Verify(lessThanVerifier);
                    case VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO:
                        VerifierSetMembershipParameters greaterEqualVerifier = new VerifierSetMembershipParameters(
                             LastD,
                             new FieldZqElement[] { verifier.FieldZq.Zero, verifier.FieldZq.One },
                             verifier);
                        return this.OrEqualToProof.Verify(greaterEqualVerifier);
                    case VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO:
                        VerifierSetMembershipParameters lessEqualProver = new VerifierSetMembershipParameters(
                             LastD,
                             new FieldZqElement[] { verifier.FieldZq.Zero, verifier.FieldZq.One.Negate() },
                             verifier);
                        return this.OrEqualToProof.Verify(lessEqualProver);
                }
            }
            catch (Exception)
            {
            }
            return false;
        }

        /// <summary>
        /// Verifies that A is a valid bit decomposition of verifier.ClosedIntegerA and 
        /// B is a valid bit decomposition of verifier.ClosedIntegerB.
        /// </summary>
        /// <param name="verifier"></param>
        /// <param name="A">Bit decomposition of A.</param>
        /// <param name="B">Bit decomposition of B.</param>
        /// <param name="proofA">Proof that A is a valid bit decomposition of verifier.ClosedIntegerA.</param>
        /// <param name="proofB">Proof that B is a valid bit decomposition of verifier.ClosedIntegerB.</param>
        /// <returns></returns>
        private static bool VerifyBitDecompositionProofs(VerifierRangeProofParameters verifier, GroupElement [] A, GroupElement [] B, BitDecompositionProof proofA, BitDecompositionProof proofB)
        {
            // verify A

            VerifierBitDecompositionParameters bitVerifierA = new VerifierBitDecompositionParameters(verifier.RangeNormalizedClosedIntegerA, A, verifier);
            if (!proofA.Verify(bitVerifierA))
            {
                return false;
            }

            // verify B
            if ((verifier.IntegerBIsKnown) && (B == null) && (proofB == null))
            {
                return true;
            }
            VerifierBitDecompositionParameters bitVerifierB = new VerifierBitDecompositionParameters(verifier.RangeNormalizedClosedIntegerB, B, verifier);
            if (!proofB.Verify(bitVerifierB))
            {
                return false;
            }
            return true;

        }


        /// <summary>
        /// Creates a bit decomposition of prover.OpenIntegerA and prover.OpenIntegerB,
        /// and proofs that they are valid.  Sets member fields
        /// A, B, ProofBitDecompositionOfA and ProofBitDecompositionOfB.
        /// </summary>
        /// <param name="prover">Prover range proof parameters</param>
        /// <param name="bitProverA">outputs parameters for bit decomposition proof for A</param>
        /// <param name="bitProverB">outputs parameters for bit decomposition proof for B</param>
        /// <returns>Array AdivB with the bit decomposition of A divided by the bit decomposition of B.</returns>
        private DLRepOfGroupElement [] CreateBitDecompositionProofs(ProverRangeProofParameters prover)
        {
            int decompositionLength = RangeProof.ComputeDecompositionLength(prover);

            // create proof for A
            ProverBitDecompositionParameters bitProverA = new ProverBitDecompositionParameters(prover.RangeNormalizedOpenIntegerA, decompositionLength, prover);
            this.ProofBitDecompositionOfA = new BitDecompositionProof(bitProverA);
            this.A = bitProverA.ClosedBitDecomposition();

            // create proof for B if it is unknown.
            ProverBitDecompositionParameters bitProverB = new ProverBitDecompositionParameters(prover.RangeNormalizedOpenIntegerB, decompositionLength, prover);
            if (prover.IntegerBIsKnown)
            {
                this.ProofBitDecompositionOfB = null;
                this.B = null;
                DLRepOfGroupElement[] defaultB = DefaultOpenDecompositionOfIntegerB(prover);
                return ComputeOpenAdivB(prover, bitProverA.OpenBitDecomposition(), defaultB);
            }
                this.ProofBitDecompositionOfB = new BitDecompositionProof(bitProverB);
                this.B = bitProverB.ClosedBitDecomposition();
                return ComputeOpenAdivB(prover, bitProverA.OpenBitDecomposition(), bitProverB.OpenBitDecomposition());
        }

        /// <summary>
        /// If verifier knows Integer B, returns the default bit-decomposition. Returns Null if verifier does not know integer B.
        /// If bit[i] = 0, output[i] = verifier.G^0.
        /// If bit[i] = 1, output[i] = verifier.G.
        /// </summary>
        /// <param name="verifier">Verifier parameters.</param>
        /// <returns></returns>
        private static GroupElement[] DefaultClosedDecompositionOfIntegerB(VerifierRangeProofParameters verifier)
        {
            if (!verifier.IntegerBIsKnown)
            {
                return null;
            }
            FieldZqElement integerB = verifier.FieldZq.GetElement((uint)verifier.RangeNormalizedIntegerB);
            int decompositionLength = ComputeDecompositionLength(verifier);
            BitArray bitsB = VerifierBitDecompositionParameters.GetBitDecomposition(integerB, decompositionLength, verifier.FieldZq);
            GroupElement[] defaultBitDecomposition = new GroupElement[bitsB.Length];
            for (int i = 0; i < defaultBitDecomposition.Length; ++i)
            {
                if (bitsB.Get(i))
                {
                    defaultBitDecomposition[i] = verifier.G;
                }
                else
                {
                    defaultBitDecomposition[i] = verifier.Group.Identity;
                }
            }
            return defaultBitDecomposition;
        }

        /// <summary>
        /// If verifier knows Integer B, returns the default bit-decomposition. Returns Null if verifier does not know integer B.
        /// If bit[i] = 0, output[i] = verifier.G^0.
        /// If bit[i] = 1, output[i] = verifier.G.
        /// </summary>
        /// <param name="verifier">Verifier parameters.</param>
        /// <returns></returns>
        private static DLRepOfGroupElement[] DefaultOpenDecompositionOfIntegerB(VerifierRangeProofParameters verifier)
        {
            if (!verifier.IntegerBIsKnown)
            {
                return null;
            }
            FieldZqElement integerB = verifier.FieldZq.GetElement((uint)verifier.RangeNormalizedIntegerB);
            int decompositionLength = ComputeDecompositionLength(verifier);
            BitArray bitsB = VerifierBitDecompositionParameters.GetBitDecomposition(integerB, decompositionLength, verifier.FieldZq);
            PedersenCommitment[] defaultBitDecomposition = new PedersenCommitment[bitsB.Length];
            GroupElement [] bases = new GroupElement [2] {verifier.G, verifier.H};
            FieldZqElement [] exponent0 = new FieldZqElement[2] {verifier.FieldZq.Zero, verifier.FieldZq.Zero,};

            FieldZqElement [] exponent1 = new FieldZqElement[2] {verifier.FieldZq.One, verifier.FieldZq.Zero,};
 
            for (int i = 0; i < defaultBitDecomposition.Length; ++i)
            {
                if (! bitsB.Get(i))
                {
                    defaultBitDecomposition[i] = new PedersenCommitment(bases, exponent0, verifier.Group);
                }
                else
                {
                    defaultBitDecomposition[i] = new PedersenCommitment(bases, exponent1, verifier.Group);
                }
            }
            return defaultBitDecomposition;
        }

        /// <summary>
        /// Copies openX[i].Value into field X.
        /// </summary>
        /// <param name="openX">DL representation of X.</param>
        private void SetX(DLRepOfGroupElement[] openX)
        {
            this.X = new GroupElement[openX.Length];
            this.X[0] = null;
            for (int i = 1; i < X.Length; ++i)
            {
                this.X[i] = openX[i].Value;
            }
        }

        /// <summary>
        /// Copies D[i].Value into field D.
        /// </summary>
        /// <param name="openD"></param>
        private void SetD(DLRepOfGroupElement[] openD)
        {
            this.D = new GroupElement[openD.Length];
            D[0] = null;
            for(int i=1; i<openD.Length; ++i)
            {
                D[i] = openD[i].Value;
            }
        }

        /// <summary>
        /// Computes the EqualityMap used by both the prover and verifier.
        /// </summary>
        /// <param name="verifier">Public parameters</param>
        /// <param name="decompositionLength">Number of bits used to represent integer A and integer B (e.g. A.Length)</param>
        /// <returns>EqualityMap</returns>
        public static EqualityMap ComputeEqualityMap(VerifierRangeProofParameters verifier, int decompositionLength)
        {
            EqualityMap map = new EqualityMap();
            int dlIndex = 0;

            // process forall i in [0,m-2] D[i] = g^{delta,i} h^{tau,i}
            for (int i = 0; i < decompositionLength-1; ++i)
            {
                map.Add(new PrettyName("delta", i), new DoubleIndex(dlIndex, 0));
                ++dlIndex;
            }
            // skip D[m -1] -- this will be a separate proof based on RangeProofType

            // process forall i in [1,m-1]:  A[i]/B[i] = g^{chi,i} h^{zeta,i}
            // Note: A[0]/B[0] appears in the proof indirectly as D[0]
            for (int i = 1; i < decompositionLength; ++i)
            {
                map.Add(new PrettyName("chi", i), new DoubleIndex(dlIndex, 0));
                ++dlIndex;
            }
 
            // process forall i in [1,m-1]: X[i] = (A[i]/B[i])^{chi,i} h^{mu,i}
            // Note: X[0]=null.
            for (int i = 1; i < decompositionLength; ++i)
            {
                map.Add(new PrettyName("chi", i), new DoubleIndex(dlIndex, 0));
                ++dlIndex;
            }
            
            // process forall i in [1,m-1]: E[i] = (X[i]^-1)^{delta, i-1} h^{nu,i}
            // Note: E[0] = null.
            for (int i = 1; i < decompositionLength; ++i)
            {
                map.Add(new PrettyName("delta",i-1), new DoubleIndex(dlIndex,0));
                ++dlIndex;
            }

            return map;
        }

        /// <summary>
        /// Combines the input arrays into a master array of DL representation equations to use
        /// for FullRangeProof.  Arrays should all be not null and of equal length.
        /// </summary>
        /// <param name="openD">openD[length-1] is excluded.</param>
        /// <param name="AdivB">AdivB[0] is excluded.</param>
        /// <param name="openX">openX[0] is excluded.</param>
        /// <param name="openE">openE[0] is excluded. </param>
        /// <returns>Concatentation of all arrays, minus excluded values.</returns>
        public static DLRepOfGroupElement[] CombineAllOpenDLReps(DLRepOfGroupElement []openD, DLRepOfGroupElement[] AdivB, DLRepOfGroupElement[] openX, DLRepOfGroupElement[] openE)
        {
            DLRepOfGroupElement[] openDL = new DLRepOfGroupElement[openD.Length-1 + AdivB.Length -1 + openX.Length-1 + openE.Length-1];
            int openDLIndex=0;

            for (int i = 0; i < openD.Length-1; ++i)
            {
                openDL[openDLIndex] = openD[i];
                ++openDLIndex;
            }

            for (int i = 1; i < AdivB.Length; ++i)
            {
                openDL[openDLIndex] = AdivB[i];
                ++openDLIndex;
            }
            
            for (int i = 1; i < openX.Length; ++i)
            {
                openDL[openDLIndex] = openX[i];
                ++openDLIndex;
            }
            
            for (int i = 1; i < openE.Length; ++i)
            {
                openDL[openDLIndex] = openE[i];
                ++openDLIndex;
            }
            return openDL;
        }

        /// <summary>
        /// Combines all input arrays into an array of Closed DL representation equations
        /// to be used to verify FullRangeProof.  Sets bases for closedD and AdivB as
        /// new GroupElement[2]{crypto.G, crypto.H}.
        /// </summary>
        /// <param name="closedD">closedD[length-1] excluded.</param>
        /// <param name="AdivB">AdivB[0] excluded.</param>
        /// <param name="closedX">closedX[0] excluded.</param>
        /// <param name="closedE">closedE[0] excluded.</param>
        /// <param name="crypto">Contains parameters G and H</param>
        /// <returns></returns>
        public static ClosedDLRepOfGroupElement[] CombineAllClosedDLReps(GroupElement[] closedD, GroupElement[] AdivB, ClosedDLRepOfGroupElement[] closedX, ClosedDLRepOfGroupElement[] closedE, CryptoParameters crypto)
        {
            ClosedDLRepOfGroupElement[] closedDL = new ClosedDLRepOfGroupElement[closedD.Length-1 + AdivB.Length-1 + closedX.Length-1 + closedE.Length -1];
            int closedDLIndex = 0;
            GroupElement[] bases = new GroupElement[2] { crypto.G, crypto.H };
            Group group = crypto.Group;

            for (int i = 0; i < closedD.Length-1; ++i)
            {
                closedDL[closedDLIndex] = new ClosedDLRepOfGroupElement(bases, closedD[i], group);
                ++closedDLIndex;
            }

            for (int i = 1; i < AdivB.Length; ++i)
            {
                closedDL[closedDLIndex] = new ClosedDLRepOfGroupElement(bases, AdivB[i], group);
                ++closedDLIndex;
            }
            
            for (int i = 1; i < closedX.Length; ++i)
            {
                closedDL[closedDLIndex] = closedX[i];
                ++closedDLIndex;
            }
            
            for (int i = 1; i < closedE.Length; ++i)
            {
                closedDL[closedDLIndex] = closedE[i];
                ++closedDLIndex;
            }
             
            return closedDL;
        }



        /// <summary>
        /// Let a[i] be the committed bits in openAdivB,
        /// 
        /// Computes the arrray d as follows:
        /// d[0] = a[0]
        /// d[i] = d[i-1] - d[i-1]*a[i]^2 + a[i]
        /// </summary>
        /// <param name="prover">Prover parameters</param>
        /// <returns>The array d</returns>
        private static FieldZqElement[] Compute_d(ProverRangeProofParameters prover, DLRepOfGroupElement [] openAdivB)
        {
            FieldZqElement[] d = new FieldZqElement[openAdivB.Length];
            for (int i = 0; i < d.Length; ++i)
            {
                FieldZqElement difference = openAdivB[i].ExponentAtIndex(0);
                if(i==0)
                {
                    d[0] = difference;
                }
                else
                {
                    d[i] = d[i - 1]
                        + (d[i - 1].Negate() * difference * difference)
                        + difference;
                }
            }
            return d;
        }

        /// <summary>
        /// Returns array of DLRepOfGroupElement objects, where output[i] = openA[i] / openB[i].
        /// Input arrays should be not null and of equal lengths.
        /// </summary>
        /// <param name="prover">Used to get bases G and H.</param>
        /// <param name="openA">Each openA[i] should have RepresentationLength=2, with bases equal to prover.G and prover.H</param>
        /// <param name="openB">Each openB[i] should have RepresentationLength=2, with bases equal to prover.G and prover.H</param>
        /// <returns></returns>
        public static DLRepOfGroupElement[] ComputeOpenAdivB(ProverRangeProofParameters prover, DLRepOfGroupElement [] openA, DLRepOfGroupElement [] openB)
        {
            DLRepOfGroupElement[] AdivB = new DLRepOfGroupElement[openA.Length];
            for (int i = 0; i < AdivB.Length; ++i)
            {
                AdivB[i] = new PedersenCommitment(
                   prover.G,
                   prover.H,
                    openA[i].ExponentAtIndex(0) - openB[i].ExponentAtIndex(0),
                    openA[i].ExponentAtIndex(1) - openB[i].ExponentAtIndex(1),
                    prover.Group);
            }
            return AdivB;
        }

        /// <summary>
        /// Returns array of ClosedDLRepOfGroupElement objects, where output[i] = A[i] / B[i].
        /// If verifier.IntegerBIsKnown is true, replaces input B with default B.
        /// </summary>
        /// <param name="verifier">Used to get bases G and H. If verifier knows B, generates new array B.</param>
        /// <param name="A">Array of group elements.</param>
        /// <param name="B">Array of group elements of same length as A. May be null if verifier.IntegerBIsKnown is true.</param>
        /// <returns></returns>
        public static GroupElement[] ComputeClosedAdivB(VerifierRangeProofParameters verifier, GroupElement[] A, GroupElement[] B)
        {
            if (verifier.IntegerBIsKnown)
            {
                B = DefaultClosedDecompositionOfIntegerB(verifier);
            }

            GroupElement [] closedAdivB = new GroupElement[A.Length];
            for (int i = 0; i < closedAdivB.Length; ++i)
            {
                closedAdivB[i] = verifier.Group.Divide(A[i], B[i]);
            }
            return closedAdivB;
        }



        /// <summary>
        /// Computes commitment to (a-b)^2.
        /// Let openAdivB[i] be a commitment to (a[i]-b[i]). This method chooses
        /// random u[i] and returns:
        /// output[i] = (openAdivB[i].Value)^(a[i]-b[i]) * prover.H^u[i]
        /// </summary>
        /// <param name="prover">Range proof parameters</param>
        /// <param name="openAdivB">Commitment to A/B</param>
        /// <returns>Array of same length as openAdivB, first element is null.</returns>
        public static DLRepOfGroupElement[] ComputeOpenX(ProverRangeProofParameters prover, DLRepOfGroupElement[] openAdivB)
        {
            FieldZqElement[] u = prover.FieldZq.GetRandomElements(openAdivB.Length, true);
            DLRepOfGroupElement[] openX = new DLRepOfGroupElement[openAdivB.Length];
            openX[0] = null;
            for (int i = 1; i < openX.Length; ++i)
            {
                openX[i] = new PedersenCommitment(
                    openAdivB[i].Value,
                    prover.H,
                    openAdivB[i].ExponentAtIndex(0),
                    u[i],
                    prover.Group);
            }
            return openX;
        }

        /// <summary>
        /// Computes closed DL representation equations for X using
        /// bases closedAdivB[i] and verifier.H.
        /// </summary>
        /// <param name="verifier">Used to get base verifier.H</param>
        /// <param name="X">Array of group elements</param>
        /// <param name="closedAdivB">Used for base at index 0.</param>
        /// <returns>Array of same length as X, first element is null.</returns>
        public static ClosedDLRepOfGroupElement[] ComputeClosedX(VerifierRangeProofParameters verifier, GroupElement[] X, GroupElement [] closedAdivB)
        {
            ClosedDLRepOfGroupElement[] closedX = new ClosedDLRepOfGroupElement[X.Length];
            closedX[0] = null;
            for (int i = 1; i < X.Length; ++i)
            {
                closedX[i] = new ClosedDLRepOfGroupElement(
                    new GroupElement[2] {closedAdivB[i],verifier.H},
                    X[i],
                    verifier.Group);
            }
            return closedX;
        }

        /// <summary>
        /// Computes an array of commitments to d=Compute_d(prover,AdivB).
        /// </summary>
        /// <param name="prover">Used for bases G, H.</param>
        /// <param name="AdivB">Used to compute committed values d.</param>
        /// <returns>Array of same length as AdivB.</returns>
        public static DLRepOfGroupElement[] ComputeOpenD(ProverRangeProofParameters prover, DLRepOfGroupElement [] AdivB)
        {
            FieldZqElement[] d = Compute_d(prover, AdivB);
            DLRepOfGroupElement[] D = new DLRepOfGroupElement[d.Length];
            FieldZqElement[] t = prover.FieldZq.GetRandomElements(d.Length, true);
            D[0] = AdivB[0];
            for (int i = 1; i < D.Length; ++i)
            {
                D[i] = new PedersenCommitment(
                    prover.G,
                    prover.H,
                    d[i],
                    t[i],
                    prover.Group);
            }

            return D;
        }

        /// <summary>
        /// Creates a DL representation equation E[i].
        /// Let d[i] be the committed value in D[i].
        /// Let E[i].Value = D[i]/D[i-1] * AdivB[i]^{-1}.
        /// Computes nu[i] so that the following relation holds
        /// E[i].Value= (X[i]^{-1})^{d[i-1]} * prover.H^{nu[i]}.
        /// </summary>
        /// <param name="prover"></param>
        /// <param name="D">Commitments to d</param>
        /// <param name="X">Commitment to (a-b)^2</param>
        /// <param name="AdivB">A/B</param>
        /// <returns>Array of same length as D, first element is null.</returns>
        public static DLRepOfGroupElement[] ComputeOpenE(ProverRangeProofParameters prover, DLRepOfGroupElement[] D, DLRepOfGroupElement [] X, DLRepOfGroupElement [] AdivB)
        {
            DLRepOfGroupElement[] E = new DLRepOfGroupElement[D.Length];
            E[0] = null;
            for (int i = 1; i < E.Length; ++i)
            {
                FieldZqElement nu =
                    D[i].ExponentAtIndex(1)                       // t[i]
                    - D[i - 1].ExponentAtIndex(1)                 // - t[i-1]
                    - AdivB[i].ExponentAtIndex(1)                 // - r[i]
                    + (D[i - 1].ExponentAtIndex(0)                // + (d[i-1] * r[i] * adivb[i])
                        * AdivB[i].ExponentAtIndex(1)
                        * AdivB[i].ExponentAtIndex(0))
                    + (D[i - 1].ExponentAtIndex(0)                // (d[i-1] * u[i])
                       * X[i].ExponentAtIndex(1)); 
                E[i] = new PedersenCommitment(
                    prover.Group.Invert(X[i].Value),
                    prover.H,
                    D[i - 1].ExponentAtIndex(0),
                    nu,
                    prover.Group);
            }
            return E;
        }

        /// <summary>
        /// Computes closed DL representation of E[i] = D[i]/D[i-1] * closedAdivB[i]^{-1}.
        /// Bases are X^{-1} and verifier.H.
        /// </summary>
        /// <param name="verifier">Verifier range proof parameters.</param>
        /// <param name="X">Array of commitments to (a-b)^2</param>
        /// <param name="D">Array of commitments to d.</param>
        /// <param name="closedAdivB">A/B</param>
        /// <returns>Array of same length as X, first element is null.</returns>
        public static ClosedDLRepOfGroupElement[] ComputeClosedE(VerifierRangeProofParameters verifier, GroupElement[] X, GroupElement[] D, GroupElement[] closedAdivB)
        {
            ClosedDLRepOfGroupElement[] closedE = new ClosedDLRepOfGroupElement[X.Length];
            closedE[0] = null;
            for (int i = 1; i < closedE.Length; ++i)
            {
                closedE[i] = new ClosedDLRepOfGroupElement(
                    new GroupElement[2] { verifier.Group.Invert(X[i]), verifier.H },
                    verifier.Group.Divide(new GroupElement[]{D[i]}, new GroupElement[]{D[i-1], closedAdivB[i]}),
                    verifier.Group);
            }
            return closedE;
        }

        #region UProve Integration

        /// <summary>
        /// Creates a range proof that compares a UProve attribute to a target date.
        /// Target attribute MUST NOT be hashed.
        /// Value MUST be generated via RangeProofParameterFactory.EncodeYearAndDayAsUProveAttribute.
        /// </summary>
        /// <param name="prover">Token information.</param>
        /// <param name="attributeIndexForProver">1-based index of target attribute.</param>
        /// <param name="proofType">Range proof type</param>
        /// <param name="targetDate">Compare token attribute to this date.  (Time component is ignored).</param>
        /// <param name="minYear">Minimum year for attribute and target date.</param>
        /// <param name="maxYear">Maximum year for attribute and target date.</param>
        public RangeProof(
            ProverPresentationProtocolParameters prover, 
            int attributeIndexForProver, 
            VerifierRangeProofParameters.ProofType proofType,
            DateTime targetDate,
            int minYear,
            int maxYear)
        {
            // make sure target attribute is not hashed
            if (prover.IP.E[attributeIndexForProver - 1] == 0x01)
            {
                throw new ArgumentException("UProve attributes used in Range Proof must not be hashed.");
            }

            // generate Pedersen Commitments to token attribute
            ProverPresentationProtocolParameters[] provers = new ProverPresentationProtocolParameters[] { prover };
            int[] attributeIndices = new int[] { attributeIndexForProver };
            PedersenCommitment[] attributeCommitments = PedersenCommitment.PedersenCommmitmentsToAttributes(provers, attributeIndices);

            // create range proof
            ProverRangeProofParameters rangeProver = RangeProofParameterFactory.GetDateTimeProverParameters(
                new CryptoParameters(prover.IP),
                attributeCommitments[0],
                proofType,
                targetDate,
                minYear,
                maxYear);
            ConstructorHelper(rangeProver);

            // Add UProve Integration proof
            this.UPIProof = new UProveIntegrationProof(provers, attributeIndices, attributeCommitments);
            this.UPIProof.IsGroupSerializable = false;
        }

        /// <summary>
        /// Creates a range proof that compares a UProve attribute to a target date.
        /// Target attribute MUST NOT be hashed.
        /// Value MUST be generated via RangeProofParameterFactory.EncodeYearAndDayAsUProveAttribute.
        /// </summary>
        /// <param name="prover">Token information.</param>
        /// <param name="attributeIndexForProver">1-based index of target attribute.</param>
        /// <param name="proofType">Range proof type</param>
        /// <param name="targetDate">Compare token attribute to this date.  (Time component is ignored).</param>
        /// <param name="minYear">Minimum year for attribute and target date.</param>
        /// <param name="maxYear">Maximum year for attribute and target date.</param>
        public RangeProof(
            ProverPresentationProtocolParameters prover1,
            int attributeIndexForProver1,
            VerifierRangeProofParameters.ProofType proofType,
            ProverPresentationProtocolParameters prover2,
            int attributeIndexForProver2,
            int minValue,
            int maxValue)
        {
            // make sure target attribute is not hashed
            if ((prover1.IP.E[attributeIndexForProver1 - 1] == 0x01) || ((prover2.IP.E[attributeIndexForProver2 - 1]) == 0x01))
            {
                throw new ArgumentException("UProve attributes used in Range Proof must not be hashed.");
            }

            // generate Pedersen Commitments to token attributes
            ProverPresentationProtocolParameters[] provers = new ProverPresentationProtocolParameters[] { prover1, prover2 };
            int[] attributeIndices = new int[] { attributeIndexForProver1, attributeIndexForProver2 };
            PedersenCommitment[] attributeCommitments = PedersenCommitment.PedersenCommmitmentsToAttributes(provers, attributeIndices);

            // create range proof
            ProverRangeProofParameters rangeProver = new ProverRangeProofParameters(
                new CryptoParameters(prover1.IP),
                attributeCommitments[0],
                proofType,
                attributeCommitments[1],
                minValue,
                maxValue);
            ConstructorHelper(rangeProver);

            // Add UProve Integration proof
            this.UPIProof = new UProveIntegrationProof(provers, attributeIndices, attributeCommitments);
            this.UPIProof.IsGroupSerializable = false;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="verifier"></param>
        /// <param name="attributeIndexForVerifier"></param>
        /// <param name="proofType"></param>
        /// <param name="targetDate"></param>
        /// <param name="minYear"></param>
        /// <param name="maxYear"></param>
        /// <returns></returns>
        public bool Verify(
            VerifierPresentationProtocolParameters verifier,
            int attributeIndexForVerifier,
            VerifierRangeProofParameters.ProofType proofType,
            DateTime targetDate,
            int minYear,
            int maxYear)

        {
            // Verify target attribute is not hashed
            if (verifier.IP.E[attributeIndexForVerifier - 1] == 0x01)
            {
                return false;
            }


            // Verify UProve Integration Proof
            if (this.UPIProof == null)
            {
                return false;
            }
            VerifierPresentationProtocolParameters[] verifiers = new VerifierPresentationProtocolParameters[1] { verifier};
            int[] attributeIndices = new int[1] { attributeIndexForVerifier};
            if (!this.UPIProof.Verify(verifiers, attributeIndices))
            {
                return false;
            }

            // Verify Range Proof
            VerifierRangeProofParameters rangeVerifier = RangeProofParameterFactory.GetDateTimeVerifierParameters(
                new CryptoParameters(verifier.IP),
                this.UPIProof.PedersenCommitmentValues[0],
                proofType,
                targetDate,
                minYear,
                maxYear);
            return this.Verify(rangeVerifier);
        }

        public bool Verify(
            VerifierPresentationProtocolParameters verifier1,
            int attributeIndexForVerifier1,
            VerifierRangeProofParameters.ProofType proofType,
            VerifierPresentationProtocolParameters verifier2,
            int attributeIndexForVerifier2,
            int minYear,
            int maxYear)
        {
            // Verify target attribute is not hashed
            if ((verifier1.IP.E[attributeIndexForVerifier1 - 1] == 0x01) || (verifier2.IP.E[attributeIndexForVerifier1-1] == 0x01))
            {
                return false;
            }


            // Verify UProve Integration Proof
            if (this.UPIProof == null)
            {
                return false;
            }
            VerifierPresentationProtocolParameters[] verifiers = new VerifierPresentationProtocolParameters[2] { verifier1, verifier2 };
            int[] attributeIndices = new int[2] { attributeIndexForVerifier1, attributeIndexForVerifier2 };
            if (!this.UPIProof.Verify(verifiers, attributeIndices))
            {
                return false;
            }

            // Verify Range Proof
            VerifierRangeProofParameters rangeVerifier = new VerifierRangeProofParameters(
                new CryptoParameters(verifier1.IP),
                this.UPIProof.PedersenCommitmentValues[0],
                proofType,
                this.UPIProof.PedersenCommitmentValues[1],
                minYear,
                maxYear);
            return this.Verify(rangeVerifier);
        }

        #endregion



        #region Serialization
        /// <summary>
        /// Serialize A
        /// </summary>
        [DataMember(Name = "A", EmitDefaultValue = false)]
        internal string[] _a;

        /// <summary>
        /// Serialize B
        /// </summary>
        [DataMember(Name = "B", EmitDefaultValue = false)]
        internal string[] _b;

        /// <summary>
        /// Serialize X[1]....X[n-1]
        /// </summary>
        [DataMember(Name = "X", EmitDefaultValue = false)]
        internal string[] _x;

        /// <summary>
        /// Serialize D[1]....D[n-1]
        /// </summary>
        [DataMember(Name = "D", EmitDefaultValue = false)]
        internal string[] _d;

        /// <summary>
        /// Serialize A,B,X,D
        /// </summary>
        /// <param name="context"></param>
        [OnSerializing]
        internal void OnSerializing(StreamingContext context)
        {
            // check lengths of arrays A, B, X, D
            if((A == null) || (X == null) || (D == null)
                || (A.Length != X.Length) 
                || (A.Length != D.Length) 
                || ((B != null) && (B.Length != A.Length)))
            {
                throw new SerializationException("Arrays A, B, X, and D must have the same length.");
            }

            // serialize A
            _a = CryptoSerializer.SerializeGroupElementArray(A, "A");
            if (this.B != null)
            {
                _b = CryptoSerializer.SerializeGroupElementArray(B, "B");
            }
            _x = CryptoSerializer.SerializeGroupElementArray(X, 1, X.Length - 1, "X");
            _d = CryptoSerializer.SerializeGroupElementArray(D, 1, D.Length - 1, "D");
        }

        /// <summary>
        /// Deserialize A,B,X,D, as well as all proofs.
        /// </summary>
        public override void FinishDeserializing()
        { 
            // deserialize A
            this.A = CryptoSerializer.DeserializeGroupElementArray(_a, "A", this.Group);
            int length = A.Length;
            if (this._b != null)
            {
                this.B = CryptoSerializer.DeserializeGroupElementArray(_b, "B", this.Group);
            }
            this.X = CryptoSerializer.DeserializeGroupElementArray(_x, 1, _x.Length + 1, "X", this.Group);
            this.D = CryptoSerializer.DeserializeGroupElementArray(_d, 1, _d.Length + 1, "D", this.Group);

            if (this.ProofBitDecompositionOfA != null)
            {
                this.ProofBitDecompositionOfA.FinishDeserializing(this.Group);
            }
            if (this.ProofBitDecompositionOfB != null)
            {
                this.ProofBitDecompositionOfB.FinishDeserializing(this.Group);
            }
            if (this.FullRangeProof != null)
            {
                this.FullRangeProof.FinishDeserializing(this.Group);
            }
            if (this.OrEqualToProof != null)
            {
                this.OrEqualToProof.FinishDeserializing(this.Group);
            }
            if (this.StrictlyThanProof != null)
            {
                this.StrictlyThanProof.FinishDeserializing(this.Group);
            }
            if (this.UPIProof != null)
            {
                this.UPIProof.FinishDeserializing(this.Group);
            }
        }


        #endregion

    }
}
