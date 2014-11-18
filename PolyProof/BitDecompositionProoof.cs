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
using UProveCrypto.PolyProof;
using System.Collections;
using System.Runtime.Serialization;

namespace UProveCrypto.PolyProof
{
    [DataContract]
    public class BitDecompositionProof : GroupParameterizedSerializer
    {

        /// <summary>
        /// Proof that each PedersenCommitment is a commitment to 0 or 1.
        /// </summary>
        [DataMember(Name = "BitProof", EmitDefaultValue = false, Order = 1)]
        private SetMembershipProof[] bitCommitmentProof;

        /// <summary>
        /// Proof that the committed bits a the bit decomposition of the correct value.
        /// </summary>
        [DataMember(Name = "CompositionProof", EmitDefaultValue = false, Order = 2)]
        private EqualityProof compositionProof;

        /// <summary>
        /// Creates a bit decomposition proof for the given parameters. Throws
        /// an exception on failure.
        /// </summary>
        /// <param name="prover">Prover parameters.</param>
        public BitDecompositionProof(ProverBitDecompositionParameters prover)
        {
            ConstructorHelper(prover);
        }

        public void ConstructorHelper(ProverBitDecompositionParameters prover)
        {
            try
            {
                if (!prover.Verify())
                {
                    throw new ArgumentException("Could not create BitDecompositionProof because prover parameters are invalid.");
                }

                this.Group = prover.Group;
                this.IsGroupSerializable = true;

                // Generate proof that each Pedersen Commitment in prover.OpenBitDecomposition
                // is a valid commitment to either 0 or 1.
                this.bitCommitmentProof = new SetMembershipProof[prover.DecompositionLength];
                FieldZqElement[] memberSet = BitDecompositionProof.SetOfZeroAndOne(prover);
                for (int proofIndex = 0; proofIndex < bitCommitmentProof.Length; ++proofIndex)
                {
                    ProverSetMembershipParameters psmParameters = new ProverSetMembershipParameters(
                        prover.OpenBitDecomposition(proofIndex),
                        memberSet,
                        prover);
                    bitCommitmentProof[proofIndex] = new SetMembershipProof(psmParameters);
                    bitCommitmentProof[proofIndex].IsGroupSerializable = false;
                }

                //now create proof that actualComposedBits and parameters.OpenCommitment are
                //commitments to the same value.
                PedersenCommitment actualComposedBits;
                if (ComposeCommitments(prover.OpenBitDecomposition(), prover.FieldZq, out actualComposedBits))
                {
                    ProverEqualityParameters peParameters =
                        new ProverEqualityParameters(
                            actualComposedBits,
                            0,
                            prover.OpenCommitment,
                            0,
                            prover);
                    this.compositionProof = new EqualityProof(peParameters);
                    this.compositionProof.IsGroupSerializable = false;
                }
                else
                {
                    throw new Exception("Could not create BitDecompositionProof.");
                }

            }
            catch (Exception e)
            {
                throw e;
            }
        }

        /// <summary>
        /// Checks that this bit decomposition proof is valid with respect to
        /// the given verifier parameters.
        /// </summary>
        /// <param name="verifier">Verifier parameters.</param>
        /// <returns>True if this proof is valid, false otherwise.</returns>
        public bool Verify(VerifierBitDecompositionParameters verifier)
        {
            try
            {
                // check verifier parameters
                if (!verifier.Verify())
                {
                    return false;
                }

                // check each set membership proof
                VerifierSetMembershipParameters smParameters = new VerifierSetMembershipParameters(verifier);
                FieldZqElement[] memberSet = SetOfZeroAndOne(verifier);
                for (int committedBitIndex = 0; committedBitIndex < this.bitCommitmentProof.Length; ++committedBitIndex)
                {
                    GroupElement committedBit = verifier.ClosedBitDecomposition(committedBitIndex);
                    smParameters.setVerifierParameters(committedBit, memberSet);
                    if (!this.bitCommitmentProof[committedBitIndex].Verify(smParameters))
                    {
                        return false;
                    }
                }

                // check the composition proof
                GroupElement actualComposedValue = ComposeClosedCommittedBits(verifier.ClosedBitDecomposition(), verifier);
                GroupElement[] bases = new GroupElement[2] { verifier.G, verifier.H };
                VerifierEqualityParameters veParameters = new VerifierEqualityParameters(
                    new ClosedDLRepOfGroupElement(bases, actualComposedValue, verifier.Group),
                    0,
                    new ClosedDLRepOfGroupElement(bases, verifier.ClosedCommitment, verifier.Group),
                    0,
                    verifier);

                if (!this.compositionProof.Verify(veParameters))
                {
                    return false;
                }
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Takes as input a series of commitments to 0 and 1, and composes them into a single Pedersen commitment:
        /// output.CommittedValue = product (2^i * committedBits[i].CommittedValue)
        /// </summary>
        /// <param name="committedBits">Array of commitments to Zero and One. Each commitment must use the same bases G and H.</param>
        /// <param name="fieldZq">Field corresponding to all PedersenCommitments</param>
        /// <param name="composition">Output paramter.</param>
        /// <returns>True on success, false on failure.</returns>
        private static bool ComposeCommitments(PedersenCommitment[] committedBits, FieldZq fieldZq, out PedersenCommitment composition)
        {
            try
            {
                FieldZqElement two = fieldZq.GetElement(2);
                FieldZqElement powerOfTwo = fieldZq.One;
                DLRepOfGroupElement[] bitsExpPowerOfTwo = new DLRepOfGroupElement[committedBits.Length];
                for (int i = 0; i < committedBits.Length; ++i)
                {
                    bitsExpPowerOfTwo[i] = committedBits[i].Exponentiate(powerOfTwo);
                    powerOfTwo = powerOfTwo * two;
                }
                DLRepOfGroupElement actualComposition;
                bool success = DLRepOfGroupElement.TryStrictMultiply(bitsExpPowerOfTwo, out actualComposition);
                if(success)
                {
                    composition = new PedersenCommitment(actualComposition);
                    return true;
                }
            }
            catch (Exception)
            {
                // do nothing
            }
            composition = null;
            return false;
        }

        /// <summary>
        /// Computes: output = product closedBitDecomposition[i] ^ (2^i)
        /// </summary>
        /// <param name="closedBitDecomposition">Array of group elements, none of which may be null.</param>
        /// <param name="parameters">Crypto parameters.</param>
        /// <returns></returns>
        private static GroupElement ComposeClosedCommittedBits(GroupElement[] closedBitDecomposition, CryptoParameters parameters)
        {
            FieldZqElement two = parameters.FieldZq.GetElement(2);
            FieldZqElement[] exponents = new FieldZqElement[closedBitDecomposition.Length];
            exponents[0] = parameters.FieldZq.One;
            for (int i = 1; i < exponents.Length; ++i)
            {
                exponents[i] = exponents[i-1]*two;
            }
            return parameters.Group.MultiExponentiate(closedBitDecomposition, exponents);
        }


        /// <summary>
        /// Returns an array containing Zero and One in parameters.FieldZq
        /// </summary>
        /// <param name="parameters">parameters</param>
        /// <returns>Array containing Zero and One, in that order.</returns>
        private static FieldZqElement[] SetOfZeroAndOne(CryptoParameters parameters)
        {
            FieldZqElement[] memberSet = new FieldZqElement[2]
            {
                parameters.FieldZq.Zero,
                parameters.FieldZq.One
            };
            return memberSet;
        }


        #region Serialization

        [OnSerializing]
        internal void OnSerializing(StreamingContext context)
        {
           // do nothing
        }

        /// <summary>
        /// Deserialize the bitCommitmentProofs and compositionProof.
        /// </summary>
        public override void FinishDeserializing()
        {
            if (this.bitCommitmentProof != null)
            {
                for (int i = 0; i < this.bitCommitmentProof.Length; i++)
                {
                    this.bitCommitmentProof[i].FinishDeserializing(this.Group);
                }
            }

            if (this.compositionProof != null)
            {
                this.compositionProof.FinishDeserializing(this.Group);
            }

        }
        
        #endregion


    }
}
