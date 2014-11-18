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
using System.Collections;
using UProveCrypto;
using UProveCrypto.Math;
using UProveCrypto.PolyProof;
using System.Runtime.Serialization;

namespace UProveCrypto.PolyProof
{
    /// <summary>
    /// Container class for the parameters used by the Prover and Verifier
    /// </summary>
    [DataContract]
    public class VerifierBitDecompositionParameters : ProofParameters
    {

#region Properties
        /// <summary>
        /// Value of a Pedersen Commitment.
        /// </summary>
        public GroupElement ClosedCommitment {
            get
            {
                if ((this.PublicValues == null) || (this.PublicValues.Length < 1))
                {
                    return null;
                }
                return (GroupElement)this.PublicValues[this.PublicValues.Length - 1];
            }
        }

        /// <summary>
        /// Number of bits in the bit decomposition.
        /// </summary>
        public int DecompositionLength
        {
            get
            {
                if ((this.PublicValues == null) || (this.PublicValues.Length == 0))
                {
                    return 0;
                }
                return this.PublicValues.Length - 1;
            }

        }

#endregion

        /// <summary>
        /// Constructor. Sets cryptographic parameters only.
        /// </summary>
        /// <param name="parameters">Cryptographic parameters.</param>
        public VerifierBitDecompositionParameters(CryptoParameters parameters)
            : base(parameters)
        {
            this.setVerifierParameters(null, null);
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="closedCommitment">Value of Pedersen Commitment.</param>
        /// <param name="closedCommittedBits">Array of Pedersen Commitments to a sequence of bits.</param>
        /// <param name="parameters">Cryptographic parameters.</param>
        public VerifierBitDecompositionParameters(
            GroupElement closedCommitment,
            GroupElement[] closedCommittedBits,
            CryptoParameters parameters): base (parameters)
        {
            this.setVerifierParameters(closedCommittedBits, closedCommitment);
        }

        /// <summary>
        /// Sets verifier parameters.
        /// </summary>
        /// <param name="closedCommittedBits">Array of Pedersen Commitments to a sequence of bits.</param>
        /// <param name="closedCommitment">Value of Pedersen Commitment.</param>
        public void setVerifierParameters(GroupElement [] closedCommittedBits, GroupElement closedCommitment)
        {
            if ((closedCommittedBits == null)
                || (closedCommitment == null))
            {
                base.setVerifierParameters(null);
                return;
            }
            GroupElement[] publicValues = new GroupElement[ closedCommittedBits.Length + 1];
            for (int i = 0; i < closedCommittedBits.Length; ++i)
            {
                publicValues[i] = closedCommittedBits[i];
            }
            publicValues[publicValues.Length-1] = closedCommitment;
            this.setVerifierParameters(publicValues);
        }

        /// <summary>
        /// Sets verifier parameters for situations when the committed value is known
        /// to the verifier.  Computes the bit decomposition for committedValue
        /// ClosedCommittment = G^committedValue
        /// ClosedCommittedBit[i] = G^bit[i]
        /// </summary>
        /// <param name="committedValue">Committed value.</param>
        /// <param name="decompositionLength">Minimum bit decomposition length.</param>
        public void setVerifierParameters(FieldZqElement committedValue, int decompositionLength)
        {
            if (committedValue == null)
            {
                base.setVerifierParameters(null);
                return;
            }
            BitArray commitedBits = VerifierBitDecompositionParameters.GetBitDecomposition(committedValue, decompositionLength, this.FieldZq);
            GroupElement[] publicValues = new GroupElement[commitedBits.Length + 1];
            for (int i = 0; i < commitedBits.Length; ++i)
            {
                if (! commitedBits.Get(i))
                {
                    publicValues[i] = this.Group.Identity;
                }
                else
                {
                    publicValues[i] = this.G;
                }
            }
            publicValues[publicValues.Length - 1] = this.G.Exponentiate(committedValue);
            this.setVerifierParameters(publicValues);
        }

        /// <summary>
        /// Returns Pedersen Commitment to one of the bits in the bit decomposition.
        /// </summary>
        /// <param name="index">Which bit to return.</param>
        /// <returns></returns>
        public GroupElement ClosedBitDecomposition(int index)
        {
            return this.PublicValues[index];
        }

        /// <summary>
        /// Returns all Pedersen Commitments in the bit decomposition, with the commitment to the
        /// least significant bit first.
        /// </summary>
        /// <returns></returns>
        public GroupElement[] ClosedBitDecomposition()
        {
            GroupElement[] output = new GroupElement[this.DecompositionLength];
            for (int i = 0; i < output.Length; ++i)
            {
                output[i] = this.ClosedBitDecomposition(i);
            }
            return output;
        }

        /// <summary>
        /// Returns an array of Zero and One FieldZqElements, in Small Endian notation.
        /// So sum result[i] * 2^i = integer.  If decompositionLength is too short,
        /// returns the minimum length array with the correct decomposition.
        /// </summary>
        /// <param name="integer">Integer to decompose</param>
        /// <param name="decompositionLength">Minimum number of bits.</param>
        /// <param name="fieldZq">Field</param>
        /// <returns></returns>
        public static BitArray GetBitDecomposition(FieldZqElement integer, int decompositionLength, FieldZq fieldZq)
        {
            // get bit array
            BitArray bits = new BitArray(VerifierBitDecompositionParameters.Reverse(integer.ToByteArray()));

            // compute minimum decompositionLength
            if ((decompositionLength < IndexOfMostSignificantNonZeroBit(bits) + 1))
            {
                decompositionLength = IndexOfMostSignificantNonZeroBit(bits) + 1;
            }

            // translate bits into array of FieldZqElements
            BitArray bitDecomposition = new BitArray(decompositionLength);
            for (int bitIndex = 0; bitIndex < bitDecomposition.Length; ++bitIndex)
            {
                if ((bitIndex < bits.Length) && bits.Get(bitIndex))
                {
                    bitDecomposition.Set(bitIndex, true);
                }
                else
                {
                    bitDecomposition.Set(bitIndex, false);
                }
            }
            return bitDecomposition;
        }

        /// <summary>
        /// Returns the index of the most significant non-zero bit. Goes through
        /// array from the end to the start, and returns the index of the first non-zero bit.
        /// </summary>
        /// <param name="bits"></param>
        /// <returns></returns>
        public static int IndexOfMostSignificantNonZeroBit(BitArray bits)
        {
            for (int index = bits.Length - 1; index > 0; --index)
            {
                if (bits.Get(index))
                {
                    return index;
                }
            }
            return 0;
        }

        /// <summary>
        /// Returns the array in revese order.
        /// </summary>
        /// <param name="array"></param>
        /// <returns></returns>
        public static byte[] Reverse(byte[] array)
        {
            if (array == null)
            {
                return null;
            }
            byte[] reverseArray = new byte[array.Length];
            for (int i = 0; i < reverseArray.Length; ++i)
            {
                reverseArray[i] = array[array.Length - i - 1];
            }
            return reverseArray;
        }

        /// <summary>
        /// Takes as input a bit decomposition of some FieldZqElement and computes it.
        /// </summary>
        /// <param name="bitDecomposition">Array of zero and one in the field, in little endian order.</param>
        /// <param name="fieldZq">Field Zq</param>
        /// <returns>sum bitDecomposition[i] * 2^i</returns>
        public static FieldZqElement GetBitComposition(BitArray bitDecomposition, FieldZq fieldZq)
        {
            FieldZqElement powerOfTwo = fieldZq.One;
            FieldZqElement two = fieldZq.One + fieldZq.One;
            FieldZqElement composition = fieldZq.Zero;
            for (int exponent = 0; exponent < bitDecomposition.Length; ++exponent)
            {
                if (bitDecomposition.Get(exponent))
                {
                    composition += powerOfTwo;
                }
                powerOfTwo *= two;
            }
            return composition;
        }

        /// <summary>
        /// Reverses the BitArray.
        /// </summary>
        /// <param name="bits"></param>
        /// <returns></returns>
        public static BitArray ReverseBitArray(BitArray bits)
        {
            if (bits == null)
            {
                return null;
            }
            BitArray reverse = new BitArray(bits.Length);
            for (int i = 0; i < reverse.Length; ++i)
            {
                reverse.Set(i, bits.Get(bits.Length - i - 1));
            }
            return reverse;
        }

    }

    /// <summary>
    /// Contains prover parameters for a bit decomposition proof.
    /// </summary>
    [DataContract]
    public class ProverBitDecompositionParameters : VerifierBitDecompositionParameters
    {
        /// <summary>
        /// Pedersen Commitment to a secret integer.
        /// </summary>
        public PedersenCommitment OpenCommitment
        {
            get
            {
                if ((this.Witnesses == null) || (this.Witnesses.Length < 1))
                {
                    return null;
                }
                return (PedersenCommitment)this.Witnesses[this.Witnesses.Length - 1];
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="openCommitment">Pedersen commitment about which proof is made</param>
        /// <param name="openBitDecompisition">Bit decompisition of openCommitment.CommittedValue.</param>
        /// <param name="parameterSet">Parameters</param>
        /// <param name="fieldZq">FieldZq associated with parameterSet.</param>
        public ProverBitDecompositionParameters(
            PedersenCommitment openCommitment,
            PedersenCommitment [] openBitDecomposition,
            CryptoParameters parameters) : base(parameters)
        {
            this.setProverParameters(openBitDecomposition, openCommitment);
        }

        /// <summary>
        /// Constructs a bit decomposition of openCommitment.CommittedValue and
        /// generates the appropriate ProverBitDecompositionParameters.
        /// If decompositionLength is too short, automatically chooses
        /// minimum required length.
        /// </summary>
        /// <param name="openCommitment">Pedersen Commitment to some value</param>
        /// <param name="decompositionLength">Number of bits in bit-decomposition.</param>
        /// <param name="parameterSet">Parameter set</param>
        /// <returns></returns>
        public  ProverBitDecompositionParameters(
            PedersenCommitment openCommitment,
            int decompositionLength,
            CryptoParameters crypto)
            : base(crypto)
        {
            BitArray bits = VerifierBitDecompositionParameters.GetBitDecomposition(openCommitment.CommittedValue, decompositionLength, this.FieldZq);
            PedersenCommitment [] openBitDecomposition = new PedersenCommitment[bits.Length];
            for (int bitIndex = 0; bitIndex < bits.Length; ++bitIndex)
            {
                if (bits.Get(bitIndex))
                {
                    openBitDecomposition[bitIndex] = new PedersenCommitment(crypto.FieldZq.One, crypto);
                }
                else
                {
                    openBitDecomposition[bitIndex] = new PedersenCommitment(crypto.FieldZq.Zero, crypto);
                }
            }
            this.setProverParameters(openBitDecomposition, openCommitment);
        }

        /// <summary>
        /// Constructor.  Takes as input an integer, creates a Pedersen Commitment to it, and generates
        /// a sequence of Pedersen Commitments to its bit decomposition.
        /// </summary>
        /// <param name="integer">Creates a Pedersen Commitment to this value.</param>
        /// <param name="decompositionLength">Minimum number of integers in the decomposition.</param>
        /// <param name="crypto">Cryptographic parameters.</param>
        /// <param name="hideCommittedValue">Decomposed integer is secret.</param>
        public ProverBitDecompositionParameters(FieldZqElement integer, int decompositionLength, CryptoParameters crypto, bool hideCommittedValue = true)
            : base(crypto)
        {
            BitArray bits = VerifierBitDecompositionParameters.GetBitDecomposition(integer, decompositionLength, this.FieldZq);
            PedersenCommitment[] openCommittedBits = new PedersenCommitment[bits.Length];
            PedersenCommitment openCommitment;
            if (hideCommittedValue)
            {
                for (int i = 0; i < bits.Length; ++i)
                {
                    FieldZqElement curBit = this.FieldZq.Zero;
                    if (bits.Get(i))
                    {
                        curBit = this.FieldZq.One;
                    }
                    openCommittedBits[i] = new PedersenCommitment(curBit, this);
                }
                openCommitment = new PedersenCommitment(integer, this);
            }
            else
            {
                for (int i = 0; i < bits.Length; ++i)
                {
                    FieldZqElement curBit = this.FieldZq.Zero;
                    if (bits.Get(i))
                    {
                        curBit = this.FieldZq.One;
                    }
                    openCommittedBits[i] = new PedersenCommitment(this.G, this.H, curBit, this.FieldZq.Zero, this.Group);
                }
                openCommitment = new PedersenCommitment(this.G, this.H, integer, this.FieldZq.Zero, this.Group);
            }
            this.setProverParameters(openCommittedBits, openCommitment);
        }

        /// <summary>
        /// Gets verifier parameters corresponding to this object.
        /// </summary>
        /// <returns></returns>
        public VerifierBitDecompositionParameters GetVerifierParameters()
        {
            VerifierBitDecompositionParameters verifierParams = new VerifierBitDecompositionParameters(
                this.ClosedCommitment,
                this.ClosedBitDecomposition(),
                this);
            return verifierParams;
        }

        /// <summary>
        /// Sets prover parameters.
        /// </summary>
        /// <param name="openCommittedBits">Bit decomposition.</param>
        /// <param name="openCommitment">Commited integer.</param>
        public void setProverParameters(PedersenCommitment[] openCommittedBits, PedersenCommitment openCommitment)
        {
            PedersenCommitment [] ped = new PedersenCommitment[openCommittedBits.Length + 1];
            for (int dlIndex = 0; dlIndex < openCommittedBits.Length; ++dlIndex)
            {
                ped[dlIndex] = openCommittedBits[dlIndex];
            }
            ped[ped.Length - 1] = openCommitment;
            this.setProverParameters(ped);
        }



        /// <summary>
        /// Returns Pedersen Commitment to a bit in the bit decomposition.
        /// </summary>
        /// <param name="index">Which bit.</param>
        /// <returns></returns>
        public PedersenCommitment OpenBitDecomposition(int index)
        {
            return (PedersenCommitment)this.Witnesses[index];
        }

        /// <summary>
        /// Returns entire bit decomposition.
        /// </summary>
        /// <returns></returns>
        public PedersenCommitment[] OpenBitDecomposition()
        {
            PedersenCommitment[] output = new PedersenCommitment[this.DecompositionLength];
            for (int i = 0; i < output.Length; ++i)
            {
                output[i] = this.OpenBitDecomposition(i);
            }
            return output;
        }

        /// <summary>
        /// Checks that these parameters can be used to create a BitDecomposition proof.
        /// </summary>
        /// <returns></returns>
        public new bool Verify()
        {
            if (!base.Verify())
            {
                return false;
            }

            // check that the openBitDecomposition is actually a bit
            // decomposition of the committed value;
            FieldZqElement actualComposedValue = this.FieldZq.Zero;
            FieldZqElement powerOfTwo = this.FieldZq.One;
            FieldZqElement two = this.FieldZq.One + this.FieldZq.One;
            for (int i = 0; i < this.DecompositionLength; ++i)
            {
                actualComposedValue = actualComposedValue + (powerOfTwo * this.OpenBitDecomposition(i).CommittedValue);
                powerOfTwo = powerOfTwo * two;
            }
            if (this.OpenCommitment.CommittedValue != actualComposedValue)
            {
                return false;
            }
            return true;
        }
    }
}
