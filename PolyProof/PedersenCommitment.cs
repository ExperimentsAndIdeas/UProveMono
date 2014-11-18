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

namespace UProveCrypto.PolyProof
{

    /// <summary>
    /// Class representing a Pedersen Commitment with unknown committed value
    /// and opening. In other words, an UnknownDLRepOfGroupElement with
    /// exactly two bases.
    /// </summary>
    [DataContract]
    public class ClosedPedersenCommitment : ClosedDLRepOfGroupElement
    {
        /// <summary>
        /// Convenience accessor for BaseAtIndex(0)
        /// </summary>
        public GroupElement G
        {
            get { return this.BaseAtIndex(0); }
        }

        /// <summary>
        /// Convenience accessor for BaseAtIndex(1)
        /// </summary>
        public GroupElement H
        {
            get { return this.BaseAtIndex(1); }
        }


        /// <summary>
        /// Constructor checks that bases is an array with exactly two elements,
        /// </summary>
        /// <param name="bases"></param>
        /// <param name="value"></param>
        /// <param name="Group"></param>
        public ClosedPedersenCommitment(GroupElement[] bases, GroupElement value, Group group)
            : base(bases, value, group)
        {
            if (bases.Length != 2)
            {
                throw new ArgumentException("Representation length should be 2");
            }

        }

        /// <summary>
        /// Transforms ClosedDLRepOfGroupElement object into ClosedPedersenCommitment.
        /// </summary>
        /// <param name="dl"></param>
        public ClosedPedersenCommitment(ClosedDLRepOfGroupElement dl)
        {
            if ((dl == null) || (dl.RepresentationLength != 2))
            {
                throw new ArgumentException("Cannot convert input into Pedersen Commitment");
            }

            this.Bases = new GroupElement[2] { dl.BaseAtIndex(0), dl.BaseAtIndex(1) };
            this.Group = dl.Group;
            this.Value = dl.Value;
        }

        /// <summary>
        /// Creates a closed commitment from one of the commitments created by a presentation proof.
        /// This is a UProve integration method that should be called by the Verifier.
        /// </summary>
        /// <param name="ip">Issuer parameters</param>
        /// <param name="proof">token presentation proof</param>
        /// <param name="commitmentIndex">which commitment</param>
        public ClosedPedersenCommitment(IssuerParameters ip, PresentationProof proof, int commitmentIndex)
        {
            this.Value = proof.Commitments[commitmentIndex].TildeC;

            CryptoParameters crypto = new CryptoParameters(ip);
            this.Group = crypto.Group;
            this.Bases = new GroupElement[2] { crypto.Generators[0], crypto.Generators[1] };
        }

        /// <summary>
        /// Creates a closed commitment using default generators from the IssuerParameters.
        /// </summary>
        /// <param name="ip">Issuer parameters</param>
        /// <param name="value">Value of commitment</param>
        public ClosedPedersenCommitment(IssuerParameters ip, GroupElement value)
        {
            this.Value = value;

            CryptoParameters crypto = new CryptoParameters(ip);
            this.Group = crypto.Group;
            this.Bases = new GroupElement[2] { crypto.Generators[0], crypto.Generators[1] };
        }

        /// <summary>
        /// Returns all Closed Pedersen Commitments associated with a presentation proof.
        /// This is a UProve integration function that is called by the verifier.
        /// </summary>
        /// <param name="ip">Issuer Parameters</param>
        /// <param name="proof">Instance of the proof presentation protocol</param>
        /// <returns></returns>
        public static ClosedPedersenCommitment[] ArrayOfClosedPedersenCommitments(IssuerParameters ip, PresentationProof proof)
        {
            ClosedPedersenCommitment[] closedPed = new ClosedPedersenCommitment[proof.Commitments.Length];
            for (int i = 0; i < closedPed.Length; ++i)
            {
                closedPed[i] = new ClosedPedersenCommitment(ip, proof, i);
            }
            return closedPed;
        }

        /// <summary>
        /// Takes the commitment map from UProve presentation proof protocol parameters and
        /// returns the attribute index (0 based index) for a particular commitment index.
        /// This method should be used with ArrayOfClosedPedersenCommitments and
        /// ArrayofPedersenCommitments.
        /// UProve integration method.
        /// </summary>
        /// <param name="committed">The commitment mapping from the ProverPresentationProtocolParameters or the VerifierPresentationProtocolParameters</param>
        /// <param name="commitmentIndex">Index into the commitment map.</param>
        /// <returns></returns>
        public static int GetAttributeIndex(int [] committed, int commitmentIndex)
        {
            return committed[commitmentIndex] -1;
        }

        /// <summary>
        /// Returns the index for the commitment associated with attribute index.
        /// This method should be used with ArrayOfClosedPedersenCommitments and
        /// ArrayofPedersenCommitments.
        /// UProve integration method.
        /// </summary>
        /// <param name="committed">Commitment map found in ProverPresentationProtocolParameters and VerifierPresentationProtocolParameters.</param>
        /// <param name="attributeIndex">1-based index of the committed token attribute.</param>
        /// <returns></returns>
        public static int GetCommitmentIndex(int []committed, int attributeIndex)
        {
            for (int commitmentIndex = 0; commitmentIndex < committed.Length; ++commitmentIndex)
            {
                if (committed[commitmentIndex] == attributeIndex)
                {
                    return commitmentIndex;
                }
            }
            throw new Exception("Could not find attributeIndex");
        }

        /// <summary>
        /// Returns true if this is a valid ClosedPedersenCommitment
        /// </summary>
        /// <returns></returns>
        public bool Validate()
        {
            if ((this.RepresentationLength != 2)
                || (this.Value == null)
                ||(this.BaseAtIndex(0) == this.BaseAtIndex(1))
                || (this.BaseAtIndex(0) == null)
                || (this.BaseAtIndex(1) == null))
            {
                return false;
            }
            return true;
        }
    }




    /// <summary>
    /// A PedersenCommitment is a DLRepOfGroupElement that has RepresentationLength of exactly 2.
    /// </summary>
    [DataContract]
    public class PedersenCommitment : DLRepOfGroupElement
    {
        /// <summary>
        /// Convenience accessor for BaseAtIndex(0)
        /// </summary>
        public GroupElement G
        {
            get { return this.BaseAtIndex(0); }
        }

        /// <summary>
        /// Convenience accessor for BaseAtIndex(1)
        /// </summary>
        public GroupElement H
        {
            get { return this.BaseAtIndex(1); }
        }


        /// <summary>
        /// Constructor. Creates a PedersenCommitment where value = g^x h^y
        /// </summary>
        /// <param name="g">First base, will have index 0.</param>
        /// <param name="h">Second base, will have index 1.</param>
        /// <param name="x">First exponent, will have index 0, corresponds to CommittedValue.</param>
        /// <param name="y">Second exponent, will have index 1, corresponds to Opening.</param>
        /// <param name="group">Group of which g and h are members.</param>
	    public PedersenCommitment(GroupElement g, GroupElement h, FieldZqElement x, FieldZqElement y, Group group) 
            : base(new GroupElement[2]{g,h}, new FieldZqElement[2]{x,y}, group)
	    {
	    }

        /// <summary>
        /// Constructor.  Creates a PedersenCommitment where value = bases[0]^exponents[0] * bases[1]^exponents[1]
        /// Throws exception if bases or exponents are not arrays of exactly length 2.
        /// </summary>
        /// <param name="bases">Array containing exactly two bases.</param>
        /// <param name="exponents">Array containing exactly two exponents.</param>
        /// <param name="group">Group of which bases are members.</param>
        public PedersenCommitment(GroupElement[] bases, FieldZqElement[] exponents, Group group)
            : base(bases, exponents, group)
        {
            if ((bases == null) || (exponents == null) || (group==null) 
                ||(bases.Length != 2) || (exponents.Length != 2))
            {
                throw new Exception("Expects input arrays of length 2");
            }
        }

        /// <summary>
        /// Creates a Pedersen Commitment to committedValue. Uses parameterSet to
        /// choose two bases, and chooses a random opening for the second exponent.
        /// </summary>
        /// <param name="committedValue"></param>
        /// <param name="parameters"></param>
        public PedersenCommitment(FieldZqElement committedValue, CryptoParameters parameters)
        {
            this.Group = parameters.Group;
            FieldZqElement[] exponents = new FieldZqElement[2];
            exponents[0] = committedValue; 
            exponents[1] = parameters.FieldZq.GetRandomElement(true);
            GroupElement[] bases = new GroupElement[2] { parameters.G, parameters.H };
            this.ComputeValue(bases, exponents);
        }

        public PedersenCommitment(DLRepOfGroupElement dl)
        {
            if ((dl == null) || (dl.RepresentationLength != 2))
            {
                throw new ArgumentException("Cannot convert input into Pedersen Commitment");
            }

            GroupElement [] bases = new GroupElement[2] { dl.BaseAtIndex(0), dl.BaseAtIndex(1) };
            FieldZqElement[] exponents = new FieldZqElement[] { dl.ExponentAtIndex(0), dl.ExponentAtIndex(1) };
            this.Group = dl.Group;
            this.ComputeValue(bases, exponents);
        }

        /// <summary>
        /// Creates a Pedersen Commitment for one of the attributes using the commitment 
        /// from the PresentationProof.
        /// </summary>
        /// <param name="pppp">Parameters used by Prover</param>
        /// <param name="pp">The presentation proof generated by the Prover</param>
        /// <param name="cpv">Output of PresentationProof.Generate()</param>
        /// <param name="commitmentIndex">Which commitment to use: index into cpv.TildeO array.
        ///                         DO NOT use the attribute index, the Constructor will compute it from
        ///                         the commitmentIndex.</param>
        public PedersenCommitment(ProverPresentationProtocolParameters pppp, PresentationProof pp, CommitmentPrivateValues cpv, int commitmentIndex)
        {
            int attributeIndex = pppp.Committed[commitmentIndex] -1;
            FieldZqElement committedValue = ProtocolHelper.ComputeXi(pppp.IP, attributeIndex,pppp.Attributes[attributeIndex]);
            FieldZqElement opening = cpv.TildeO[commitmentIndex];

            CryptoParameters crypto = new CryptoParameters(pppp.IP);
            this.Group = crypto.Group;
            this.Bases = new GroupElement[2] { crypto.Generators[0], crypto.Generators[1] };
            this.Exponents = new FieldZqElement[2] { committedValue, opening };
            this.Value = pp.Commitments[commitmentIndex].TildeC;
        }

        /// <summary>
        /// Generates a Pedersen Commitment to the attribute.  The committed value is equal to 
        /// what it would be if the attribute was encoded in the token.  The committed value depends
        /// on the attribute index.
        /// </summary>
        /// <param name="ip">Issuer parameters</param>
        /// <param name="attributeIndex">The 1-based index of the attribute as it would be in the token</param>
        /// <param name="attribute">Encoding of the attribute</param>
        public PedersenCommitment(IssuerParameters ip, int attributeIndex, byte[] attribute)
        {
            CryptoParameters crypto = new CryptoParameters(ip);
            this.Group = crypto.Group;
            this.Bases = new GroupElement[2] { crypto.Generators[0], crypto.Generators[1] };
            FieldZqElement committedValue = ProtocolHelper.ComputeXi(ip, attributeIndex - 1, attribute);
            FieldZqElement opening = this.Group.FieldZq.GetRandomElement(false);
            this.Exponents = new FieldZqElement[2] { committedValue, opening };
            this.Value = this.Group.MultiExponentiate(this.Bases, this.Exponents);
        }

        /// <summary>
        /// Creates an array of Pedersen Commitments from the ProverPresentationProtocolParameters
        /// and the CommitmentPrivateValues.  This is a convenience method for generating the
        /// Pedersen commitments output by the PresentationProof.Generate() method.
        /// </summary>
        /// <param name="pppp">The Prover parameters.</param>
        /// <param name="pp">The presentation proof.</param>
        /// <param name="cpv">The commitment private values.</param>
        /// <returns></returns>
        public static PedersenCommitment [] ArrayOfPedersenCommitments(ProverPresentationProtocolParameters pppp, PresentationProof pp, CommitmentPrivateValues cpv)
        {
            PedersenCommitment[] pedersenCommitments = new PedersenCommitment[cpv.TildeO.Length];
            for (int index = 0; index < pedersenCommitments.Length; ++index)
            {
                pedersenCommitments[index] = new PedersenCommitment(pppp, pp, cpv, index);
            }
            return pedersenCommitments;
        }

        /// <summary>
        /// Creates an array of PedersenCommitments to the specified attributes
        /// </summary>
        /// <param name="prover">Array of tokens</param>
        /// <param name="attributeIndices">Attribute to commit in token (1-based array)</param>
        /// <returns>Array of PedersenCommitments</returns>
        public static PedersenCommitment[] PedersenCommmitmentsToAttributes(ProverPresentationProtocolParameters[] prover = null, int[] attributeIndices = null)
        {
            if ((prover == null) || (prover.Length == null))
            {
                throw new ArgumentException("First argument must be an array of at least one element.");
            }

            if (attributeIndices == null)
            {
                throw new ArgumentNullException("Second argument may not be null if first argument is not null.");
            }

            if (prover.Length != attributeIndices.Length)
            {
                throw new ArgumentException("Prover array and attribute index array must be of equal length.");
            }

            PedersenCommitment[] peds = new PedersenCommitment[prover.Length];
            for (int i = 0; i < peds.Length; ++i)
            {
                peds[i] = new PedersenCommitment(prover[i].IP, attributeIndices[i], prover[i].Attributes[attributeIndices[i] - 1]);
            }

            return peds;
        }



        public static PedersenCommitment[] GetCommitments(CryptoParameters crypto, FieldZqElement[] committedValues, FieldZqElement[] openings)
        {
            if ((crypto == null) || (committedValues == null) || (openings == null)
                || (committedValues.Length != openings.Length))
            {
                throw new ArgumentException("GetCommitments expects non-null input, with arrays committedValues and openings of the same length.");
            }

            PedersenCommitment [] commitments = new PedersenCommitment[committedValues.Length];
            for (int i = 0; i < committedValues.Length; ++i)
            {
                PedersenCommitment ped = new PedersenCommitment(
                    crypto.G,
                    crypto.H,
                    committedValues[i],
                    openings[i],
                    crypto.Group);
                    commitments[i] = ped;
            }
            return commitments;
        }

        public static GroupElement[] GetCommitmentValues(CryptoParameters crypto, FieldZqElement[] committedValues, FieldZqElement[] openings)
        {
            if ((crypto == null) || (committedValues == null) || (openings == null)
                || (committedValues.Length != openings.Length))
            {
                throw new ArgumentException("GetCommitmentValues expects non-null input, with arrays committedValues and openings of the same length.");
            }

            GroupElement[] values = new GroupElement[committedValues.Length];
            for (int i = 0; i < committedValues.Length; ++i)
            {
                PedersenCommitment ped = new PedersenCommitment(
                    crypto.G,
                    crypto.H,
                    committedValues[i],
                    openings[i],
                    crypto.Group);
                values[i] = ped.Value;
            }
            return values;
        }


        /// <summary>
        /// Constructs a new UnknownDlRepOfGroupElement that has the same
        /// bases, value, group, and fieldZq.
        /// </summary>
        /// <returns>New UnknownDlRepOfGroupElement object.</returns>
 /*       public new ClosedPedersenCommitment GetClosed()
        {
            return new ClosedPedersenCommitment(
                this.Bases,
                this.Value,
                this.Group);
        }
  */

        public bool Validate()
        {
            if ((this.RepresentationLength != 2)
                || (this.Value == null)
                || (this.BaseAtIndex(0) == this.BaseAtIndex(1))
                || (this.BaseAtIndex(0) == null)
                || (this.BaseAtIndex(1) == null)
                || (this.ExponentAtIndex(0) == null)
                || (this.ExponentAtIndex(1) == null)
                || (this.Group.MultiExponentiate(this.Bases, this.Exponents) != this.Value))
            {
                return false;
            }
            return true;
        }

        public FieldZqElement CommittedValue
        {
            get { return this.ExponentAtIndex(0); }
        }

        public FieldZqElement Opening
        {
            get { return this.ExponentAtIndex(1); }
        }


    }

}
