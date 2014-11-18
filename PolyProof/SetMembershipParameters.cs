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
    /// Class that contains parameters used by the  Verifier to
    /// verify SetMembershipProof.
    /// 
    /// Prover has a PedersenCommitment OpenCommitment.  The value 
    /// OpenCommitment.CommittedValue is in MemberSet.
    /// 
    /// The Verifier knows MemberSet, and ClosedCommitment, which
    /// is equal to OpenCommitment.Value
    /// </summary>
    [DataContract]
    public class VerifierSetMembershipParameters : ProofParameters
    {
        /// <summary>
        /// Prover will show that a committed value is equal to one of these
        /// elements.  For the proof to work, both the Prover and Verifier must
        /// use an identical MemberSet (same elements, in the same order).
        /// </summary>
        public FieldZqElement[] MemberSet { get; set; }

        /// <summary>
        /// The value of a PedersenCommitment that contains a secret value.
        /// ClosedCommitment = OpenCommitment.Value (see ProverSetMembershipParameters).
        /// </summary>
        public GroupElement ClosedCommitment 
        { 
            get
            {
                if((this.PublicValues == null)
                    || (this.PublicValues.Length == 0))
                {
                    return null;
                }
                return this.PublicValues[0];
            }
            private set
            {
                GroupElement[] publicValues = new GroupElement[1] { value };
                this.setVerifierParameters(publicValues);
            }
        }

        /// <summary>
        /// Constructor. Creates an instance of VerifierSetMembershipParameters
        /// that is immediately ready to use (as long as closedCommitment and
        /// memberSet are not null).
        /// </summary>
        /// <param name="closedCommitment">ClosedCommitment</param>
        /// <param name="memberSet">MemberSet</param>
        /// <param name="parameters">Sets up the group, field, generators G and H, and hash function.
        ///     If null, will use default values.</param>
        public VerifierSetMembershipParameters(
            GroupElement closedCommitment,
            FieldZqElement [] memberSet,
            CryptoParameters parameters)
            : base(parameters)
        {
            this.MemberSet = memberSet;
            this.setVerifierParameters(closedCommitment, memberSet);
        }

        /// <summary>
        /// Sets up the CryptoParameters. Need to call setVerifierParameters before
        /// these parameters are ready to use in a proof.
        /// </summary>
        /// <param name="parameters">Sets up the group, field, generators G and H, and hash function.
        ///     If null, will use default values.</param>
        public VerifierSetMembershipParameters(CryptoParameters parameters)
            : base(parameters)
        {
            this.setVerifierParameters(null);
        }

        /// <summary>
        /// Sets the ClosedCommitment and MemberSet.
        /// </summary>
        /// <param name="closedCommitment">ClosedCommitment</param>
        /// <param name="memberSet">MemberSet</param>
        public void setVerifierParameters(GroupElement closedCommitment, FieldZqElement[] memberSet)
        {
            this.MemberSet = memberSet;
            this.setVerifierParameters(new GroupElement[] { closedCommitment });
        }

        /// <summary>
        /// Generates a member set for UProve tokens. 
        /// </summary>
        /// <param name="ip">Issuer parameters.</param>
        /// <param name="attributeIndexInToken">Index of attribute in the token the proof will be about (encoding of memberSet depends on this). Index is 1....n.</param>
        /// <param name="memberSet">Member set</param>
        /// <returns></returns>
        public static FieldZqElement[] GenerateMemberSet(IssuerParameters ip, int attributeIndexInToken, byte[][] memberSet)
        {
            if (attributeIndexInToken <= 0)
            {
                throw new ArgumentException("attributeIndexInToken must be a positive integer");
            }
            FieldZqElement[] output = new FieldZqElement[memberSet.Length];
            for (int i = 0; i < output.Length; ++i)
            {
                output[i] = ProtocolHelper.ComputeXi(ip, attributeIndexInToken - 1, memberSet[i]);
            }
            return output;
        }

        /// <summary>
        /// Sanity checks the parameters.
        /// </summary>
        /// <returns>True is this object is ready to use to verify a SetMembershipProof. False otherwise.</returns>
        public new bool Verify()
        {
            if (!base.Verify())
            {
                return false;
            }

            if ((MemberSet == null) 
                || (MemberSet.Length == 0)
                || (this.ClosedCommitment == null))
            {
                return false;
            }
            return true;
        }


        #region Serialization

        [DataMember(Name="MemberSet",EmitDefaultValue=false, Order=1)]
        internal string[] _memberSet;

        [OnSerializing]
        public void VSMSerializing(StreamingContext context)
        {
            _memberSet = CryptoSerializer.SerializeFieldZqElementArray(MemberSet, "MemberSet");
        }

        [OnDeserialized]
        public void VSMDeserialized(StreamingContext context)
        {
            MemberSet = CryptoSerializer.DeserializeFieldZqElementArray(_memberSet, "MemberSet", this.Group);
        }

        #endregion


    }

    /// <summary>
    /// Class that contains all the parameters needed for a Prover to
    /// create a SetMembershipProof.
    /// 
    /// Prover has a PedersenCommitment OpenCommitment.  The value 
    /// OpenCommitment.CommittedValue is in MemberSet.
    /// 
    /// The Verifier knows MemberSet, and ClosedCommitment, which
    /// is equal to OpenCommitment.Value
    /// </summary>
    [DataContract]
    public class ProverSetMembershipParameters : VerifierSetMembershipParameters
    {
        /// <summary>
        /// This is the Prover's witness.
        /// OpenCommitment.Value must equal ClosedCommitment.
        /// OpenCommitment.G and OpenCommitment.H must equal this.G and this.H
        /// </summary>
        public PedersenCommitment OpenCommitment
        {
            get
            {
                if ((this.Witnesses == null)
                    || (this.Witnesses.Length == 0))
                {
                    return null;
                }
                return (PedersenCommitment)this.Witnesses[0];
            }
            private set
            {
                PedersenCommitment[] witnesses = new PedersenCommitment[1] { value };
                this.setProverParameters(witnesses);
            }
        }

        /// <summary>
        /// Searches memberSet for the committed value (commitment.CommittedValue).
        /// </summary>
        /// <param name="commitment">A Pedersen commitment.</param>
        /// <param name="memberSet">An array of exponents.</param>
        /// <returns>Index of committed value in memberSet. Throws exception if not found.</returns>
        public int IndexOfCommittedValueInSet
        {
            get
            {
                if (this.OpenCommitment.CommittedValue == null)
                {
                    throw new Exception("commitment.CommittedValue is null");
                }
                for (int index = 0; index < this.MemberSet.Length; ++index)
                {
                    if (this.MemberSet[index] == this.OpenCommitment.CommittedValue)
                    {
                        return index;
                    }
                }
                throw new Exception("Committed value is not in memberSet");
            }
        }

        /// <summary>
        /// Returns true if committedValue is in memberSet. 
        /// </summary>
        /// <param name="commitment">A Pedersen Commitment</param>
        /// <param name="memberSet">An array of exponents</param>
        /// <returns>True if commitment.ComittedValue is in memberset. Returns false otherwise or on null input.</returns>
        public bool IsCommittedValueInSet
        {
            get
            {

                if ((this.OpenCommitment == null) || (this.OpenCommitment.CommittedValue == null))
                {
                    return false;
                }
                foreach (FieldZqElement member in this.MemberSet)
                {
                    if (member == this.OpenCommitment.CommittedValue)
                    {
                        return true;
                    }
                }
                return false;
            }
        }




        /// <summary>
        /// Constructor. Creates an instance of ProverSetMembershipParameters that
        /// is ready to use to create a SetMembershipProof (assuming openCommitment
        /// and memberSet are not null).
        /// </summary>
        /// <param name="openCommitment">OpenCommitment</param>
        /// <param name="memberSet">MemberSet</param>
        /// <param name="parameters">Sets crypto parameters: Group, FieldZq, G, H, HashFunction. 
        /// If null uses default parameters.</param>
        public ProverSetMembershipParameters(
            PedersenCommitment openCommitment,
            FieldZqElement [] memberSet,
            CryptoParameters parameters) : base(parameters)
        {
            this.setProverParameters(openCommitment, memberSet);
        }

        /// <summary>
        /// Constructor. Sets the crypto parameters. Must call setProverParameters
        /// in order for this class to be ready to use.
        /// </summary>
        /// <param name="parameters">Sets crypto parameters: Group, FieldZq, G, H, HashFunction. 
        /// If null, uses default parameters.</param>
        public ProverSetMembershipParameters(CryptoParameters parameters)
            : base(parameters)
        {
            this.setProverParameters(null);
        }

        /// <summary>
        /// Sets the OpenCommitment and MemberSet.
        /// </summary>
        /// <param name="memberOfSet">must be in memberSet</param>
        /// <param name="memberSet"></param>
        public void setProverParameters(FieldZqElement memberOfSet, FieldZqElement[] memberSet)
        {
            PedersenCommitment openCommitment = new PedersenCommitment(memberOfSet, this);
            this.setProverParameters(openCommitment, memberSet);
        }

        /// <summary>
        /// Sets the OpenCommitment and MemberSet
        /// </summary>
        /// <param name="openCommitment">openCommitment.Value must be in memberSet</param>
        /// <param name="memberSet"></param>
        public void setProverParameters(PedersenCommitment openCommitment, FieldZqElement[] memberSet)
        {
            this.setProverParameters(new PedersenCommitment[] { openCommitment });
            this.MemberSet = memberSet;
        }

        /// <summary>
        /// Creates a new instance of the verifier parameters containing all the 
        /// common parameters in this object.
        /// </summary>
        /// <returns></returns>
        public VerifierSetMembershipParameters GetVerifierParameters()
        {
            return new VerifierSetMembershipParameters(
                this.ClosedCommitment,
                this.MemberSet,
                new CryptoParameters(this.Group, this.Generators, this.HashFunctionName));
        }

        /// <summary>
        /// Verifies that these parameters can be used to create a valid SetMembershipProof.
        /// </summary>
        /// <returns></returns>
        public new bool Verify()
        {
            if (!base.Verify())
            {
                return false;
            }

            // check that committed value is in MemberSet
            if (!this.IsCommittedValueInSet)
            {
                return false;
            }

            // check bases, value of OpenCommitment
            if ((this.OpenCommitment.G != this.G)
                || (this.OpenCommitment.H != this.H)
                || (this.OpenCommitment.Value != this.ClosedCommitment))
            {
                return false;
            }
            return true;

        }

    }

}
