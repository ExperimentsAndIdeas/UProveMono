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
    /// This class contains verifier parameters for the Inequality Proof.
    /// </summary>
    [DataContract]
    public class VerifierInequalityProofParameters : ProofParameters
    {
        #region Properties

        /// <summary>
        /// Known value.  The if this proof is a comparison to a known value,
        /// then the prover will show that the opening of ClosedCommitmentX is not
        /// equal to Value.
        /// </summary>
        public FieldZqElement Value;

        /// <summary>
        /// If true, the verifier will check that the opening of ClosedCommitmentX
        /// is not equal to Value.  If false, the verifier will check that
        /// the committed value in ClosedCommitmentX is not equal to the 
        /// committed value in ClosedCommitmentY.
        /// </summary>
        [DataMember]
        public bool CompareToKnownValue=true;

        /// <summary>
        /// Value of Pedersen Commitment.  Must not be null.
        /// </summary>
        public GroupElement ClosedCommitmentX
        {
            get
            {
                if ((this.PublicValues == null) || (this.PublicValues.Length < 1))
                {
                    return null;
                }
                return (GroupElement)this.PublicValues[0];
            }
        }

        /// <summary>
        /// Value of Pedersen Commitment. If CompareToKnownValue
        /// is true, this must not be null and must not equal
        /// ClosedCommitmentX.
        /// </summary>
        public GroupElement ClosedCommitmentY
        {
            get
            {
                if ((this.PublicValues == null) || (this.PublicValues.Length <2))
                {
                    return null;
                }
                return (GroupElement)this.PublicValues[1];
            }
        }

        #endregion

        /// <summary>
        /// Constructor. Must call SetVerifierParameters() after using
        /// this constructor.
        /// </summary>
        /// <param name="parameters"></param>
        public VerifierInequalityProofParameters(CryptoParameters parameters)
            : base(parameters)
        {
            this.setVerifierParameters(null);
        }

        /// <summary>
        /// Create verifier parameters for verifying that the committed value
        /// in closedCommitment is not equal to value.  The generators G and H
        /// for Pedersen Commitment closedCommitment come from parameters.
        /// </summary>
        /// <param name="closedCommitment">Value of Pedersen Commitment</param>
        /// <param name="value">Known value</param>
        /// <param name="parameters">Crypto parameters</param>
        public VerifierInequalityProofParameters(
            GroupElement closedCommitment,
            FieldZqElement value,
            CryptoParameters parameters)
            : base(parameters)
        {
            this.SetVerifierParameters(closedCommitment, value);
        }

        /// <summary>
        /// Create verifier parameters for verifying that the committed value
        /// in closedCommitmentX is not equal to the committed value in
        /// closedCommitmentY.  The generators G and H
        /// for both Pedersen Commitments come from parameters.
        /// The values of closedCommitmentX and closedCommitmentY must be different.
        /// </summary>
        /// <param name="closedCommitmentX">Value of a Pedersen Commitment</param>
        /// <param name="closedCommitmentY">Value of a Pedersen Commitment</param>
        /// <param name="parameters">Crypto parameters</param>
        public VerifierInequalityProofParameters(
            GroupElement closedCommitmentX,
            GroupElement closedCommitmentY,
            CryptoParameters parameters)
            : base(parameters)
        {
            this.SetVerifierParameters(closedCommitmentX, closedCommitmentY);
        }

        /// <summary>
        /// Set verifier parameters for verifying that the committed value
        /// in closedCommitment is not equal to value.  The generators G and H
        /// for Pedersen Commitment closedCommitment come from parameters.
        /// </summary>
        /// <param name="closedCommitment">Value of Pedersen Commitment</param>
        /// <param name="value">Known value</param>
        public void SetVerifierParameters(GroupElement closedCommitment, FieldZqElement value)
        {
            GroupElement[] publicValues = new GroupElement[1];
            publicValues[0] = closedCommitment;
            this.setVerifierParameters(publicValues);
            this.Value = value;
            this.CompareToKnownValue = true;
        }

        /// <summary>
        /// Set verifier parameters for verifying that the committed value
        /// in closedCommitmentX is not equal to the committed value in
        /// closedCommitmentY.  The generators G and H
        /// for both Pedersen Commitments come from parameters.
        /// The values of closedCommitmentX and closedCommitmentY must be different.
        /// </summary>
        /// <param name="closedCommitmentX">Value of a Pedersen Commitment</param>
        /// <param name="closedCommitmentY">Value of a Pedersen Commitment</param>
        public void SetVerifierParameters(GroupElement closedCommitmentX, GroupElement closedCommitmentY)
        {
            GroupElement[] publicValues = new GroupElement[2];
            publicValues[0] = closedCommitmentX;
            publicValues[1] = closedCommitmentY;
            this.setVerifierParameters(publicValues);
            this.CompareToKnownValue = false;
        }

        /// <summary>
        /// Verify that these parameters are valid.
        /// </summary>
        /// <returns></returns>
        new public bool Verify()
        {
            if (!base.Verify())
            {
                return false;
            }
            if ((this.ClosedCommitmentX == null) || (this.ClosedCommitmentX == this.Group.Identity))
            {
                return false;
            }

            if (this.CompareToKnownValue)
            {

                if (this.Value == null)
                {
                    return false;
                }
            }
            else
            {
                if ((this.ClosedCommitmentY == null) || (this.ClosedCommitmentY == this.Group.Identity))
                {
                    return false;
                }

                if (this.ClosedCommitmentX == this.ClosedCommitmentY)
                {
                    return false;
                }
            }
            return true;
        }

        #region Serialization
        [DataMember(Name = "Value", EmitDefaultValue = false)]
        internal string _value;

        [OnSerializing]
        internal void OnVIPSerializing(StreamingContext context)
        {
            if (this.CompareToKnownValue)
            {
                _value = this.Value.ToBase64String();
            }
            else
            {
                _value = null;
            }
        }

        [OnDeserialized]
        internal void OnVIPDeserialized(StreamingContext context)
        {
            if (this.CompareToKnownValue)
            {
                this.Value = CryptoSerializer.DeserializeFieldZqElement(this._value, this.Group);
            }
            else
            {
                this.Value = null;
            }
        }


        #endregion


    }

    /// <summary>
    /// This class contains prover parameters for Inequality Proof.
    /// </summary>
    [DataContract]
    public class ProverInequalityProofParameters : VerifierInequalityProofParameters
    {
        #region Properties

        /// <summary>
        /// Prover will show that the committed value in CommitmentX is not
        /// equal to either Value or CommitmentY.
        /// CommitmentX may not be null or equal to 1. The following
        /// conditions must hold:
        /// CommitmentX != null
        /// CommitmentX != this.Group.Identity
        /// CommitmentX.G == this.G
        /// CommitmentX.H == this.H
        /// </summary>
        public PedersenCommitment CommitmentX
        {
            get
            {
                if ((this.Witnesses == null) || (this.Witnesses.Length < 1))
                {
                    return null;
                }
                return (PedersenCommitment)this.Witnesses[0];
            }
        }

        /// <summary>
        /// For unknown value proofs, the Prover will show that the
        /// committed value in CommitmentX is not equal to the committed
        /// value in CommitmentY.  If CompareToKnownValue= false, then
        /// the following conditions must hold:
        /// CommitmentY != null
        /// CommitmentY != this.Group.Identity
        /// CommitmentY != this.CommitmentX
        /// CommitmentY.G == this.G
        /// CommitmentY.H == this.H
        /// </summary>
        public PedersenCommitment CommitmentY
        {
            get
            {
                if ((this.Witnesses == null) || (this.Witnesses.Length < 2))
                {
                    return null;
                }
                return (PedersenCommitment)this.Witnesses[1];
            }
        }

        #endregion

        /// <summary>
        /// Constructor. Must call SetProverParameters after calling
        /// this constructor.
        /// </summary>
        /// <param name="parameters">Crypto parameters</param>
        public ProverInequalityProofParameters(CryptoParameters parameters)
            : base(parameters)
        {
            this.setProverParameters(null);
        }

        /// <summary>
        /// Constructor. Creates prover parameters for proving that
        /// the committed value in openCommitment is not equal to value.
        /// </summary>
        /// <param name="openCommitment">Pedersen Commitment</param>
        /// <param name="value">Value known to verifier</param>
        /// <param name="parameters">Crypto parameters</param>
        public ProverInequalityProofParameters(
            PedersenCommitment openCommitment,
            FieldZqElement value,
            CryptoParameters parameters)
            : base(parameters)
        {
            this.setProverParameters(openCommitment, value);
        }

        /// <summary>
        /// Constructor.  Creates prover parameters for proving that
        /// the committed value in openCommitmentX is not equal to the
        /// committed value in openCommitmentY.
        /// </summary>
        /// <param name="openCommitmentX">Pedersen Commitment</param>
        /// <param name="openCommitmentY">Pedersen Commitment</param>
        /// <param name="parameters">Crypto parameters</param>
        public ProverInequalityProofParameters(
            PedersenCommitment openCommitmentX,
            PedersenCommitment openCommitmentY,
            CryptoParameters parameters)
            : base(parameters)
        {
            this.setProverParameters(openCommitmentX, openCommitmentY);
        }

        /// <summary>
        /// Sets prover parameters for proving that
        /// the committed value in openCommitment is not equal to value.
        /// </summary>
        /// <param name="openCommitment">Pedersen Commitment</param>
        /// <param name="value">Value known to verifier</param>
        /// <param name="parameters">Crypto parameters</param>
        public void setProverParameters(PedersenCommitment openCommitment, FieldZqElement value)
        {
            PedersenCommitment[] witnesses = new PedersenCommitment[1];
            witnesses[0] = openCommitment;
            this.setProverParameters(witnesses);
            this.Value = value;
            this.CompareToKnownValue = true;
        }

        /// <summary>
        /// Sets prover parameters for proving that
        /// the committed value in openCommitmentX is not equal to the
        /// committed value in openCommitmentY.
        /// </summary>
        /// <param name="openCommitmentX">Pedersen Commitment</param>
        /// <param name="openCommitmentY">Pedersen Commitment</param>
        public void setProverParameters(PedersenCommitment openCommitmentX, PedersenCommitment openCommitmentY)
        {
            PedersenCommitment[] witnesses = new PedersenCommitment[2];
            witnesses[0] = openCommitmentX;
            witnesses[1] = openCommitmentY;
            this.setProverParameters(witnesses);
            this.CompareToKnownValue = false;
        }

        /// <summary>
        /// Verifies that the prover parameters are valid.
        /// </summary>
        /// <returns>True is parameters are valid, false otherwise.</returns>
        new public bool Verify()
        {
            if(! base.Verify())
            {
                return false;
            }

            // check Pedersen Commitment bases against crypto parameter bases
            if ((this.CommitmentX == null)
                || (this.CommitmentX.G !=this.G) || (this.CommitmentX.H != this.H))
            {
                return false;
            }

            if (this.CompareToKnownValue)
            {
                if (this.CommitmentX.CommittedValue == this.Value)
                {
                    return false;
                }
            }
            else
            {
                if ((this.CommitmentY == null)
                   || (this.CommitmentY.G != this.G) || (this.CommitmentY.H != this.H)
                    || (this.CommitmentY.CommittedValue == this.CommitmentX.CommittedValue))
                {
                    return false;
                }
  
            }
            return true;
        }
    }
}
