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
    /// This class stores the prover and verifier proof parameters.  It is not used directly.
    /// Subclasses of this class hold the proof-specific parameters.
    /// </summary>
    [DataContract]
    public class ProofParameters : CryptoParameters
    {        
        /// <summary>
        /// Public values known to the Verifier.  This should be the Value
        /// of a PedersenCommitment or DLRepOfGroupElement.
        /// </summary>
        public GroupElement[] PublicValues { get; internal set; }

        /// <summary>
        /// Should PublicValues be serialized.  Default: only serialize if this.ProverParameters=false.
        /// </summary>
        [DataMember (Name="ArePublicValuesSerializable", EmitDefaultValue=false, Order=5)]
        public bool ArePublicValuesSerializable = true;

        /// <summary>
        /// Should Witnesses be serialized.  Default: only serialize if this.ProverParameters=true.
        /// </summary>
        [DataMember(Name = "AreWitnessesSerializable", EmitDefaultValue = false, Order = 5)]
        public bool AreWitnessesSerializable = true;

        /// <summary>
        /// Should witness bases be serialized. If false, use generators Generators[0],...,Generators[n] during deserialization.
        /// </summary>
        [DataMember(Name = "AreWitnessBasesSerializable", EmitDefaultValue = false, Order = 5)]
        public bool AreWitnessBasesSerializable = false;

        /// <summary>
        /// Witnesses known only to the prover.
        /// For all i: Witnesses[i].Value = PublicValues[i]
        /// </summary>
        public DLRepOfGroupElement[] Witnesses { get; internal set;}

        /// <summary>
        /// If true, this instance holds parameters belonging to the Prover. 
        /// If false, this instance holds parameters belonging to the Verifier.
        /// The value of this property affects how Verify() executes.
        /// </summary>
        [DataMember (Name="isProverParameters", EmitDefaultValue=false, Order=1)]
        public bool ProverParameters { get; set; }

        /// <summary>
        /// Constructor.  Sets PublicValues and Witnesses to null, ProverParameters=false;
        /// </summary>
        /// <param name="parameters"></param>
        public ProofParameters(CryptoParameters parameters) : base(parameters.Group, parameters.Generators, parameters.HashFunctionName)
        {
            this.ProverParameters = false;
            this.ArePublicValuesSerializable = true;
            this.AreWitnessesSerializable = false;
        }
        
        /// <summary>
        /// Sets the Witnesses and PublicValues properties.  Sets ProverParameters=true.
        /// </summary>
        /// <param name="witnesses"></param>
        public void setProverParameters(DLRepOfGroupElement [] witnesses)
        {
            this.ProverParameters = true;
            this.Witnesses = witnesses;
            if (this.Witnesses == null)
            {
                this.PublicValues = null;
                return;
            }
            this.PublicValues = new GroupElement[this.Witnesses.Length];
            for (int i = 0; i < witnesses.Length; ++i)
            {
                this.PublicValues[i] = witnesses[i].Value;
            }
            this.ArePublicValuesSerializable = false;
            this.AreWitnessesSerializable = true;
        }

        /// <summary>
        /// Sets the PublicValues property, and sets ProverParameters=false;
        /// </summary>
        /// <param name="publicValues"></param>
        public void setVerifierParameters(GroupElement [] publicValues)
        {
            this.ProverParameters = false;
            this.PublicValues = publicValues;
            this.Witnesses = null;
            this.ArePublicValuesSerializable = true;
            this.AreWitnessesSerializable = false;
        }

        /// <summary>
        /// Sanity checks the parameters.  If these are prover parameters, makes sure
        /// PublicValues correspond to Witnesses.  Also checks the associated CryptoParameters.
        /// </summary>
        /// <returns>True if these are valid parameters, false otherwise.</returns>
        public new bool Verify()
        {
            if (!base.Verify())
            {
                return false;
            }

            if (this.ProverParameters)
            {
                if ((this.Witnesses == null)
                    ||(this.PublicValues == null)
                    || (this.Witnesses.Length != this.PublicValues.Length))
                {
                    return false;
                }
                for (int i = 0; i < this.Witnesses.Length; ++i)
                {
                    if (this.Witnesses[i].Value != this.PublicValues[i])
                    {
                        return false;
                    }
                }
            }
            else
            {
                if (this.PublicValues == null)
                {
                    return false;
                }
            }
            return true;
        }

        #region Serialization
        /// <summary>
        /// Serialized witnesses.
        /// </summary>
        [DataMember(Name = "Witnesses", EmitDefaultValue = false, Order = 2)]
        internal string [] _witnesses;

        /// <summary>
        /// Serialized public values.
        /// </summary>
        [DataMember(Name = "PublicValues", EmitDefaultValue = false, Order = 3)]
        internal string [] _publicValues;

        /// <summary>
        /// Serialize witnesses and/or public values.
        /// </summary>
        /// <param name="context"></param>
        [OnSerializing]
        internal void OnPPSerializing(StreamingContext context)
        {
            if ((PublicValues == null) || (! ArePublicValuesSerializable))
            {
                _publicValues = null;
            }
            else
            {
                _publicValues = CryptoSerializer.SerializeGroupElementArray(this.PublicValues, "PublicValues");
            }

            if ((Witnesses == null) || (! AreWitnessesSerializable))
            {
                _witnesses = null;
            }
            else
            {
                _witnesses = CryptoSerializer.Serialize(this.Witnesses, false, this.AreWitnessBasesSerializable);
            }
        }

        /// <summary>
        /// Deserialize.
        /// </summary>
        /// <param name="context"></param>
        public override void FinishDeserializing()
        {
            base.FinishDeserializing();
            if ((_witnesses != null) && (AreWitnessesSerializable))
            {
                if (this.AreWitnessBasesSerializable)
                {
                    this.Witnesses = CryptoSerializer.Deserialize<DLRepOfGroupElement>(_witnesses, this.Group);
                }
                else
                {
                    this.Witnesses = CryptoSerializer.Deserialize<DLRepOfGroupElement>(_witnesses, this.Group, this.Generators);
                }
            }
            if ((_publicValues != null) && ArePublicValuesSerializable)
            {
                this.PublicValues = CryptoSerializer.DeserializeGroupElementArray(_publicValues, "PublicValues", this.Group);
            }
            if ((this.PublicValues == null) && (this.Witnesses != null))
            {
                this.PublicValues = new GroupElement[this.Witnesses.Length];
                for (int i = 0; i < this.PublicValues.Length; ++i)
                {
                    this.PublicValues[i] = this.Witnesses[i].Value;
                }
            }
        
        }
 
        #endregion
    }
}
