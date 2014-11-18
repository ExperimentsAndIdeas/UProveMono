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
    /// Container class for the parameters used by the Verifier
    /// </summary>
    [DataContract]
    public class VerifierEqualityParameters : CryptoParameters
    {
        /// <summary>
        /// Equality map.  Shows which exponents are claimed to be equal.
        /// </summary>
        [DataMember(Name="Map")]
        private EqualityMap _map;
        public EqualityMap Map
        {
            get
            {
                if (this._map == null)
                {
                    this._map = new EqualityMap();
                }
                return this._map;
            }
            set
            {
                this._map = value;
            }
        }

        /// <summary>
        /// Statements about which proof is made.
        /// </summary>
        public IStatement [] Statements {get; internal set;}

        /// <summary>
        /// Always serialize statements for VerifierEqualityParameters.
        /// </summary>
        private const bool AreStatementsSerializable = true;

        /// <summary>
        /// Empty constructor.  Must call SetVerifierParameters to complete.
        /// </summary>
        /// <param name="crypto"></param>
        public VerifierEqualityParameters(CryptoParameters crypto)
            : base(crypto)
        {
        }

        /// <summary>
        /// Create verifier parameters.
        /// </summary>
        /// <param name="statements">Statements.</param>
        /// <param name="map">Equality map for statements.</param>
        /// <param name="crypto">Crypto parameters</param>
        public VerifierEqualityParameters(
            IStatement[] statements,
            EqualityMap map,
            CryptoParameters crypto)
            : base(crypto)
        {
            this.Map = map;
            this.setVerifierParameters(statements);
        }

        /// <summary>
        /// Create a proof that the exponent at index0 for statement0
        /// is identical to the exponent at index1 for statement1.
        /// </summary>
        /// <param name="statement0">Statement</param>
        /// <param name="index0">Index of exponent in statement0.</param>
        /// <param name="statement1">Statement</param>
        /// <param name="index1">Index of exponent in statement1</param>
        /// <param name="crypto">Crypto parameters</param>
        public VerifierEqualityParameters(
            IStatement statement0,
            int index0,
            IStatement statement1,
            int index1,
            CryptoParameters crypto)
            : base(crypto)
        {
            IStatement[] statements = new IStatement[2];
            statements[0] = statement0;
            statements[1] = statement1;
            this.setVerifierParameters(statements);
            this.Map = new EqualityMap(index0, index1);
        }

        /// <summary>
        /// Creates a proof of knowledge of exponents in statement.
        /// </summary>
        /// <param name="statement"></param>
        /// <param name="crypto"></param>
        public VerifierEqualityParameters(IStatement statement, CryptoParameters crypto)
            : base(crypto)
        {
            this.setVerifierParameters(new IStatement[1] { statement });
            this.Map = null;
        }

        /// <summary>
        /// Sets verifier parameters.
        /// </summary>
        /// <param name="statements"></param>
        private void setVerifierParameters(IStatement[] statements)
        {
            this.Statements = statements;
        }

        /// <summary>
        /// Returns a hash of all the parameters.
        /// </summary>
        public byte[] HashDigest
        {
            get
            {
                System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();

                HashFunction hash = new HashFunction(this.HashFunctionName);
                hash.Hash(encoding.GetBytes(this.Group.GroupName));
                hash.Hash(this.Group.Q);
                hash.Hash(this.Map.Hash(this.HashFunctionName));

                // hash all closed equations
                for (int equationIndex = 0; equationIndex < this.Statements.Length; ++equationIndex)
                {
                    hash.Hash(this.Statements[equationIndex].Value);
                    for (int baseIndex = 0; baseIndex < this.Statements[equationIndex].RepresentationLength; ++baseIndex)
                    {
                        hash.Hash(this.Statements[equationIndex].BaseAtIndex(baseIndex));
                    }
                }
                return hash.Digest;
            }
        }

        /// <summary>
        /// Sanity check verifier parameters.
        /// </summary>
        /// <returns></returns>
        public new bool Verify()
        {
            if (!base.Verify())
            {
                return false;
            }

            if (this.Map == null)
            {
                return false;
            }

            //sanity check the map
            if (!this.Map.Verify(this.Statements))
            {
                return false;
            }

            return true;
        }

        #region Serialization

        /// <summary>
        /// Serialized statements
        /// </summary>
        [DataMember(Name = "ClosedEq")]
        internal string[] _closedEq;

        /// <summary>
        /// Serialize statements
        /// </summary>
        /// <param name="context"></param>
        [OnSerializing]
        public void VerifierOnSerializing(StreamingContext context)
        {
            _closedEq = null;
            if (AreStatementsSerializable)
            {
                _closedEq = CryptoSerializer.Serialize(this.Statements, false, true);
            }
        }

        /// <summary>
        /// Deserialize statements.
        /// </summary>
        /// <param name="context"></param>
        [OnDeserialized]
        public void VerifierOnDeserialized(StreamingContext context)
        {
            if (this._closedEq == null)
            {
                return;
            }
            this.Statements = CryptoSerializer.Deserialize<IStatement>(_closedEq, this.Group);
        }


        #endregion 

    }

    /// <summary>
    /// Container class for the parameters used by the Prover
    /// </summary>
    [DataContract]
    public class ProverEqualityParameters : VerifierEqualityParameters
    {
        /// <summary>
        /// Never serialize statements, as all data is contained in witnesses.
        /// </summary>
        private const bool AreStatementsSerializable = false;

        /// <summary>
        /// Witnesses to the Statements.
        /// </summary>
        public IWitness[] Witnesses { get; internal set; }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="witnesses"></param>
        /// <param name="map"></param>
        /// <param name="crypto"></param>
         public ProverEqualityParameters(
            IWitness[] witnesses,
            EqualityMap map,
            CryptoParameters crypto)
            : base(crypto)
        {
            this.setProverParameters(witnesses);
            this.Map = map;
        }

        /// <summary>
        /// Create a proof that two exponents in two witnesses are equal.
        /// </summary>
        /// <param name="witness0">Witness</param>
        /// <param name="exponentIndex0">Index of exponent in witness0</param>
        /// <param name="witness1">Witness</param>
        /// <param name="exponentIndex1">Index of exponent in witness1</param>
        /// <param name="crypto">Crypto parameters</param>
        public ProverEqualityParameters(
            IWitness witness0,
            int exponentIndex0,
            IWitness witness1,
            int exponentIndex1,
            CryptoParameters crypto)
            : base(crypto)
        {
            IWitness[] witnesses = new IWitness[2];
            witnesses[0] = witness0;
            witnesses[1] = witness1;
            this.setProverParameters(witnesses);
            this.Map = new EqualityMap(exponentIndex0, exponentIndex1);
        }

        /// <summary>
        /// Create a proof of knowledge of the exponents in witness.
        /// </summary>
        /// <param name="witness"></param>
        /// <param name="crypto"></param>
        public ProverEqualityParameters(IWitness witness, CryptoParameters crypto)
            : base(crypto)
        {
            this.setProverParameters(new IWitness[1] { witness });
            this.Map = null;
        }

        /// <summary>
        /// Sets prover parameters.
        /// </summary>
        /// <param name="witnesses"></param>
        private void setProverParameters(IWitness[] witnesses)
        {
            this.Witnesses = witnesses;
            this.Statements = new IStatement[witnesses.Length];
            for (int i = 0; i < this.Statements.Length; ++i)
            {
                this.Statements[i] = this.Witnesses[i].GetStatement();
            }
        }

        /// <summary>
        /// Sanity check parameters to make sure they can be used to create the proof.
        /// </summary>
        /// <returns></returns>
        public new bool Verify()
        {
            if (!base.Verify())
            {
                return false;
            }

            if (!this.Map.Verify(this.Witnesses))
            {
                return false;
            }
            return true;
        }

        #region Serialization

        /// <summary>
        /// Serialized witnesses.
        /// </summary>
        [DataMember(Name = "Witnesses")]
        internal string[] _witnesses;

        /// <summary>
        /// Serialize the witnesses.
        /// </summary>
        /// <param name="context"></param>
        [OnSerializing]
        public void ProverOnSerializing(StreamingContext context)
        {
            _witnesses = CryptoSerializer.Serialize(this.Witnesses, false, true);
        }

        /// <summary>
        /// Deserialize witnesses and statements.
        /// </summary>
        /// <param name="context"></param>
        [OnDeserialized]
        public void ProverOnDeserialized(StreamingContext context)
        {
            this.Witnesses = (IWitness []) CryptoSerializer.Deserialize<IWitness>(_witnesses, this.Group);

            this.Statements = new IStatement[this.Witnesses.Length];
            for (int i = 0; i < Witnesses.Length; ++i)
            {
                this.Statements[i] = this.Witnesses[i].GetStatement();
            }
        }

        #endregion 
    }
}
