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
    /// Holds basic cryptographic information needed for proofs: hash function, group, fieldZQ, and
    /// a list of generators.
    /// </summary>
    [DataContract]
    public class CryptoParameters : GroupParameterizedSerializer
    {
        /// <summary>
        /// Default hash function.
        /// </summary>
        public const string DefaultHashFunctionName = "SHA-256";

        /// <summary>
        /// Default parameter set used to get group, field, and generators.
        /// </summary>
        public const string DefaultParameterSetName = ECParameterSets.ParamSet_EC_P256_V1Name;

        [DataMember(Name = "hash", EmitDefaultValue = false, Order = 2)]
        private string _hashFunctionName=null;

        /// <summary>
        /// The name of the hash algorithm. Must be one of the value listed in http://msdn.microsoft.com/en-us/library/wet69s13.aspx. If
        /// set to null, will set to default.
        /// </summary>
        public string HashFunctionName
        {
            get
            {
                return _hashFunctionName;
            }
            set
            {
                if (value == null)
                {
                    _hashFunctionName = DefaultHashFunctionName;
                }
                else
                {
                    _hashFunctionName = value;
                }
            }
        }

        /// <summary>
        /// Array of generators.  Length must be at least two.
        /// </summary>
        public GroupElement[] Generators;

        /// <summary>
        /// Returns the FieldZq.
        /// </summary>
        public FieldZq FieldZq
        {
            get
            {
                return this.Group.FieldZq;
            }
        }


        /// <summary>
        /// Returns Generators[0].
        /// </summary>
        public GroupElement G
        {
            get
            {
                if ((this.Generators == null) || (this.Generators.Length < 1))
                {
                    return null;
                }
                return Generators[0];
            }
        }

        /// <summary>
        /// Returns Generators[1].
        /// </summary>
        public GroupElement H
        {
            get
            {
                if ((this.Generators == null) || (this.Generators.Length < 2))
                {
                    return null;
                }
                return Generators[1];
            }
        }

        /// <summary>
        /// Constructor.  Initializes object from UProve IssuerParameters.
        /// Use this when integrating PolyProof proofs with UProve.
        /// </summary>
        /// <param name="ip"></param>
        public CryptoParameters(IssuerParameters ip)
        {
            this.Group = ip.Gq;
            this.Generators = new GroupElement[ip.G.Length];
            this.Generators[0] = ip.Gq.G;
            for (int i = 1; i < Generators.Length; ++i)
            {
                this.Generators[i] = ip.G[i];
            }
            this.HashFunctionName = ip.UidH;
        }

        /// <summary>
        /// Constructor. 
        /// If ParameterSet or hashFunctionName are null, uses defaults.
        /// For UProve integration, use CryptoParameters(IssuerParameters).
        /// </summary>
        /// <param name="parameterSet">UProve parameterSet to use.</param>
        /// <param name="hashFunctionName">The name of the hash algorithm. Must be one of the value listed in http://msdn.microsoft.com/en-us/library/wet69s13.aspx </param>
        public CryptoParameters(ParameterSet parameterSet, string hashFunctionName)
        {
            if (parameterSet == null)
            {
                bool success = ParameterSet.TryGetNamedParameterSet(DefaultParameterSetName, out parameterSet);
                if (!success)
                {
                    throw new Exception("could not create default parameters");
                }
            }
            this.Group = parameterSet.Group;
            this.Generators = parameterSet.G;
            this.HashFunctionName = hashFunctionName;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="group">Must not be null.</param>
        /// <param name="generators">Must contain at least two GroupElements.</param>
        /// <param name="hashFunctionName">The name of the hash algorithm. Must be one of the value listed in http://msdn.microsoft.com/en-us/library/wet69s13.aspx 
        /// Sets to default on null input.</param>.
        public CryptoParameters(Group group, GroupElement[] generators, string hashFunctionName)
        {
            this.Group = group;
            this.Generators = generators;
            this.HashFunctionName = hashFunctionName;
        }

        public CryptoParameters(CryptoParameters crypto)
        {
            this.Group = crypto.Group;
            this.Generators = crypto.Generators;
            this.HashFunctionName = crypto.HashFunctionName;
        }

        /// <summary>
        /// Checks to make sure that all parameters are set, and that
        /// Generators is an array of at least two.
        /// </summary>
        /// <returns></returns>
        public bool Verify()
        {
            if ((this.Group == null)
                || (this.HashFunctionName == null)
                || (this.Generators.Length < 2))
            {
                return false;
            }
            return true;
        }


        #region Serialization

        /// <summary>
        /// Serialized generators.
        /// </summary>
        [DataMember(Name = "Generators", EmitDefaultValue = false, Order=3)]
        internal string [] _generators;

        /// <summary>
        /// Serialize generators.
        /// </summary>
        /// <param name="context"></param>
        [OnSerializing]
        internal void OnSerializing(StreamingContext context)
        {
            _generators = CryptoSerializer.SerializeGroupElementArray(this.Generators, "Generators");
        }

        /// <summary>
        /// Deserialize generators.
        /// </summary>
        public override void FinishDeserializing()
        {
            this.Generators = CryptoSerializer.DeserializeGroupElementArray(_generators, "Generators", this.Group);
        }
 

        #endregion

    }
}
