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
using System.ComponentModel;
using System.Runtime.Serialization;

namespace UProveCrypto.DVARevocation
{
    /// <summary>
    /// Contains Revocation Authority parameters.
    /// </summary>
    [DataContract]
    public class RAParameters : IParametrizedDeserialization
    {
        /// <summary>
        /// The group.
        /// </summary>
        public Group group { get; internal set; }
        /// <summary>
        /// The <code>g</code> value.
        /// </summary>
        public GroupElement g { get; internal set; }
        /// <summary>
        /// The <code>g1</code> value.
        /// </summary>
        public GroupElement g1 { get; internal set; }
        /// <summary>
        /// The <code>gt</code> value.
        /// </summary>
        public GroupElement gt { get; internal set; }
        /// <summary>
        /// The hash algorithm identifier.
        /// </summary>
        public string uidh { get; internal set; }
        /// <summary>
        /// The public key value <code>K</code>.
        /// </summary>
        public GroupElement K { get; internal set; }

        /// <summary>
        /// Construcst a Revocation Authority parameters object.
        /// </summary>
        /// <param name="group">The group.</param>
        /// <param name="g">The <code>g</code> value.</param>
        /// <param name="g1">The <code>g1</code> value.</param>
        /// <param name="gt">The <code>gt</code> value.</param>
        /// <param name="K">The public key value <code>K</code>.</param>
        /// <param name="uidh">The hash algorithm identifier.</param>
        public RAParameters(Group group, GroupElement g, GroupElement g1, GroupElement gt, GroupElement K, string uidh)
        {
            if (group == null) { throw new ArgumentNullException("group"); }
            this.group = group;
            if (g == null) { throw new ArgumentNullException("g"); }
            this.g = g;
            if (g1 == null) { throw new ArgumentNullException("g1"); }
            this.g1 = g1;
            if (gt == null) { throw new ArgumentNullException("gt"); }
            this.gt = gt;
            if (K == null) { throw new ArgumentNullException("K"); }
            this.K = K;
            if (uidh == null) { throw new ArgumentNullException("uidh"); }
            this.uidh = uidh;
        }

        /// <summary>
        /// Creates a Revocation Authority parameters object.
        /// </summary>
        /// <param name="recommendedParamsName">The recommended parameters name. Must be a value defined
        /// either in <code>UProveCrypto.SubgroupParameterSets</code></param> or in 
        /// <code>UProveCrypto.ECParameterSets</code>.
        /// <param name="K">The public key value <code>K</code>.</param>
        /// <param name="uidh">The hash algorithm identifier.</param>
        public RAParameters(string recommendedParamsName, GroupElement K, string uidh)
        {
            if (recommendedParamsName == null) { throw new ArgumentNullException("recommendedParamsName"); }
            ParameterSet defaultParamSet;
            if (ParameterSet.TryGetNamedParameterSet(recommendedParamsName, out defaultParamSet))
            {
                this.group = defaultParamSet.Group;
                this.g = defaultParamSet.Group.G;
                this.g1 = defaultParamSet.G[0];
                this.gt = defaultParamSet.G[defaultParamSet.G.Length - 1];
            }
            else
            {
                throw new ArgumentException("unknown parameters name: " + recommendedParamsName);
            }

            if (K == null) { throw new ArgumentNullException("K"); }
            this.K = K;
            if (uidh == null) { throw new ArgumentNullException("uidh"); }
            this.uidh = uidh;
        }

        internal byte[] ComputeChallenge(GroupElement tildeCid, GroupElement X, GroupElement Y, GroupElement Cd, GroupElement T1, GroupElement T2, GroupElement T3)
        {
            HashFunction hasher = new HashFunction(uidh);
            hasher.Hash(this.g);
            hasher.Hash(this.g1);
            hasher.Hash(this.gt);
            hasher.Hash(this.K);
            hasher.Hash(tildeCid);
            hasher.Hash(X);
            hasher.Hash(Y);
            hasher.Hash(Cd);
            hasher.Hash(T1);
            hasher.Hash(T2);
            hasher.Hash(T3);
            return hasher.Digest;
        }


        #region Serialization

        [DataMember(Name = "k", Order = 1)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string _k;

        [OnSerializing]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnSerializing(StreamingContext context)
        {
            _k = this.K.ToBase64String();
        }

        bool deserializationStarted = false;
        [OnDeserialized]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnDeserialized(StreamingContext context)
        {
            if (_k == null)
            {
                throw new UProveSerializationException("k");
            }

            deserializationStarted = true;
        }

        void IParametrizedDeserialization.FinishDeserialization(IssuerParameters ip)
        {
            try
            {
                if (!this.deserializationStarted)
                {
                    throw new SerializationException("deserialization not started");
                }

                this.group = ip.Gq;
                this.g = group.G;
                this.g1 = ip.G[1];
                this.gt = ip.G[ip.G.Length - 1];
                this.uidh = ip.UidH;
                this.K = _k.ToGroupElement(ip.Gq);
            }
            catch
            {
                throw;
            }
            finally
            {
                this.deserializationStarted = false;
            }

        }

        #endregion Serialization

    }
   
}
