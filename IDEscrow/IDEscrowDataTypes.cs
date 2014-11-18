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
using System.Linq;
using System.Runtime.Serialization;

using UProveCrypto;
using UProveCrypto.Math;

namespace IDEscrow
{

    /// <summary> The parameters for the ID escrow scheme. </summary>
    /// <remarks> Note that when serialized,  the IssuerParamters are not serialized, only UIDp.
    ///           When deserializing, the serialized UIDp must match the current UIDp.
    /// </remarks>
    [DataContract]
    public class IDEscrowParams : IParametrizedDeserialization
    {
        private GroupElement ge;                    // base to use for the encryption scheme.  Fixed to Gq.G (the generator of the group)
        public IssuerParameters ip { set; get; }
        internal Group G { set;  get; }             // same as in ip
        internal HashFunction H { set; get; }       // same as in ip

        /// <summary>
        ///  Create a new IDEscrowParams instance. 
        /// </summary>
        /// <param name="ip">The issuer paramters to use.</c></param>
        /// <remarks> The choice of issuer paramters defines the <c>GroupDescription</c> and
        /// <c>HashFunction</c> to use for the ID escrow scheme. </remarks>
        public IDEscrowParams(IssuerParameters ip)
        {
            this.ip = ip;
            this.G = ip.Gq;
            this.ge = ip.Gq.G;          // g_e is set to the generator of the group
            this.H = ip.HashFunction;
        }

        /// <summary>
        ///  <c>Ge</c> is the generator of G used for the encryption scheme. 
        /// </summary>
        public GroupElement Ge
        {
            get { return ge; }
            set { ge = value; }
        }

        /// <summary>
        /// <c>Zq</c> is the field associated with the Group <c>Gq</c>.
        /// </summary>
        public FieldZq Zq
        {
            get { return ip.Zq; }
        }

        /// <summary> Equality check between this <c>IDEscrowParams</c> and another.</summary>
        /// <remarks> Since IssuerParameters does not implement Equals, we only 
        /// compare the UIDp of the issuer params.  Same for <c>GroupDescription</c>,
        /// so we only compare the group name. </remarks>
        /// <returns> <c>true</c> if equal, <c>false</c> otherwise </returns>
        public bool Equals(IDEscrowParams iep)
        {
            if (iep == null)
                return false;

            // compare the UIDp field of issuer params only
            if (!ip.UidP.SequenceEqual(iep.ip.UidP))
                return false;
            if (!G.GroupName.Equals(iep.G.GroupName))
                return false;
            if (!ge.Equals(iep.Ge))
                return false;

            // Note: we don't have a good way to compare hash functions, but
            // if the issuer parameters are the same the hash functions should be too

            return true;

        }


        #region Serialization

        // We don't actually serialize the whole issuer params, just UIDp
        [DataMember(Name = "uidp", EmitDefaultValue = false, Order = 1)]
        internal string _uidp;

        [DataMember(Name = "ge", EmitDefaultValue = false, Order = 2)]
        internal string _ge;

        [OnSerializing]
        internal void OnSerializing(StreamingContext context)
        {
            _uidp = ip.UidP.ToBase64String();
            _ge = ge.ToBase64String();
        }

        bool deserializationStarted = false;
        [OnDeserialized]
        internal void OnDeserialized(StreamingContext context)
        {
            if (_uidp == null)
                throw new UProveSerializationException("uidp");
            if (_ge == null)
                throw new UProveSerializationException("ge");


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

                if (!_uidp.ToByteArray().SequenceEqual(ip.UidP))
                    throw new UProveSerializationException("Invalid issuer parameters in IdEscrowParams.FinishDeserializing (UIDp does not match serialized UIDp).");
                this.ip = ip;
                this.H = ip.HashFunction;
                this.G = ip.Gq;
                this.ge = _ge.ToGroupElement(ip);
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

        #endregion


    }

    //***************  Key objects *******************//
    // internally use the notation H = g^x, where H = public, x = secret
    // The keys are quite simple now, so encapsulating them in an object may be
    // overkill, but it buys flexiblity should we decide to change the encryption scheme

    /// <summary>
    /// Simple struct-like class to store the public key of the ID escrow scheme.
    /// </summary>
    [DataContract]
    public class IDEscrowPublicKey : IParametrizedDeserialization
    {
        private GroupElement h;

        /// <summary>
        ///  Constructs a public key from the private key.
        /// </summary>
        public IDEscrowPublicKey(IDEscrowParams param, IDEscrowPrivateKey priv)
        {
            h = param.Ge.Exponentiate(priv.X);       // H = (g_e)^x
        }

        /// <summary>
        ///  The public key. 
        /// </summary>
        public GroupElement H
        {
            get { return h; }
        }

        /// <summary>
        ///  Checks that <c>sk</c> is consistent with this public key and <c>param</c>.
        /// </summary>
        /// <returns><c>true</c> if valid, <c>false</c> otherwise.</returns>
        public bool Verify(IDEscrowParams param, IDEscrowPrivateKey sk)
        {
            if (!param.ip.Zq.IsElement(sk.X))  // is x in the right field?
                return false;

            GroupElement hPrime = param.Ge.Exponentiate(sk.X);
            if (!hPrime.Equals(h))                      // is h = ge^x ?
                return false;

            return true;
        }

        /// <summary>
        ///  Verify that this public key is consistent with the parameters.
        /// </summary>
        /// <param name="param">paramters of ID escrow scheme. </param>
        /// <returns></returns>
        public bool Verify(IDEscrowParams param)
        {
            try
            {
                param.ip.Gq.ValidateGroupElement(h);
            }
            catch
            {
                return false;
            }

            return true;
        }
        /// <summary>
        /// Compare two <c>IDEscrowPublicKey</c> objects
        /// </summary>
        /// <param name="pk2">To be compared to this object</param>
        /// <returns>True if equal, false otherwise.</returns>
        public bool Equals(IDEscrowPublicKey pk2)
        {
            if(pk2 == null)
                return false;

            if (!pk2.H.Equals(this.h))
                return false;

            return true;
        }


        #region Serialization

        [DataMember(Name = "H", EmitDefaultValue = false, Order = 1)]
        internal string _H;

        [OnSerializing]
        internal void OnSerializing(StreamingContext context)
        {
            _H = h.ToBase64String();
        }

        bool deserializationStarted = false;
        [OnDeserialized]
        internal void OnDeserialized(StreamingContext context)
        {
            if (_H == null)
                throw new UProveSerializationException("H");

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

                h = _H.ToGroupElement(ip);
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

        #endregion
    }



    /// <summary>
    /// Simple struct-like object to hold the private key of the ID escrow scheme.
    /// </summary>
    [DataContract]
    public class IDEscrowPrivateKey : IParametrizedDeserialization
    {
        private FieldZqElement x;

        /// <summary>
        ///  Generates a new, random, private key.
        /// </summary>
        /// <remarks>The random number generator used is the one associated
        ///  with <c>iep</c> (indirectly, via the <c>IssuerParamters</c>). 
        ///  </remarks>
        public IDEscrowPrivateKey(IDEscrowParams iep)
        {
            UProveCrypto.Math.FieldZq F = iep.ip.Zq;
            x = F.GetRandomElement(true);
        }

        /// <summary>
        /// Constructs a private key object.
        /// </summary>
        /// <param name="x">The private key value.</param>
        internal IDEscrowPrivateKey(FieldZqElement x)
        {
            this.x = x;
        }

        public FieldZqElement X
        {
            get { return x; }
        }

#if false
        /// <summary>
        ///  Not yet implemented.
        /// </summary>
        public void zeroize()
        {
            // TODO implement the zeroize function
            // add special handling of sk (pinning), and ability to zeroize it.
            throw new NotImplementedException();
        }
#endif

        /// <summary>
        /// Compare two IDEscrowPrivateKey objects. 
        /// </summary>
        /// <param name="sk2">The object to compare against.</param>
        /// <returns>True if equal, false otherwise.</returns>
        public bool Equals(IDEscrowPrivateKey sk2)
        {
            if (sk2 == null)
                return false;

            if (!sk2.X.Equals(this.x))
                return false;

            return true;
        }


        #region Serialization

        [DataMember(Name = "x", EmitDefaultValue = false, Order = 1)]
        internal string _x;

        [OnSerializing]
        internal void OnSerializing(StreamingContext context)
        {
            _x = x.ToBase64String();
        }

        bool deserializationStarted = false;
        [OnDeserialized]
        internal void OnDeserialized(StreamingContext context)
        {
            if (_x == null)
                throw new UProveSerializationException("x");

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

                x = _x.ToFieldElement(ip);
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

        #endregion
    }

    //*********** Ciphertext ******************//

    /// <summary>
    /// Simple struct-like class to hold the ciphertext and the associated
    /// proof of correctness.  Stores an <c>IDEscrowProof</c> object and group
    /// elements representing the ciphertext. 
    /// </summary>
    [DataContract]
    public class IDEscrowCiphertext : IParametrizedDeserialization
    {
        public GroupElement E1;
        public GroupElement E2;
        public byte[] additionalInfo;
        [DataMember(Name = "ieproof", EmitDefaultValue = false, Order = 4)]
        internal IDEscrowProof proof;

        /// <summary>
        /// Create a new combined ciphertext and proof object from computed values.  
        /// Users of this library will not use this function, because ciphertexts will be created
        /// with the <c>VerifiableEncrypt</c> function, which creates the ciphertext.
        /// </summary>
        /// <seealso cref="IDEscrow.IDEscrowFunctions.VerifiableEncrypt"/>
        public IDEscrowCiphertext(GroupElement E1, GroupElement E2, IDEscrowProof proof, byte[] additionalInfo)
        {
            if (E1 == null || E2 == null || proof == null)
                throw new ArgumentNullException("Null inputs IDEscrowCiphertext()");

            this.E1 = E1;
            this.E2 = E2;
            this.proof = proof;
            this.additionalInfo = additionalInfo;
        }

        /// <summary>
        /// Compare two IDEscrowCiphertext objects. 
        /// </summary>
        /// <param name="ctext2">The object to compare against.</param>
        /// <returns></returns>
        public bool Equals(IDEscrowCiphertext ctext2)
        {
            if (ctext2 == null)
                return false;

            if (ctext2.E1 == null || ctext2.E2 == null || ctext2.proof == null)
                return false;

            // additionalInfo may be null.
            if (ctext2.additionalInfo == null && additionalInfo != null)
                return false;
            else if (ctext2.additionalInfo != null && additionalInfo == null)
                return false;
            else if ( (ctext2.additionalInfo != null && additionalInfo != null)
                        && !ctext2.additionalInfo.SequenceEqual(additionalInfo))
                return false;

            if (!ctext2.E1.Equals(E1))
                return false;
            if (!ctext2.E2.Equals(E2))
                return false;
            if (!ctext2.proof.Equals(proof))
                return false;

            
            return true;
        }

        #region Serialization

        [DataMember(Name = "E1", EmitDefaultValue = false, Order = 1)]
        internal string _E1;

        [DataMember(Name = "E2", EmitDefaultValue = false, Order = 2)]
        internal string _E2;

        [DataMember(Name = "info", EmitDefaultValue = false, Order = 3)]
        internal string _info;

        // The proof is the 4th item to be serialized

        [OnSerializing]
        internal void OnSerializing(StreamingContext context)
        {
            _E1 = E1.ToBase64String();
            _E2 = E2.ToBase64String();
            if (additionalInfo != null)
                _info = additionalInfo.ToBase64String();
            else
                _info = "NULL";
            // proof is already serializable
        }

        bool deserializationStarted = false;
        [OnDeserialized]
        internal void OnDeserialized(StreamingContext context)
        {
            if (_E1 == null)
                throw new UProveSerializationException("E1");
            if (_E2 == null)
                throw new UProveSerializationException("E2");
            if (_info == null)
                throw new UProveSerializationException("info");
            if (proof == null)
                throw new UProveSerializationException("ieproof");


            if (_info.Equals("NULL"))
                additionalInfo = null;
            else
                additionalInfo = _info.ToByteArray();

            this.deserializationStarted = true;
        }

        void IParametrizedDeserialization.FinishDeserialization(IssuerParameters ip)
        {
            try
            {
                if (!this.deserializationStarted)
                {
                    throw new SerializationException("deserialization not started");
                }

                E1 = _E1.ToGroupElement(ip);
                E2 = _E2.ToGroupElement(ip);
                (this.proof as IParametrizedDeserialization).FinishDeserialization(ip);
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

        #endregion
    }

    //**********  Proof *********************//

    /// <summary>
    /// Simple struct-like class to hold the proof associated to a ciphertext.
    /// The proof is generated with <c>VerifiableEncrypt</c>, so this class
    /// will not be used by users of the ID escrow library.
    /// </summary>
    /// <seealso cref="IDEscrow.IDEscrowFunctions.VerifiableEncrypt"/>
    [DataContract]
    public class IDEscrowProof : IParametrizedDeserialization
    {
        public FieldZqElement c;
        public FieldZqElement rXb;
        public FieldZqElement rR;
        public FieldZqElement rOb;

        /// <summary>
        /// Create a new object to hold the proof values. 
        /// </summary>
        public IDEscrowProof(FieldZqElement c, FieldZqElement rXb, FieldZqElement rR, FieldZqElement rOb)
        {
            this.c = c;
            this.rXb = rXb;
            this.rR = rR;
            this.rOb = rOb;
        }

        /// <summary>
        /// Compare two <c>IDEscrowProof</c> objects.
        /// </summary>
        /// <param name="proof2">The object to compare against.</param>
        /// <returns>True if equal, false otherwise.</returns>
        public bool Equals(IDEscrowProof proof2)
        {
            if (proof2 == null)
                return false;
            if (!proof2.c.Equals(c))
                return false;
            if (!proof2.rXb.Equals(rXb))
                return false;
            if (!proof2.rR.Equals(rR))
                return false;
            if (!proof2.rOb.Equals(rOb))
                return false;

            return true;
        }

        #region Serialization
        [DataMember(Name = "c", EmitDefaultValue = false, Order = 1)]
        internal string _c;

        [DataMember(Name = "rXb", EmitDefaultValue = false, Order = 2)]
        internal string _rXb;

        [DataMember(Name = "rR", EmitDefaultValue = false, Order = 3)]
        internal string _rR;

        [DataMember(Name = "rOb", EmitDefaultValue = false, Order = 4)]
        internal string _rOb;

        [OnSerializing]
        internal void OnSerializing(StreamingContext context)
        {
            _c = c.ToBase64String();
            _rXb = rXb.ToBase64String();
            _rR = rR.ToBase64String();
            _rOb = rOb.ToBase64String();
        }

        bool deserializationStarted = false;
        [OnDeserialized]
        internal void OnDeserialized(StreamingContext context)
        {
            if (_c == null)
                throw new UProveSerializationException("c");
            if (_rXb == null)
                throw new UProveSerializationException("rXb");
            if (_rR == null)
                throw new UProveSerializationException("rR");
            if (_rOb == null)
                throw new UProveSerializationException("rOb");

            this.deserializationStarted = true;
        }

        void IParametrizedDeserialization.FinishDeserialization(IssuerParameters ip)
        {
            try
            {
                if (!this.deserializationStarted)
                {
                    throw new SerializationException("deserialization not started");
                }

                c = _c.ToFieldElement(ip);
                rXb = _rXb.ToFieldElement(ip);
                rR = _rR.ToFieldElement(ip);
                rOb = _rOb.ToFieldElement(ip);
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

        #endregion

    }

}