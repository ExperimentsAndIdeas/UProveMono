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
using UProveCrypto.Math;

namespace UProveCrypto.DVARevocation
{
    /// <summary>
    /// Contains a non-revocation proof.
    /// </summary>
    [DataContract]
    public class NonRevocationProof : IParametrizedDeserialization
    {
        /// <summary>
        /// The <c>c'</c> value.
        /// </summary>
        public FieldZqElement cPrime { get; private set; }
        
        /// <summary>
        /// The <c>s</c> values.
        /// </summary>
        public FieldZqElement[] s { get; private set; }
        
        /// <summary>
        /// The <c>X</c> value.
        /// </summary>
        public GroupElement X { get; private set; }
        
        /// <summary>
        /// the <c>Y</c> value.
        /// </summary>
        public GroupElement Y { get; private set; }
        
        /// <summary>
        /// The <c>Cd</c> value.
        /// </summary>
        public GroupElement Cd { get; private set; }

        /// <summary>
        /// Constructs a non-revocation proof instance.
        /// </summary>
        /// <param name="cPrime">The <c>c'</c> value.</param>
        /// <param name="s">The <c>s</c> value.</param>
        /// <param name="X">The <c>X</c> value.</param>
        /// <param name="Y">The <c>Y</c> value.</param>
        /// <param name="Cd">The <c>Cd</c> value.</param>
        public NonRevocationProof(FieldZqElement cPrime, FieldZqElement[] s, GroupElement X, GroupElement Y, GroupElement Cd)
        {
            if (cPrime == null)
            {
                throw new ArgumentNullException("cPrime");
            }
            this.cPrime = cPrime;
            if (s == null || s.Length != 6)
            {
                throw new ArgumentException("s");
            }
            this.s = s;
            if (X == null)
            {
                throw new ArgumentNullException("X");
            }
            this.X = X;
            if (Y == null)
            {
                throw new ArgumentNullException("Y");
            }
            this.Y = Y;
            if (Cd == null)
            {
                throw new ArgumentNullException("Cd");
            }
            this.Cd = Cd;
        }


        #region Serialization

        [DataMember(Name = "cPrime", Order = 1)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string _cPrime;

        [DataMember(Name = "s", Order = 2)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string[] _s;

        [DataMember(Name = "X", Order = 3)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string _X;

        [DataMember(Name = "Y", Order = 4)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string _Y;

        [DataMember(Name = "Cd", Order = 5)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string _Cd;

        [OnSerializing]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnSerializing(StreamingContext context)
        {
            _cPrime = this.cPrime.ToBase64String();
            _s = new string[this.s.Length];
            for (int i = 0; i < this.s.Length; i++)
            {
                _s[i] = this.s[i].ToBase64String();
            }
            _X = this.X.ToBase64String();
            _Y = this.Y.ToBase64String();
            _Cd = this.Cd.ToBase64String();
        }

        bool deserializationStarted = false;
        [OnDeserialized]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnDeserialized(StreamingContext context)
        {
            if (_cPrime == null)
            {
                throw new UProveSerializationException("cPrime");
            }
            if (_s == null || _s.Length != 6)
            {
                throw new UProveSerializationException("s");
            }
            if (_X == null)
            {
                throw new UProveSerializationException("X");
            }
            if (_Y == null)
            {
                throw new UProveSerializationException("Y");
            }
            if (_Cd == null)
            {
                throw new UProveSerializationException("Cd");
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

                this.cPrime = _cPrime.ToFieldZqElement(ip.Zq);
                this.s = new FieldZqElement[6];
                for (int i = 0; i < 6; i++)
                {
                    this.s[i] = _s[i].ToFieldZqElement(ip.Zq);
                }
                this.X = _X.ToGroupElement(ip.Gq);
                this.Y = _Y.ToGroupElement(ip.Gq);
                this.Cd = _Cd.ToGroupElement(ip.Gq);

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
