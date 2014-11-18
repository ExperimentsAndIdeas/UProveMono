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
    /// Contains the revocation witness corresponding to a revocation attribute.
    /// </summary>
    [DataContract]
    public class RevocationWitness : IParametrizedDeserialization
    {
        /// <summary>
        ///  The <c>d</c> value.
        /// </summary>
        public FieldZqElement d { get; private set; }

        /// <summary>
        ///  The <c>W</c> value.
        /// </summary>
        public GroupElement W { get; private set; }

        /// <summary>
        ///  The <c>Q</c> value.
        /// </summary>
        public GroupElement Q { get; private set; }

        /// <summary>
        /// Constructs a new <c>RevocationWitness</c> instance.
        /// </summary>
        /// <param name="d">The <c>d</c> value.</param>
        /// <param name="W">The <c>W</c> value.</param>
        /// <param name="Q">The <c>Q</c> value.</param>
        public RevocationWitness(FieldZqElement d, GroupElement W, GroupElement Q) {
            if (d == null) { throw new ArgumentNullException("d"); }
            this.d = d;
            if (W == null) { throw new ArgumentNullException("W"); }
            this.W = W;
            if (Q == null) { throw new ArgumentNullException("Q"); }
            this.Q = Q;
        }

        #region Serialization

        [DataMember(Name = "d", Order = 1)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string _d;

        [DataMember(Name = "W", Order = 2)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string _W;

        [DataMember(Name = "Q", Order = 3)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string _Q;

        [OnSerializing]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnSerializing(StreamingContext context)
        {
            _d = this.d.ToBase64String();
            _W = this.W.ToBase64String();
            _Q = this.Q.ToBase64String();
        }

        bool deserializationStarted = false;
        [OnDeserialized]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnDeserialized(StreamingContext context)
        {
            if (_d == null)
            {
                throw new UProveSerializationException("d");
            }
            if (_W == null)
            {
                throw new UProveSerializationException("W");
            }
            if (_Q == null)
            {
                throw new UProveSerializationException("Q");
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

                this.d = _d.ToFieldZqElement(ip.Zq);
                this.W = _W.ToGroupElement(ip.Gq);
                this.Q = _Q.ToGroupElement(ip.Gq);
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
