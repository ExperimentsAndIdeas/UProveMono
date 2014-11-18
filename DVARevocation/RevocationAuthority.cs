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
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.Serialization;
using UProveCrypto.Math;

namespace UProveCrypto.DVARevocation
{
 
    /// <summary>
    /// Implements the Revocation Authority for the Designated Verifier Accumulator scheme.
    /// </summary>
    [DataContract]
    public class RevocationAuthority : IParametrizedDeserialization
    {
        [DataMember(Name = "rap", Order = 1)]
        /// <summary>
        /// The Revocation Authority parameters.
        /// </summary>
        public RAParameters RAParameters { get; private set; }

        private GroupElement accumulator;
        /// <summary>
        /// The current accumulator value.
        /// </summary>
        public GroupElement Accumulator { 
            get
            {
                return accumulator;
            }
            set 
            {
                if (value == null)
                {
                    accumulator = RAParameters.gt;
                }
                else
                {
                    accumulator = value;
                }

            }
        }

        /// <summary>
        /// The Revocation Authority private key.
        /// </summary>
        public FieldZqElement PrivateKey { get; private set; }

        /// <summary>
        /// Constructs a RevocationAuthority instance.
        /// </summary>
        /// <param name="raParams">The public parameters.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="accumulator">The optional current accumulator. If not present, then the accumulator is reset and the revocation list is considered empty.</param>
        public RevocationAuthority(RAParameters raParams, FieldZqElement privateKey, GroupElement accumulator = null)
        {
            RAParameters = raParams;
            PrivateKey = privateKey;
            Accumulator = accumulator;
        }


        /// <summary>
        /// Add or remove a single value from the accumulator.
        /// </summary>
        /// <param name="revoked">The value to add or remove.</param>
        /// <param name="add">If <c>true</c>, the value is added to the accumulator; otherwise it is removed.</param>
        public void UpdateAccumulator(FieldZqElement revoked, bool add = true)
        {
            if (revoked == null)
            {
                return;
            }
            HashSet<FieldZqElement> addSet = new HashSet<FieldZqElement>();
            HashSet<FieldZqElement> removeSet = new HashSet<FieldZqElement>();
            if (add)
            {
                addSet.Add(revoked);
            }
            else
            {
                removeSet.Add(revoked);
            }
            UpdateAccumulator(addSet, removeSet);
        }

        /// <summary>
        /// Updates the accumulator with values added to and removed from the revocation list. 
        /// Although unuseful, it is legal to have a value present in both the revoked and unrevoked set.
        /// </summary>
        /// <param name="revoked">Set of values to add to the accumulator.</param>
        /// <param name="unrevoked">Set of values to remove from the accumulator (optional).</param>
        public void UpdateAccumulator(HashSet<FieldZqElement> revoked, HashSet<FieldZqElement> unrevoked = null)
        {
            var minusDelta = PrivateKey.Negate();

            var exponent = RAParameters.group.FieldZq.One;
            if (revoked != null)
            {
                foreach (var x in revoked)
                {
                    if (minusDelta.Equals(x)) // TODO: add unit test with -delta on revocation list
                    {
                        throw new ArgumentException("revoked set cannot contain the negation of the private key");
                    }
                    exponent *= (PrivateKey + x);
                }
                Accumulator = Accumulator.Exponentiate(exponent);
            }

            exponent = RAParameters.group.FieldZq.One;
            if (unrevoked != null)
            {
                foreach (var x in unrevoked)
                {
                    if (minusDelta.Equals(x)) // TODO: add unit test with -delta on revocation list
                    {
                        throw new ArgumentException("unrevoked set cannot contain the negation of the private key");
                    }
                    exponent *= (PrivateKey + x);
                }
                Accumulator = Accumulator.Exponentiate(exponent.Invert());
            }
        }

        /// <summary>
        /// Computes the revocation witness for a specific user attribute.
        /// </summary>
        /// <param name="revoked">Set of revoked values.</param>
        /// <param name="xid">The user attribute.</param>
        /// <returns>A revocation witness.</returns>
        public RevocationWitness ComputeRevocationWitness(HashSet<FieldZqElement> revoked, FieldZqElement xid)
        {
            if (revoked.Contains(xid))
            {
                throw new ArgumentException("xid cannot be in revoked set");
            }
            Group Gq = RAParameters.group;
            FieldZq Zq = Gq.FieldZq;
            FieldZqElement d = Zq.One;
            FieldZqElement deltaPlusXProd = Zq.One;
            foreach (var x in revoked) {
                if (x + this.PrivateKey == Zq.Zero) {
                    throw new ArgumentException("revocationList cannot contain the negation of the private key");
                }
                d *= (x - xid);
                deltaPlusXProd *= (this.PrivateKey + x);
            }
            
            GroupElement W = RAParameters.gt.Exponentiate((deltaPlusXProd - d) * (PrivateKey + xid).Invert());
            GroupElement Q = Gq.MultiExponentiate(new GroupElement[] { Accumulator, W, RAParameters.gt }, new FieldZqElement[] { Zq.One, xid.Negate(), d.Negate() });
            return new RevocationWitness(d, W, Q);
        }

        /// <summary>
        /// Verifies a non-revocation proof.
        /// </summary>
        /// <param name="ip">The issuer parameters associated with the proof.</param>
        /// <param name="revocationCommitmentIndex">The 0-based index corresponding to the revocation commitment in the proof.</param>
        /// <param name="proof">The presentation proof.</param>
        /// <param name="nrProof">The non-revocation proof.</param>
        /// <exception cref="InvalidUProveArtifactException">Thrown if the proof is invalid.</exception>
        public void VerifyNonRevocationProof(IssuerParameters ip, int revocationCommitmentIndex, PresentationProof proof, NonRevocationProof nrProof)
        {
            Group Gq = ip.Gq;
            FieldZq Zq = Gq.FieldZq;
            GroupElement tildeCid = proof.Commitments[revocationCommitmentIndex].TildeC;
            // T1 = (V Y^-1 Cd^-1)^c' * X^s1 * (tildeCid K)^-s2 * g1^s3
            GroupElement T1 = Gq.MultiExponentiate(
                new GroupElement[] {
                    Accumulator * nrProof.Y.Exponentiate(Zq.NegativeOne) * nrProof.Cd.Exponentiate(Zq.NegativeOne), // TODO: is there a better way to calculate this
                    nrProof.X,
                    tildeCid * RAParameters.K,
                    RAParameters.g1
                },
                new FieldZqElement[] {
                    nrProof.cPrime,
                    nrProof.s[0], // s1
                    nrProof.s[1].Negate(), // s2
                    nrProof.s[2] // s3
                });
            // T2 = tildeCid^c' g^s1 g1^s4
            GroupElement T2 = Gq.MultiExponentiate(
                new GroupElement[] {
                    tildeCid,
                    RAParameters.g,
                    RAParameters.g1
                },
                new FieldZqElement[] {
                    nrProof.cPrime,
                    nrProof.s[0], // s1
                    nrProof.s[3], // s4
                });
            // T3 = gt^c' Cd^s5 g1^s6
            GroupElement T3 = Gq.MultiExponentiate(
                new GroupElement[] {
                    RAParameters.gt,
                    nrProof.Cd,
                    RAParameters.g1
                },
                new FieldZqElement[] {
                    nrProof.cPrime,
                    nrProof.s[4], // s5
                    nrProof.s[5], // s6
                });
            if (!nrProof.cPrime.Equals(Zq.GetElementFromDigest(RAParameters.ComputeChallenge(tildeCid, nrProof.X, nrProof.Y, nrProof.Cd, T1, T2, T3))) ||
                !nrProof.Y.Equals(nrProof.X.Exponentiate(PrivateKey)))
            {
                throw new InvalidUProveArtifactException("Invalid non-revocation proof"); 
            }
        }

        /// <summary>
        /// Generates a new Revocation Authority.
        /// </summary>
        /// <param name="ip">A set of Issuer parameters from which to extract the group.</param>
        /// <returns>A Revocation Authority instance.</returns>
        public static RevocationAuthority GenerateRevocationAuthority(IssuerParameters ip)
        {
            return GenerateRevocationAuthority(ip.Gq.GroupName, ip.UidH);
        }

        /// <summary>
        /// Generates a new Revocation Authority.
        /// </summary>
        /// <param name="groupName">A group name.</param>
        /// <param name="uidh">The hash algorithm UID.</param>
        /// <returns>A Revocation Authority instance.</returns>
        public static RevocationAuthority GenerateRevocationAuthority(string groupName, string uidh)
        {
            ParameterSet set;
            Group Gq = null;
            if (ParameterSet.TryGetNamedParameterSet(groupName, out set))
            {
                Gq = set.Group;
            }
            else
            {
                throw new ArgumentException("unknown group: " + groupName);
            }
            
            FieldZqElement delta = Gq.FieldZq.GetRandomElement(true);
            // K = g1^delta
            GroupElement K = Gq.G.Exponentiate(delta);
            return new RevocationAuthority(
                new RAParameters(groupName, K, uidh),
                delta
                );
        }

        /// <summary>
        /// Computes the revocation value from its byte array encoding, to be added to an accumulator or used
        /// to compute the witness.
        /// </summary>
        /// <param name="ip">The issuer parameters, containing the information on how to transform the encoded value.</param>
        /// <param name="revocationIndex">The 1-based index of the revocation attribute.</param>
        /// <param name="attributeValue">The attribute value.</param>
        /// <returns>The revocation value.</returns>
        public static FieldZqElement ComputeRevocationValue(IssuerParameters ip, int revocationIndex, byte[] attributeValue) {
            if (revocationIndex <= 0)
            {
                throw new ArgumentException("revocationIndex must be positive: " + revocationIndex);
            }
            return ProtocolHelper.ComputeXi(ip, revocationIndex - 1, attributeValue);
        }

        #region Serialization

        // "rap": RAParameters, Order = 1 (see above)

        [DataMember(Name = "V", Order = 2)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string _V;

        [DataMember(Name = "delta", Order = 3)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string _delta;

        [OnSerializing]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnSerializing(StreamingContext context)
        {
            _V = this.accumulator.ToBase64String();
            _delta = this.PrivateKey.ToBase64String();
        }

        bool deserializationStarted = false;
        [OnDeserialized]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnDeserialized(StreamingContext context)
        {
            if (_V == null)
            {
                throw new UProveSerializationException("V");
            }
            if (_delta == null)
            {
                throw new UProveSerializationException("delta");
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

                this.PrivateKey = _delta.ToFieldZqElement(ip.Zq);
                this.Accumulator = _V.ToGroupElement(ip.Gq);
                (this.RAParameters as IParametrizedDeserialization).FinishDeserialization(ip);
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
