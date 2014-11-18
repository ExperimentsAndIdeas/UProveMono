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
using UProveCrypto.Math;

namespace UProveCrypto.DVARevocation
{
    /// <summary>
    /// Contains the random values to generate a non-revocation proof.
    /// </summary>
    public class NonRevocationProofGenerationRandomData
    {
        private FieldZqElement[] tk;

        /// <summary>
        /// The <c>t1</c> value.
        /// </summary>
        public FieldZqElement t1 { get { return tk[0]; } }

        /// <summary>
        /// The <c>t2</c> value.
        /// </summary>
        public FieldZqElement t2 { get { return tk[1]; } }

        /// <summary>
        /// The <c>k1</c> value.
        /// </summary>
        public FieldZqElement k1 { get { return tk[2]; } }


        /// <summary>
        /// The <c>k2</c> value.
        /// </summary>
        public FieldZqElement k2 { get { return tk[3]; } }


        /// <summary>
        /// The <c>k3</c> value.
        /// </summary>
        public FieldZqElement k3 { get { return tk[4]; } }


        /// <summary>
        /// The <c>k4</c> value.
        /// </summary>
        public FieldZqElement k4 { get { return tk[5]; } }

        /// <summary>
        /// The <c>k5</c> value.
        /// </summary>
        public FieldZqElement k5 { get { return tk[6]; } }

        /// <summary>
        /// The <c>k6</c> value.
        /// </summary>
        public FieldZqElement k6 { get { return tk[7]; } }

        /// <summary>
        /// Constructs a new <c>NonRevocationProofGenerationRandomData</c> instance.
        /// </summary>
        /// <param name="tkValues">The values <c>t1, t2, k1, k2, k3, k4, k5, k6</c>.</param>
        public NonRevocationProofGenerationRandomData(FieldZqElement[] tkValues)
        {
            if (tkValues == null || tkValues.Length != 8)
            {
                throw new ArgumentException("tkValues must contain 8 values");
            }

            this.tk = tkValues;
        }

        /// <summary>
        /// Clears the object.  Note that this does *not* securely zero the memory.
        /// </summary>
        public void Clear()
        {
            // TODO: This should zero the memory rather than just setting to null.
            //       Challening to do this in C#, so we will need to make this change
            //       as part of a comprehensive change throughout the library.
            tk = null;
        }

        /// <summary>
        /// Generates a <code>NonRevocationProofGenerationRandomData</code> instance using the internal RNG.
        /// </summary>
        /// <param name="Zq">Field Zq</param>
        /// <returns>A pregenerated set of random values.</returns>
        public static NonRevocationProofGenerationRandomData Generate(FieldZq Zq)
        {
            return new NonRevocationProofGenerationRandomData(Zq.GetRandomElements(8, false));
        }
    }

    /// <summary>
    /// Implements the user for the Designated Verifier Accumulator scheme.
    /// </summary>
    public class RevocationUser
    {
        // static class
        private RevocationUser()
        { }

        /// <summary>
        /// Updates the revocation witness for a user, either adding or removing a revoked value.
        /// </summary>
        /// <param name="rap">The Revocation Authority parameters.</param>
        /// <param name="xid">The revocation attribute value <c>xid</c>.</param>
        /// <param name="revoked">The attribute value to added to the accumulator, or <c>null</c>.</param>
        /// <param name="unrevoked">The attribute value to deleted to the accumulator, or <c>null</c>.</param>
        /// <param name="oldAccumulator">The old accumulator value <c>V</c>. If <c>null</c>, then the accumulator is freshly calculated.</param>
        /// <param name="updatedAccumulator">The old accumulator value <c>V'</c>.</param>
        /// <param name="oldWitness">The old witness values. If <c>null</c>, then the witness is freshly calculated.</param>
        /// <returns></returns>
        public static RevocationWitness UpdateWitness(RAParameters rap, FieldZqElement xid, FieldZqElement revoked, FieldZqElement unrevoked, GroupElement oldAccumulator, GroupElement updatedAccumulator, RevocationWitness oldWitness)
        {
            // TODO: implement batch updates
            if (revoked != null && unrevoked != null)
            {
                throw new ArgumentException("only one of revoked and unrevoked can be non-null");
            }

            FieldZqElement one = rap.group.FieldZq.One;
            if (oldAccumulator == null)
            {
                // set the accumulator value for an empty revocation set
                oldAccumulator = rap.gt;
            }
            if (oldWitness == null)
            {
                oldWitness = new RevocationWitness(rap.group.FieldZq.One, rap.group.Identity, rap.group.Identity);
            }

            if (revoked == null && unrevoked == null)
            {
                // nothing to do
                return oldWitness;
            }

            FieldZqElement dPrime = null;
            GroupElement WPrime = null;
            GroupElement QPrime = null;

            FieldZqElement xDiff = one;
            // add values to witness
            if (revoked != null)
            {
                xDiff = (revoked - xid);
                dPrime = oldWitness.d * xDiff;
                WPrime = oldAccumulator * oldWitness.W.Exponentiate(xDiff);
            }

            xDiff = one;
            // remove values from witness
            if (unrevoked != null)
            {
                xDiff = (unrevoked - xid).Invert();
                dPrime = oldWitness.d * xDiff;
                WPrime = updatedAccumulator.Exponentiate(one.Negate()) * oldWitness.W.Exponentiate(xDiff);
            }

            // update QPrime value
            QPrime = updatedAccumulator * WPrime.Exponentiate(xid.Negate()) * rap.gt.Exponentiate(dPrime.Negate());

            return new RevocationWitness(dPrime, WPrime, QPrime);
        }

        /// <summary>
        /// Generates a non-revocation proof.
        /// </summary>
        /// <param name="rap">The Revocation Authority parameters.</param>
        /// <param name="rw">The user's revocation witness.</param>
        /// <param name="tildeCid">The revocation attribute commitment.</param>
        /// <param name="xid">The revocation attribute.</param>
        /// <param name="tildeOid">The revocation attribute commitment's opening value.</param>
        /// <param name="preGenRandom">The optional pre-generated random values for the proof, or <c>null</c>.</param>
        /// <returns></returns>
        public static NonRevocationProof GenerateNonRevocationProof(RAParameters rap, RevocationWitness rw, GroupElement tildeCid, FieldZqElement xid, FieldZqElement tildeOid, NonRevocationProofGenerationRandomData preGenRandom = null)
        {
            if (rap == null || rw == null || tildeCid == null || xid == null || tildeOid == null)
            {
                throw new ArgumentNullException("null input to GenerateNonRevocationProof");
            }

            Group Gq = rap.group;
            FieldZq Zq = Gq.FieldZq;
            NonRevocationProofGenerationRandomData rand = preGenRandom;
            if (rand == null)
            {
                rand = NonRevocationProofGenerationRandomData.Generate(Zq);
            }
            GroupElement X = rw.W * rap.g.Exponentiate(rand.t1);
            GroupElement Y = rw.Q * rap.K.Exponentiate(rand.t1);
            GroupElement Cd = rap.gt.Exponentiate(rw.d) * rap.g1.Exponentiate(rand.t2);
            FieldZqElement w = rw.d.Invert();
            FieldZqElement z = rand.t1 * tildeOid - rand.t2;
            FieldZqElement zPrime = rand.t2.Negate() * w;
            GroupElement T1 = Gq.MultiExponentiate(new GroupElement[] { X, tildeCid * rap.K, rap.g1 }, new FieldZqElement[] { rand.k1, rand.k2.Negate(), rand.k3 });
            GroupElement T2 = Gq.MultiExponentiate(new GroupElement[] { rap.g, rap.g1 }, new FieldZqElement[] { rand.k1, rand.k4 });
            GroupElement T3 = Gq.MultiExponentiate(new GroupElement[] { Cd, rap.g1 }, new FieldZqElement[] { rand.k5, rand.k6 });
            FieldZqElement cPrime = Zq.GetElementFromDigest(rap.ComputeChallenge(tildeCid, X, Y, Cd, T1, T2, T3));
            FieldZqElement cPrimeNegate = cPrime.Negate();
            FieldZqElement s1 = cPrimeNegate * xid + rand.k1;
            FieldZqElement s2 = cPrimeNegate * rand.t1 + rand.k2;
            FieldZqElement s3 = cPrimeNegate * z + rand.k3;
            FieldZqElement s4 = cPrimeNegate * tildeOid + rand.k4;
            FieldZqElement s5 = cPrimeNegate * w + rand.k5;
            FieldZqElement s6 = cPrimeNegate * zPrime + rand.k6;
            rand.Clear();
            return new NonRevocationProof(cPrime, new FieldZqElement[] { s1, s2, s3, s4, s5, s6 }, X, Y, Cd);
        }

        /// <summary>
        /// Computes the non-revocation proof.
        /// </summary>
        /// <param name="ip">The Issuer parameters associated with the presented U-Prove token.</param>
        /// <param name="rap">The Revocation Authority parameters.</param>
        /// <param name="witness">The user non-revocation witness.</param>
        /// <param name="commitmentIndex">The 0-based index of the revocation commitment in the attribute commitments.</param>
        /// <param name="presentationProof">The presentation proof generated with the U-Prove token.</param>
        /// <param name="cpv">The commitment private values generated when presenting the U-Prove token.</param>
        /// <param name="revocationIndex">The 1-based index of the revocation attribute in the U-Prove token.</param>
        /// <param name="attributes">The token attributes.</param>
        /// <returns>A non-revocation proof.</returns>
        public static NonRevocationProof GenerateNonRevocationProof(IssuerParameters ip, RAParameters rap, RevocationWitness witness, int commitmentIndex, PresentationProof presentationProof, CommitmentPrivateValues cpv, int revocationIndex, byte[][] attributes)
        {
            if (revocationIndex <= 0)
            {
                throw new ArgumentException("revocationIndex must be positive: " + revocationIndex);
            }
            GroupElement tildeCid = presentationProof.Commitments[commitmentIndex].TildeC;
            FieldZqElement xid = ProtocolHelper.ComputeXi(ip, revocationIndex - 1, attributes[revocationIndex - 1]);
            FieldZqElement tildeOid = cpv.TildeO[commitmentIndex];
            return GenerateNonRevocationProof(rap, witness, tildeCid, xid, tildeOid);
        }
    }
}
