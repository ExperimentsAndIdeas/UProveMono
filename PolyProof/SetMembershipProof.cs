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
    /// Contains the random values to generate a non-revocation proof.
    /// </summary>
    public class SetMembershipProofGenerationRandomData
    {
        /// <summary>
        /// The <c>c</c> values.
        /// </summary>
        public FieldZqElement[] c { set; get; }

        /// <summary>
        /// The <c>r</c> values.
        /// </summary>
        public FieldZqElement[] r { set; get; }

        /// <summary>
        /// The <c>w</c> value.
        /// </summary>
        public FieldZqElement w { set; get; }

        /// <summary>
        /// Constructs a new <c>NonRevocationProofGenerationRandomData</c> instance.
        /// </summary>
        /// <param name="tkValues">The values <c>t1, t2, k1, k2, k3, k4, k5, k6</c>.</param>
        public SetMembershipProofGenerationRandomData(FieldZqElement[] c, FieldZqElement[] r, FieldZqElement w)
        {
			Console.WriteLine (c.Length + " " + r.Length +"DEBUG Length");
			 
            if (c.Length != r.Length)
            {
                throw new ArgumentException("c and r arrays must be of same size");
            }

            this.c = c;
            this.r = r;
            this.w = w;
        }

        /// <summary>
        /// Clears the object.  Note that this does *not* securely zero the memory.
        /// </summary>
        public void Clear()
        {
            // TODO: This should zero the memory rather than just setting to null.
            //       Challening to do this in C#, so we will need to make this change
            //       as part of a comprehensive change throughout the library.
            c = null;
            r = null;
            w = null;
        }

        /// <summary>
        /// Generates a <code>SetMembershipProofGenerationRandomData</code> instance using the internal RNG.
        /// </summary>
        /// <param name="Zq">Field Zq.</param>
        /// <param name="length">Desired length of the <c>c</c> and <c>r</c> arrays.</param>
        /// <returns>A pregenerated set of random values.</returns>
        public static SetMembershipProofGenerationRandomData Generate(FieldZq Zq, int length)
        {
            return new SetMembershipProofGenerationRandomData(Zq.GetRandomElements(length, false), Zq.GetRandomElements(length, false), Zq.GetRandomElement(false));
        }
    }
    
    /// <summary>
    /// This class represents the SetMembershipProof 
    /// </summary>
    [DataContract]
    public class SetMembershipProof : GroupParameterizedSerializer
    {
        /// <summary>
        /// UProve integration proof
        /// </summary>
        [DataMember(Name = "UPIProof", EmitDefaultValue = false, Order = 1)]
        public UProveIntegrationProof UPIProof;


        /* The arrays a,c,r contain the actual set membership proof.
         * 
         * Let Params be the verification parameters.
         * Let G = Params.G
         * Let H = Params.H
         * Let X = Params.ClosedCommitment
         * Let M = Params.MemberSet
         * 
         * The following relationship holds if the proof is valid:
         * forall i in [0,M.Length-1]: H^{r_i} = (X * G^{-M[i])^{c[i]} * a[i]
         */
        public GroupElement[] a { get; private set; } // commitments
        public FieldZqElement[] c { get; private set; }  // challenges
        public FieldZqElement[] r { get; private set; }  // responses

        /// <summary>
        /// Constructs a SetMembershipProof.  Throws exception if prover
        /// parameters do not allow creating valid proof.
        /// </summary>
        /// <param name="prover">Prover parameters</param>
        /// <param name="smRandom">The optional pre-generated random values to generate the proof, or <c>null</c>.</param>
        public SetMembershipProof(ProverSetMembershipParameters prover, SetMembershipProofGenerationRandomData smRandom = null)
        {
            ConstructorHelper(prover, smRandom);
        }

        private void ConstructorHelper(ProverSetMembershipParameters prover, SetMembershipProofGenerationRandomData smRandom = null)
        {
            try
            {
                // check that parameters can be used to construct valid proof.
                if (!prover.Verify())
                {
                    throw new ArgumentException("Invalid proof parameters.  Cannot create proof");
                }

                // set Group context
                this.Group = prover.Group;
                this.IsGroupSerializable = true;

                // allocate space for proof
                this.c = new FieldZqElement[prover.MemberSet.Length - 1];
                this.a = new GroupElement[prover.MemberSet.Length];
                this.r = new FieldZqElement[prover.MemberSet.Length];

                // generate random values needed for proof
                if (smRandom == null)
                {
                    // generate a pair of random values for each fake proofs, plus the random exponent for the real one
                    smRandom = SetMembershipProofGenerationRandomData.Generate(prover.FieldZq, prover.MemberSet.Length - 1);
                }

                // Find index of prover.OpenCommitment.CommittedValue in prover.MemberSet
                int indexOfCommittedValue = prover.IndexOfCommittedValueInSet;

                // generate a fake proof for each prover.MemberSet element that is not
                // equal to CommitedValue.
                FieldZqElement sumOfSubChallenges = prover.FieldZq.Zero;

                int randomIndex = 0;
                for (int index = 0; index < prover.MemberSet.Length; ++index)
                {
                    if (index != indexOfCommittedValue)
                    {
                        this.generateFakeProof(index, prover, smRandom.c[randomIndex], smRandom.r[randomIndex]);
                        sumOfSubChallenges += smRandom.c[randomIndex];
                        randomIndex++;
                    }
                }

                // generate challenge, and a real proof for committment.CommittedValue
                this.generateRealA(indexOfCommittedValue, prover, smRandom.w);
                FieldZqElement challenge = this.ComputeChallenge(prover);
                this.generateRealProof(indexOfCommittedValue, prover, smRandom.w, sumOfSubChallenges.Negate() + challenge);

            }
            catch (Exception e)
            {
                throw new Exception("Could not create SetMembershipProof.", e);
            }
        }

        /// <summary>
        /// Computes the challenge.  This method is used by both the prover and verifier.
        /// </summary>
        /// <param name="verifier">Verifier parameters</param>
        /// <returns>Challenge</returns>
        private FieldZqElement ComputeChallenge(VerifierSetMembershipParameters verifier)
        {
            HashFunction hash = new HashFunction(verifier.HashFunctionName);
            // H(desc(Gq), g = G, g1 = H, <S>, C, <a>)
            verifier.Group.UpdateHash(hash);
            hash.Hash(verifier.G);
            hash.Hash(verifier.H);
            hash.Hash(verifier.MemberSet);
            hash.Hash(verifier.ClosedCommitment);
            hash.Hash(this.a);
            return verifier.FieldZq.GetElementFromDigest(hash.Digest);
        }

        /// <summary>
        /// Verify that this object contains a valid proof for the statement contained in
        /// verifier parameters.
        /// </summary>
        /// <param name="verifier">Common parameters for prover and verifier.</param>
        /// <returns>True if this is a valid proof, false otherwise. Returns false on error (no exceptions thrown).</returns>
        public bool Verify(VerifierSetMembershipParameters verifier)
        {
            try
            {
                // check parameters
                if (!verifier.Verify())
                {
                    return false;
                }

                // make sure a,c,r are not null
                if ((a == null) || (c == null) || (r == null))
                {
                    return false;
                }

                // make sure parameters correspond to the proof.
                if ((verifier.MemberSet.Length != a.Length)
                    || (verifier.MemberSet.Length -1 != c.Length)
                    || (verifier.MemberSet.Length != r.Length)
                    || (verifier.Group != this.Group))
                {
                    return false;
                }


                // Verify each tuple a[index],c[index], r[index]
                for (int index = 0; index < verifier.MemberSet.Length; ++index)
                {
                    if (!VerifySubProof(verifier, index))
                    {
                        return false;
                    }
                }
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Helper method for Verify.
        /// Verifies that the (a[indexForMemberSet],c[indexForMemberSet],r[indexForMemberSet]) are
        /// a valid proof for verifier.MemberSet[indexForMemberSet].
        /// </summary>
        /// <param name="verifier">Verifier parameters</param>
        /// <param name="indexForMemberOfSet">index into verifier.MemberSet</param>
        /// <returns>True on success, false on failure.</returns>
        private bool VerifySubProof(VerifierSetMembershipParameters verifier, int indexForMemberOfSet)
        {
            // get the current challenge
            FieldZqElement subC;
            if (indexForMemberOfSet < this.c.Length)
            {
                subC = this.c[indexForMemberOfSet];
            }
            else
            {
                FieldZqElement challenge = this.ComputeChallenge(verifier);
                FieldZqElement sumOfSubChallenges = verifier.FieldZq.Zero;
                for (int i = 0; i < this.c.Length; ++i)
                {
                    sumOfSubChallenges += this.c[i];
                }
                subC = challenge - sumOfSubChallenges;
            }

            // compute leftSide
            GroupElement leftSide = verifier.H.Exponentiate(this.r[indexForMemberOfSet]);

            // compute rightSide = X^{c} * g^{-memberOfSet * c} * a
            GroupElement[] bases = new GroupElement[]
            {
                verifier.ClosedCommitment,                  // X
                verifier.G,                                 // g
                this.a[indexForMemberOfSet]                 // a
            };
            FieldZqElement[] exponents = new FieldZqElement[]
            {
                subC,                                                     // c
                verifier.MemberSet[indexForMemberOfSet].Negate() * subC, // -memberOfSet * c
                verifier.FieldZq.One                                                            // 1
            };
            GroupElement rightSide = verifier.Group.MultiExponentiate(bases, exponents);

            return (leftSide == rightSide);
        }

        /// <summary>
        /// Helper method for constructing proof. Computes a[index], c[index], r[index] values for when
        /// the committedValue is not equal to prover.MemberSet[index]. 
        /// </summary>
        /// <param name="index">Index into prover.MemberSet</param>
        /// <param name="prover">Prover parameters</param>
        /// <param name="randomChallengeValue">Value to set c[index]</param>
        /// <param name="randomResponseValue">Value to set r[index]</param>
        private void generateFakeProof(int index, ProverSetMembershipParameters prover, FieldZqElement randomChallengeValue, FieldZqElement randomResponseValue)
        {
            if (index < this.c.Length)
            {
                this.c[index] = randomChallengeValue;
            }

            this.r[index] = randomResponseValue;

            // compute this.a[index] as a multi-exponentiation
            // a[index] = h^r[index] * g^{memberset[index] + c[index]} * X^{-c[index]
            GroupElement[] bases = new GroupElement[3]
            {
                prover.H,                         // h
                prover.G,                         // g
                prover.ClosedCommitment           // X
            };
            FieldZqElement[] exponents = new FieldZqElement[3]
            {
                randomResponseValue,                           // r[index]
                prover.MemberSet[index] * randomChallengeValue,       // memberset[index] * c
                randomChallengeValue.Negate()                  // -c
            };
            this.a[index] = prover.Group.MultiExponentiate(bases, exponents);
        }

        /// <summary>
        /// Helper method for constructing proof.
        /// Generates a the c, r, a values for when the committed value is identical to
        /// the element in the memberSet located at index.
        /// </summary>
        /// <param name="index">Index into prover.MemberSet</param>
        /// <param name="prover">Prover parameters</param>
        /// <param name="randomWValue">random value to use to compute proof</param>
        /// <param name="challengeValue">Challenge to use to compute proof</param>
        private void generateRealProof(int index, ProverSetMembershipParameters prover, FieldZqElement randomWValue, FieldZqElement challengeValue)
        {
            if (index < this.c.Length)
            {
                this.c[index] = challengeValue;
            }
            this.r[index] = (challengeValue * prover.OpenCommitment.Opening) + randomWValue;
        }

        /// <summary>
        /// Helper method for constructing proof.
        /// Computes a[index].
        /// </summary>
        /// <param name="index">Index into prover.MemberSet</param>
        /// <param name="prover">Prover parameters</param>
        /// <param name="randomWValue">random value</param>
        private void generateRealA(int index, ProverSetMembershipParameters prover, FieldZqElement randomWValue)
        {
            this.a[index] = prover.OpenCommitment.H.Exponentiate(randomWValue);
        }


        #region Serialization

        /// <summary>
        /// Serialization of a
        /// </summary>
        [DataMember(Name = "a", EmitDefaultValue = false, Order = 2)]
        internal string[] _a;

        /// <summary>
        /// Serialization of c
        /// </summary>
        [DataMember(Name = "c", EmitDefaultValue = false, Order = 3)]
        internal string[] _c;

        /// <summary>
        /// Serialization of r
        /// </summary>
        [DataMember(Name = "r", EmitDefaultValue = false, Order = 4)]
        internal string[] _r;

        /// <summary>
        /// Serialize a, c, r.
        /// </summary>
        /// <param name="context">The streaming context.</param>
        [OnSerializing]
        internal void OnSerializing(StreamingContext context)
        {
			Console.WriteLine ("Debug: HORRAY OnSerializing(context) called");

            // we assume that the arrays a, c, and r have the same length
            int length = a.Length;
            if (length -1 != c.Length || length != r.Length)
            {
                throw new SerializationException("Arrays a and r must have the same length, while c must be one element shorter.");
            }
            _a = CryptoSerializer.SerializeGroupElementArray(this.a, "a");
            _c = CryptoSerializer.SerializeFieldZqElementArray(this.c, "c");
            _r = CryptoSerializer.SerializeFieldZqElementArray(this.r, "r");
        }

        /// <summary>
        /// Deserialize a,c,r.
        /// </summary>
        public override void FinishDeserializing()
        {

            a = CryptoSerializer.DeserializeGroupElementArray(_a, "a", this.Group);
            c = CryptoSerializer.DeserializeFieldZqElementArray(_c, "c", this.Group);
            r = CryptoSerializer.DeserializeFieldZqElementArray(_r, "r", this.Group);

            if (a.Length - 1 != c.Length || a.Length != r.Length)
            {
                throw new SerializationException("Arrays a, and r must have the same length, while c must be one element shorter.");
            }

            if (this.UPIProof != null)
            {
                this.UPIProof.FinishDeserializing(this.Group);
            }
        }
        #endregion

        #region UProveWrapper

        /// <summary>
        /// Constructor. Creates a proof that a token attribute is in a given set.
        /// </summary>
        /// <param name="prover">Token description.</param>
        /// <param name="attributeIndexForProver">1-based attribute index in token.</param>
        /// <param name="setValues">Set of attributes to compare to token attribute.</param>
        /// <param name="smRandom">Random data for set membership proof.</param>
        /// <returns>Inequality proof.</returns>
        public SetMembershipProof(ProverPresentationProtocolParameters prover, int attributeIndexForProver, byte[][] setValues, SetMembershipProofGenerationRandomData smRandom = null)
        {
            // generate Pedersen Commitments to token attribute
            ProverPresentationProtocolParameters[] provers = new ProverPresentationProtocolParameters[] { prover };
            int[] attributeIndices = new int[] { attributeIndexForProver };
            PedersenCommitment[] attributeCommitments = PedersenCommitment.PedersenCommmitmentsToAttributes(provers, attributeIndices);

            // create set membership proof using Pedersen Commitment
            FieldZqElement[] memberSet = VerifierSetMembershipParameters.GenerateMemberSet(prover.IP, attributeIndexForProver, setValues);
            ProverSetMembershipParameters setProver = new ProverSetMembershipParameters(attributeCommitments[0], memberSet, new CryptoParameters(prover.IP));
            ConstructorHelper(setProver, smRandom);

            // add UProve Integration proof
            this.UPIProof = new UProveIntegrationProof(provers, attributeIndices, attributeCommitments);
            this.UPIProof.IsGroupSerializable = false;
        }

        /// <summary>
        /// Verifies that a UProve token attribute is in a given set.
        /// </summary>
        /// <param name="verifier">Verifier info about token.</param>
        /// <param name="attributeIndexForVerifier">Target attribute, 1-based index.</param>
        /// <param name="setValues">Set of values for attribute.</param>
        /// <returns></returns>
        public bool Verify(
            VerifierPresentationProtocolParameters verifier,
            int attributeIndexForVerifier,
            byte [][] setValues)
        {
            // Verify UProve Integration Proof
            if (this.UPIProof == null)
            {
                return false;
            }
            VerifierPresentationProtocolParameters[] verifiers = new VerifierPresentationProtocolParameters[1] { verifier};
            int[] attributeIndices = new int[1] { attributeIndexForVerifier};
            if (!this.UPIProof.Verify(verifiers, attributeIndices))
            {
                return false;
            }

            // Verify Set Membership Proof
            FieldZqElement[] memberSet = VerifierSetMembershipParameters.GenerateMemberSet(verifier.IP, attributeIndexForVerifier, setValues);
            VerifierSetMembershipParameters setVerifier = new VerifierSetMembershipParameters(this.UPIProof.PedersenCommitmentValues[0], memberSet, new CryptoParameters(verifier.IP));
            return this.Verify(setVerifier);
        }




        /// <summary>
        /// Generates a set membership proof from U-Prove parameters.
        /// </summary>
        /// <param name="pppp">The prover presentation protocol parameters.</param>
        /// <param name="pp">The presentation proof.</param>
        /// <param name="cpv">The commitment private values returned when generating the presentation proof.</param>
        /// <param name="committedIndex">Index of the committed attribute used to generate the set membership proof.</param>
        /// <param name="setValues">Set values to prove against.</param>
        /// <param name="smRandom">Optional pregenerated random values, or <c>null</c>.</param>
        /// <returns>A set membership proof.</returns>
        public static SetMembershipProof Generate(ProverPresentationProtocolParameters pppp, PresentationProof pp, CommitmentPrivateValues cpv, int committedIndex, byte[][] setValues, SetMembershipProofGenerationRandomData smRandom = null)
        {
            // get the index of the commitment to use, given the underlying attribute's index
            int commitmentIndex = ClosedPedersenCommitment.GetCommitmentIndex(pppp.Committed, committedIndex);
            // generate the membership proof
            ProverSetMembershipParameters setProver =
                new ProverSetMembershipParameters(
                    new PedersenCommitment(pppp, pp, cpv, commitmentIndex),
                    VerifierSetMembershipParameters.GenerateMemberSet(pppp.IP, committedIndex, setValues),
                    new CryptoParameters(pppp.IP));
            return new SetMembershipProof(setProver, smRandom);
        }

        /// <summary>
        /// Verifies a set membership proof from U-Prove parameters.
        /// </summary>
        /// <param name="vppp">The verifier presentation protocol parameters.</param>
        /// <param name="pProof">A presentation proof.</param>
        /// <param name="smProof">A set presentation proof.</param>
        /// <param name="committedIndex">Index of the committed attribute used to generate the set membership proof.</param>
        /// <param name="setValues">Set values to verify against.</param>
        /// <returns>True if the proof is valid, false otherwise.</returns>
        public static bool Verify(VerifierPresentationProtocolParameters vppp, PresentationProof pProof, SetMembershipProof smProof, int committedIndex, byte[][] setValues)
        {
            // get the index of the commitment to use, given the underlying attribute's index
            int commitmentIndex = ClosedPedersenCommitment.GetCommitmentIndex(vppp.Committed, committedIndex);
            // verify the membership proof
            ClosedDLRepOfGroupElement closedCommittedClearance = new ClosedPedersenCommitment(vppp.IP, pProof, commitmentIndex);
            VerifierSetMembershipParameters setVerifier = new VerifierSetMembershipParameters(
                closedCommittedClearance.Value,
                VerifierSetMembershipParameters.GenerateMemberSet(vppp.IP, committedIndex, setValues),
                new CryptoParameters(vppp.IP));
            return smProof.Verify(setVerifier);
        }

        #endregion

    }
}
