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
    #region UProveWrapper

    /// <summary>
    /// Base class for (in)equality proof from a U-Prove token.
    /// </summary>
    public abstract class EQProofUProveData
    {
        /// <summary>
        /// The presentation proof, containing a commitment to the attribute being proven (un)equal.
        /// </summary>
        public PresentationProof PP { get; set; }

        /// <summary>
        /// Index of the attribute being proven (un)equal.
        /// </summary>
        public int index { get; set; }
    }

    /// <summary>
    /// Contains artifact needed to generate an attribute (in)equality proof from a U-Prove token.
    /// </summary>
    public class EQProofUProveProverData : EQProofUProveData
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public EQProofUProveProverData(ProverPresentationProtocolParameters pppp, CommitmentPrivateValues cpv, PresentationProof pp, int index)
        {
            this.PPPP = pppp;
            this.CPV = cpv;
            this.PP = pp;
            this.index = index;
        }

        /// <summary>
        /// The parameters used to generate the presentation proof.
        /// </summary>
        public ProverPresentationProtocolParameters PPPP { get; set; }

        /// <summary>
        /// The private commitment value for the attribute being proven (un)equal.
        /// </summary>
        public CommitmentPrivateValues CPV { get; set; }
    }

    /// <summary>
    /// Contains artifact needed to verify an attribute inequality proof from a U-Prove token.
    /// </summary>
    public class EQProofUProveVerifierData : EQProofUProveData
    {
        /// <summary>
        /// Constructor.
        /// </summary>
        public EQProofUProveVerifierData(VerifierPresentationProtocolParameters vppp, PresentationProof pp, int index)
        {
            this.VPPP = vppp;
            this.PP = pp;
            this.index = index;
        }

        /// <summary>
        /// The parameters used to verify the presentation proof.
        /// </summary>
        public VerifierPresentationProtocolParameters VPPP { get; set; }
    }

    #endregion

    /// <summary>
    /// Proof of knowledge of equality of discrete log representations for various formulas.
    /// </summary>
    [DataContract]
    public class EqualityProof : GroupParameterizedSerializer
    {
        /// <summary>
        /// Commitment
        /// </summary>
        private GroupElement[] b;

        /// <summary>
        /// Responses for exponents that are not in the equality map.
        /// </summary>
        private FieldZqElement[] responseUnequal;

        /// <summary>
        /// Responses for exponents that are in the equality map.
        /// </summary>
        private FieldZqElement[] responseEqual;

        /// <summary>
        /// Creates an equality proof given the prover parameters.
        /// </summary>
        /// <param name="prover"></param>
        public EqualityProof(ProverEqualityParameters prover)
        {
            ConstructorHelper(prover);
        }

        private void ConstructorHelper(ProverEqualityParameters prover)
        {
            // check prover parameters
            if (!prover.Verify())
            {
                throw new Exception("EqualityProof constructor failed. Invalid prover parameters.");
            }

            try
            {

                // set Group
                this.Group = prover.Group;
                this.IsGroupSerializable = true;

                // generate random w values
                FieldZqElement[] equalW;
                FieldZqElement[] unequalW;
                this.GenerateRandomData(prover, out equalW, out unequalW);

                //compute proof
                this.ComputeB(prover, equalW, unequalW);
                this.ComputeResponses(prover, equalW, unequalW);
            }
            catch (Exception e)
            {
                throw new Exception("Could not create EqualityProof.", e);
            }
        }

        /// <summary>
        /// Verifies this equality proof given the verifier parameters.
        /// </summary>
        /// <param name="verifier"></param>
        /// <returns></returns>
        public bool Verify(VerifierEqualityParameters verifier)
        {
            try
            {
                if (!verifier.Verify())
                {
                    return false;
                }
                FieldZqElement challenge = ComputeChallenge(verifier);

                int unequalWIndex = 0;
                for (int statementIndex = 0; statementIndex < verifier.Statements.Length; ++statementIndex)
                {
                    IStatement statement = verifier.Statements[statementIndex];
                    FieldZqElement[] responses = new FieldZqElement[statement.RepresentationLength];
                    for (int baseIndex = 0; baseIndex < statement.RepresentationLength; ++baseIndex)
                    {
                        DoubleIndex di = new DoubleIndex(statementIndex, baseIndex);
                        int equalWIndex;
                        if (verifier.Map.TryRetrieveIntIndex(di, out equalWIndex))
                        {
                            responses[baseIndex] = responseEqual[equalWIndex];
                        }
                        else
                        {
                            responses[baseIndex] = responseUnequal[unequalWIndex];
                            ++unequalWIndex;
                        }
                    }
                    if (!statement.Verify(b[statementIndex], challenge, responses))
                    {
                        return false;
                    }
                }
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }


        /// <summary>
        /// Computes the challenge used by the verifier to check the proof.
        /// </summary>
        /// <param name="verifier">Verifier parameters</param>
        /// <returns></returns>
        private FieldZqElement ComputeChallenge(VerifierEqualityParameters verifier)
        {
            HashFunction hash = new HashFunction(verifier.HashFunctionName);
            hash.Hash(verifier.HashDigest);
            hash.Hash(this.b);
            return verifier.FieldZq.GetElementFromDigest(hash.Digest);
        }

        /// <summary>
        /// Generates the random w values needed to compute the proof.
        /// </summary>
        /// <param name="prover">Prover parameters</param>
        /// <param name="equalW">Output array to place w values for when exponents are equal</param>
        /// <param name="unequalW">Output array to place w values for when exponents are unequal</param>
        private void GenerateRandomData(ProverEqualityParameters prover, out FieldZqElement[] equalW, out FieldZqElement[] unequalW)
        {
            equalW = prover.FieldZq.GetRandomElements(prover.Map.CountPrettyName, true);
            int lengthUnequalW = 0 - prover.Map.CountEquationAndExponentIndices;
            for (int dlIndex = 0; dlIndex < prover.Witnesses.Length; ++dlIndex)
            {
                lengthUnequalW += prover.Witnesses[dlIndex].RepresentationLength;
            }
            unequalW = prover.FieldZq.GetRandomElements(lengthUnequalW, true);
        }

        /// <summary>
        /// Computes the resonses to the challenge.
        /// </summary>
        /// <param name="prover">Prover parameters.</param>
        /// <param name="equalW">random data for exponents in equality map.</param>
        /// <param name="unequalW">random data for exponents not in equality map.</param>
        private void ComputeResponses(ProverEqualityParameters prover, FieldZqElement[] equalW, FieldZqElement[] unequalW)
        {
            FieldZqElement challenge = ComputeChallenge(prover);
            this.responseEqual = new FieldZqElement[equalW.Length];
            this.responseUnequal = new FieldZqElement[unequalW.Length];

            int unequalWIndex = 0;
            for (int witnessIndex = 0; witnessIndex < prover.Witnesses.Length; ++witnessIndex)
            {
                for (int exponentIndex = 0; exponentIndex < prover.Witnesses[witnessIndex].RepresentationLength; ++exponentIndex)
                {
                    FieldZqElement exponent = prover.Witnesses[witnessIndex].ExponentAtIndex(exponentIndex);

                    DoubleIndex di = new DoubleIndex(witnessIndex, exponentIndex);
                    int equalWIndex;
                    if (prover.Map.TryRetrieveIntIndex(di, out equalWIndex))
                    {
                        FieldZqElement wValue = equalW[equalWIndex];
                        this.responseEqual[equalWIndex] = prover.Witnesses[witnessIndex].ComputeResponse(challenge, wValue, exponentIndex);
                    }
                    else
                    {
                        FieldZqElement wValue = unequalW[unequalWIndex];
                        this.responseUnequal[unequalWIndex] = prover.Witnesses[witnessIndex].ComputeResponse(challenge, wValue, exponentIndex);
                        ++unequalWIndex;
                    }
                }
            }

        }


        /// <summary>
        /// Compute this.b array for the proof.
        /// </summary>
        /// <param name="prover">Prover parameters</param>
        /// <param name="equalW">w values for when exponents are equal</param>
        /// <param name="unequalW">w values for when exponents are unequal</param>
        private void ComputeB(ProverEqualityParameters prover, FieldZqElement[] equalW, FieldZqElement[] unequalW)
        {
            int unequalWIndex = 0;
            this.b = new GroupElement[prover.Witnesses.Length];
            for (int witnessIndex = 0; witnessIndex < this.b.Length; ++witnessIndex)
            {
                FieldZqElement[] randomData = new FieldZqElement[prover.Witnesses[witnessIndex].RepresentationLength];

                for (int exponentIndex = 0; exponentIndex < randomData.Length; ++exponentIndex)
                {
                    DoubleIndex di = new DoubleIndex(witnessIndex, exponentIndex);
                    int equalWIndex;
                    if (prover.Map.TryRetrieveIntIndex(di, out equalWIndex))
                    {
                        randomData[exponentIndex] = equalW[equalWIndex];
                    }
                    else
                    {
                        randomData[exponentIndex] = unequalW[unequalWIndex];
                        ++unequalWIndex;
                    }
                }
                this.b[witnessIndex] = prover.Witnesses[witnessIndex].ComputeCommitment(randomData);
            }
        }


        #region Serialization
        /// <summary>
        /// Serialization of b.
        /// </summary>
        [DataMember(Name = "b", EmitDefaultValue = false, Order = 2)]
        internal string[] _b;

        /// <summary>
        /// Serialization of responseUnequal
        /// </summary>
        [DataMember(Name = "rNeq", EmitDefaultValue = false, Order = 3)]
        internal string[] _responseUnequal;

        /// <summary>
        /// Serialization of responseEqual
        /// </summary>
        [DataMember(Name = "rEq", EmitDefaultValue = false, Order = 4)]
        internal string[] _responseEqual;

        /// <summary>
        /// Serialize b, responseEqual, and responseUnequal
        /// </summary>
        /// <param name="context"></param>
        [OnSerializing]
        internal void OnSerializing(StreamingContext context)
        {
            // serialize b, responseEqual, and responseUnequal
            this._b = CryptoSerializer.SerializeGroupElementArray(b, "b");
            this._responseEqual = CryptoSerializer.SerializeFieldZqElementArray(responseEqual, "responseEqual");
            this._responseUnequal = CryptoSerializer.SerializeFieldZqElementArray(responseUnequal, "responseUnequal");
        }

        /// <summary>
        /// Deserialize b, responseEqual, responseUnequal
        /// </summary>
        public override void FinishDeserializing()
        {
            this.b = CryptoSerializer.DeserializeGroupElementArray(this._b, "b", this.Group);
            this.responseEqual = CryptoSerializer.DeserializeFieldZqElementArray(this._responseEqual, "responseEqual", this.Group);
            this.responseUnequal = CryptoSerializer.DeserializeFieldZqElementArray(this._responseUnequal, "responseUnequal", this.Group);
        }

        #endregion

        #region UProveWrapper

        /// <summary>
        /// Constructor. Creates proof that two UProve tokens have equal attributes.
        /// </summary>
        /// <param name="prover1">Description of token 1.</param>
        /// <param name="attributeIndexForProver1">1-based index for target attribute in token 1.</param>
        /// <param name="prover2">Description of token 2.</param>
        /// <param name="attributeIndexForProver2">1-based index for target attribute in token 2.</param>
        public EqualityProof(ProverPresentationProtocolParameters prover1, int attributeIndexForProver1, ProverPresentationProtocolParameters prover2, int attributeIndexForProver2)
        {
            if (!prover1.IP.Gq.Equals(prover2.IP.Gq))
            {
                throw new ArgumentException("both provers must share the same group");
            }

            // Create OpenUProveTokens
            OpenUProveToken token1 = new OpenUProveToken(prover1);
            OpenUProveToken token2 = new OpenUProveToken(prover2);

            // Create proof
            ProverEqualityParameters eqProver = new ProverEqualityParameters(
                token1, 
                attributeIndexForProver1, 
                token2, 
                attributeIndexForProver2, 
                new CryptoParameters(prover1.IP));
            ConstructorHelper(eqProver);
        }

        public bool Verify(VerifierPresentationProtocolParameters verifier1, int attributeIndexForVerifier1, VerifierPresentationProtocolParameters verifier2, int attributeIndexForVerifier2)
        {
            if (!verifier1.IP.Gq.Equals(verifier2.IP.Gq))
            {
                throw new ArgumentException("both verifiers must share the same group");
            }

            // Create ClosedUProveTokens
            ClosedUProveToken token1 = new ClosedUProveToken(verifier1);
            ClosedUProveToken token2 = new ClosedUProveToken(verifier2);

            // Verify proof
            VerifierEqualityParameters eqVerifier = new VerifierEqualityParameters(
                token1,
                attributeIndexForVerifier1,
                token2,
                attributeIndexForVerifier2,
                new CryptoParameters(verifier1.IP));
            return this.Verify(eqVerifier);
        }



        /// <summary>
        /// Generate a proof that two tokens share an attribute value, without revealing it.
        /// </summary>
        /// <param name="prover1">Equality proof parameters for the first token.</param>
        /// <param name="prover2">Equality proof parameters for the second token.</param>
        /// <returns>An equality proof.</returns>
        public static EqualityProof GenerateUProveEqualityProof(EQProofUProveProverData prover1, EQProofUProveProverData prover2)
        {
            if (!prover1.PPPP.IP.Gq.Equals(prover2.PPPP.IP.Gq))
            {
                throw new ArgumentException("both provers must share the same group");
            }
            // Create PedersenCommitments
            int commitmentIndex1 = ClosedPedersenCommitment.GetCommitmentIndex(prover1.PPPP.Committed, prover1.index);
            PedersenCommitment ped1 = new PedersenCommitment(prover1.PPPP, prover1.PP, prover1.CPV, commitmentIndex1);
            int commitmentIndex2 = ClosedPedersenCommitment.GetCommitmentIndex(prover2.PPPP.Committed, prover2.index);
            PedersenCommitment ped2 = new PedersenCommitment(prover2.PPPP, prover2.PP, prover2.CPV, commitmentIndex2);

            // Create EqualityProof
            CryptoParameters crypto = new CryptoParameters(prover1.PPPP.IP); // Can use prover2.IP
            ProverEqualityParameters equalityProver = new ProverEqualityParameters(ped1, 0, ped2, 0, crypto); // compares committed values in ped1 and ped2
            return new EqualityProof(equalityProver);
        }

        /// <summary>
        /// Verifies a proof that two tokens share an attribute value, without revealing it.
        /// </summary>
        /// <param name="verifier1">Equality proof parameters for the first token.</param>
        /// <param name="verifier2">Equality proof parameters for the second token.</param>
        /// <param name="eQProof">The equality proof to verify.</param>
        /// <exception cref="InvalidUProveArtifactException">Thrown if the proof is invalid.</exception>
        public static void VerifyUProveEqualityProof(EQProofUProveVerifierData verifier1, EQProofUProveVerifierData verifier2, EqualityProof eQProof)
        {
            int commitmentIndex1 = ClosedPedersenCommitment.GetCommitmentIndex(verifier1.VPPP.Committed, verifier1.index);
            int commitmentIndex2 = ClosedPedersenCommitment.GetCommitmentIndex(verifier2.VPPP.Committed, verifier2.index);
            ClosedPedersenCommitment closedPed1 = new ClosedPedersenCommitment(verifier1.VPPP.IP, verifier1.PP, commitmentIndex1);
            ClosedPedersenCommitment closedPed2 = new ClosedPedersenCommitment(verifier2.VPPP.IP, verifier2.PP, commitmentIndex2);
            CryptoParameters crypto = new CryptoParameters(verifier1.VPPP.IP); // Can use prover2.IP
            VerifierEqualityParameters equalityVerifier = new VerifierEqualityParameters(closedPed1, 0, closedPed2, 0, crypto);
            if (!eQProof.Verify(equalityVerifier))
            {
                throw new InvalidUProveArtifactException("invalid equality proof");
            }
        }

        #endregion

    }
}
