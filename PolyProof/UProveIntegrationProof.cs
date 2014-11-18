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
using System.Runtime.Serialization;

namespace UProveCrypto.PolyProof
{
    public class UProveIntegrationProof : GroupParameterizedSerializer
    {
        /// <summary>
        /// Proof that an array of Pedersen Commitments are valid commitments to
        /// UProve token attributes.
        /// </summary>
        [DataMember]
        public EqualityProof TokenCommitmentEqualityProof;

        /// <summary>
        /// Value of Pedersen Commitments to token attributes.
        /// </summary>
        public GroupElement[] PedersenCommitmentValues;

        /// <summary>
        /// Generates a list of Pedersen Commitments
        /// </summary>
        /// <param name="prover">Array of tokens</param>
        /// <param name="attributeIndices">target attribute for each token</param>
        /// <param name="commitmentsToAttribute">Pedersen commitment to target attribute in token.  Generated via method
        /// Proof.PedersenCommmitmentsToAttributes</param>
        public UProveIntegrationProof(ProverPresentationProtocolParameters [] prover, int [] attributeIndices, PedersenCommitment [] commitmentsToAttribute)
        {
            if ((prover == null) || (prover.Length == 0))
            {
                throw new ArgumentException("First argument should be an array of at least one element.");
            }

            if (!UProveIntegrationProof.AreTokensCompatible(prover))
            {
                throw new ArgumentException("All tokens must use same group.");
            }


            if((attributeIndices == null) || (attributeIndices.Length != prover.Length))
            {
                    throw new ArgumentNullException("Second argument must be an array of the same length as first argument.");
            }

            if((commitmentsToAttribute == null) || (commitmentsToAttribute.Length != prover.Length))
            {
                    throw new ArgumentNullException("Third argument must be an array of the same length as first argument.");
            }

            // copy Pedersen Commitment values
            this.PedersenCommitmentValues = new GroupElement[prover.Length];
            for (int i = 0; i < PedersenCommitmentValues.Length; ++i)
            {
                this.PedersenCommitmentValues[i] = commitmentsToAttribute[i].Value;
            }

            // Create Equality Proof between Pedersen Commitments and tokens.
            EqualityMap map = new EqualityMap();
            IWitness [] witnesses = new IWitness[prover.Length * 2];
            OpenUProveToken[] tokens = new OpenUProveToken[prover.Length];
            for (int i = 0; i < tokens.Length; ++i)
            {
                // create uprove token and add target attribute to map
                witnesses[2*i] = new OpenUProveToken(prover[i]);
                map.Add(new PrettyName("token", 2 * i), new DoubleIndex(i, attributeIndices[i]));

                // add pedersen commitment to witness list, and add to map
                witnesses[2 * i + 1] = commitmentsToAttribute[i];
                map.Add(new PrettyName("token",2*i+1), new DoubleIndex(i, 0));
            }

            ProverEqualityParameters eqProver = new ProverEqualityParameters(witnesses, map, new CryptoParameters(prover[0].IP));
            this.TokenCommitmentEqualityProof = new EqualityProof(eqProver);
            this.TokenCommitmentEqualityProof.IsGroupSerializable = false;
        }

 

        /// <summary>
        /// Verifies this proof that the committed values are valid Pedersen Commitments to token attributes.
        /// </summary>
        /// <param name="verifier">Array of verifier token parameters.</param>
        /// <param name="attributeIndices">Target attribute in each token.</param>
        /// <param name="committedValues">Array of Pedersen Commitment values.</param>
        /// <returns></returns>
        public bool Verify(VerifierPresentationProtocolParameters [] verifier, int [] attributeIndices)
        {
            if ((verifier == null) || (verifier.Length == 0))
            {
                throw new ArgumentException("First argument should be an array of at least one element.");
            }
            if (!UProveIntegrationProof.AreTokensCompatible(verifier))
            {
                throw new ArgumentException("All tokens must use same group.");
            }

            if ((attributeIndices == null) || (attributeIndices.Length != verifier.Length))
            {
                throw new ArgumentNullException("Second argument must be an array of the same length as first argument.");
            }

            if ((this.PedersenCommitmentValues == null) || (this.PedersenCommitmentValues.Length != verifier.Length))
            {
                throw new ArgumentNullException("Third argument must be an array of the same length as first argument.");
            }

            EqualityMap map = new EqualityMap();
            IStatement[] statements = new IStatement[verifier.Length * 2];
            ClosedUProveToken[] tokens = new ClosedUProveToken[verifier.Length];
            for (int i = 0; i < tokens.Length; ++i)
            {
                // create uprove token and add target attribute to map
                statements[2 * i] = new ClosedUProveToken(verifier[i]);
                map.Add(new PrettyName("token", 2 * i), new DoubleIndex(i, attributeIndices[i]));

                // add pedersen commitment to witness list, and add to map
                statements[2 * i + 1] = new ClosedPedersenCommitment(verifier[i].IP, this.PedersenCommitmentValues[i]);
                map.Add(new PrettyName("token", 2 * i + 1), new DoubleIndex(i, 0));
            }

            VerifierEqualityParameters eqVerifier = new VerifierEqualityParameters(statements, map, new CryptoParameters(verifier[0].IP));
            return this.TokenCommitmentEqualityProof.Verify(eqVerifier);
        }

        /// <summary>
        /// Verifies all tokens are in the same group.
        /// </summary>
        /// <param name="verifiers">Assume called with array of at least one verifier.</param>
        /// <returns></returns>
        private static bool AreTokensCompatible(VerifierPresentationProtocolParameters [] verifiers)
        {
            for (int i = 1; i < verifiers.Length; ++i)
            {
                if (verifiers[i].IP.Gq != verifiers[0].IP.Gq)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Verifies all tokens are in the same group.
        /// </summary>
        /// <param name="provers">Assume called with array of at least one verifier.</param>
        /// <returns></returns>
        private static bool AreTokensCompatible(ProverPresentationProtocolParameters[] provers)
        {
            for (int i = 1; i < provers.Length; ++i)
            {
                if (provers[i].IP.Gq != provers[0].IP.Gq)
                {
                    return false;
                }
            }
            return true;
        }


        #region Serialization
        public override void FinishDeserializing()
        {
            if (this.TokenCommitmentEqualityProof != null)
            {
                this.TokenCommitmentEqualityProof.FinishDeserializing(this.Group);
            }
        }

        #endregion


    }
}
