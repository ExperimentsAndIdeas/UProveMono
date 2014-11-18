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
using Microsoft.VisualStudio.TestTools.UnitTesting;
using UProveCrypto;
using UProveCrypto.Math;
using UProveCrypto.PolyProof;

namespace PolyProofUnitTests
{
    [TestClass]
    public class RangeProofTest
    {
        private static System.Text.UTF8Encoding _encoding = new System.Text.UTF8Encoding();
        public CryptoParameters _crypto = StaticHelperClass.ParameterArray[5];
        PedersenCommitment PedN5;
        PedersenCommitment Ped5;
        PedersenCommitment Ped10;
        PedersenCommitment Ped11;

        [TestInitialize]
        public void Initialize()
        {
            this.PedN5 = new PedersenCommitment(_crypto.FieldZq.GetElement(5).Negate(), _crypto);
            this.Ped5 = new PedersenCommitment(_crypto.FieldZq.GetElement(5), _crypto);
            this.Ped10 = new PedersenCommitment(_crypto.FieldZq.GetElement(10), _crypto);
            this.Ped11 = new PedersenCommitment(_crypto.FieldZq.GetElement(11), _crypto);

        }


        [TestMethod]
        public void RP_UProveIntegrationTest()
        {
            // Range proofs REQUIRE unhashed attributes
            bool hashAttributes = false;

            // Range proofs require verifier and prover agreeing on a minimum and maximum year.
            int minYear = 1914;
            int maxYear = DateTime.Today.Year;


            // Setting up attributes for token
            DateTime birthday = new DateTime(1972, 12, 11);
            byte[][] tokenAttributes = new byte[][] 
            { 
                _encoding.GetBytes("Attribute 1"), 
                RangeProofParameterFactory.EncodeYearAndDayAsUProveAttribute(birthday, minYear), // this is the attribute we'll compare
                _encoding.GetBytes("Attribute 3"), 
                _encoding.GetBytes("Attribute 4") 
            };

            // we will prove target token attribute is on or after this date
            // i.e. birthday is after moon landing
            DateTime moonLanding = new DateTime(1969, 7, 20);

            // generate token
            ProverPresentationProtocolParameters prover;
            VerifierPresentationProtocolParameters verifier;
            StaticHelperClass.GetUProveParameters(hashAttributes, out prover, out verifier, null, tokenAttributes);

            // Create range proof
            RangeProof rangeProof = new RangeProof(
                prover,                                                             // token information
                2,                                                                  // token attribute
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,    // attribute >= target date
                moonLanding,                                                        // target date
                minYear,                                                            // min year for attribute
                maxYear);                                                           // max year for attribute     
           
            // ....
            // Send range proof and token to verifier
            // ...

            bool success = rangeProof.Verify(
                verifier,                                                           // token information
                2,                                                                  // token attribute
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,    // attribute >= target date
                moonLanding,                                                        // target date
                minYear,                                                            // min year for attribute
                maxYear);                                                           // max year for attribute
            Assert.IsTrue(success, "Failed to verify range proof.");
        }

        /// <summary>
        /// Range proof example.  Alice will prove she has more money in bank account 1
        /// than in bank account 2.
        /// </summary>
        [TestMethod]
        public void RP_UProveIntegration2TokenTest()
        {
            // Range proofs REQUIRE unhashed attributes
            bool hashAttributes = false;

            // Range proofs require verifier and prover agreeing on a minimum and maximum value.
            // Alice and Bob have a bank balance between $0 and $1,000,000
            int minBalance = 0;
            int maxBalance = 1000000;


            // Setting up IssuerParameters for token1
            // Alice will get a token stating she has $23,000 in bank 1
            byte[] uidP1 = new byte[] { 1, 1, 2, 3, 5, 8 };
            byte[] tokenInformation1 = new byte[] { 1, 2, 3, 4, 5, 6, 7 };
            byte[][] attributes1 = new byte[][] 
            { 
                _encoding.GetBytes("Attribute 1"), 
                _encoding.GetBytes("Attribute 2"),
                RangeProofParameterFactory.EncodeIntAsUProveAttribute(23000), // Alice  has $23,000
                _encoding.GetBytes("Attribute 4") 
            };

            // Setting up IssuerParameters for token2
            // Alice will get a token stating she has $67,000 in bank 2
            byte[] tokenInformation2 = new byte[] { 12, 13, 14, 15, 0, 10 };
            byte[] uidP2 = new byte[] { 3, 1, 4, 1, 5 };
            byte[][] attributes2 = new byte[][] 
            { 
                 RangeProofParameterFactory.EncodeIntAsUProveAttribute(67000), // Alice has $67,000
                _encoding.GetBytes("Attribute 2"), 
                _encoding.GetBytes("Attribute 3"), 
                _encoding.GetBytes("Attribute 4") 
            };

            // generate tokens
            ProverPresentationProtocolParameters prover1, prover2;
            VerifierPresentationProtocolParameters verifier1, verifier2;
            StaticHelperClass.GetUProveParameters(hashAttributes, out prover1, out verifier1, tokenInformation1, attributes1, null, uidP1);
            StaticHelperClass.GetUProveParameters(hashAttributes, out prover2, out verifier2, tokenInformation2, attributes2, null, uidP2);


            // Create range proof
            RangeProof rangeProof = new RangeProof(
                prover1,                                                            // token from bank 1
                3,                                                                  // token attribute
                VerifierRangeProofParameters.ProofType.LESS_THAN,                   // attribute1 < attribute2
                prover2,                                                            // token from bank 2
                1,                                                                  // token attribute
                minBalance,                                                         // min possible balance
                maxBalance);                                                        // max possible balance 

            // ....
            // Send range proof and token to verifier
            // ...

            bool success = rangeProof.Verify(
                verifier1,                                                            // token from bank 1
                3,                                                                    // token attribute
                VerifierRangeProofParameters.ProofType.LESS_THAN,                     // attribute1 < attribute2
                verifier2,                                                            // token from bank 2
                1,                                                                    // token attribute
                minBalance,                                                           // min possible balance
                maxBalance);                                                          // max possible balance 
            Assert.IsTrue(success, "Failed to verify range proof.");
        }



        [TestMethod]
        public void RP_EndToEndInteger()
        {

            // pedA > 0
            ProverRangeProofParameters prover = new ProverRangeProofParameters(
                _crypto,
                this.Ped10,
                VerifierRangeProofParameters.ProofType.GREATER_THAN,
                0,
                0,
                10);
            Assert.IsTrue(prover.Verify());
            RangeProof proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover));
            VerifierRangeProofParameters verifier = new VerifierRangeProofParameters(
                _crypto,
                this.Ped10.Value,
                VerifierRangeProofParameters.ProofType.GREATER_THAN,
                0,
                0,
                10);
            Assert.IsTrue(proof.Verify(verifier));

            // pedA >= 0
            prover = new ProverRangeProofParameters(
                _crypto,
                this.Ped10,
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,
                0,
                0,
                10);
            Assert.IsTrue(prover.Verify());
            proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover));
            verifier = new VerifierRangeProofParameters(
                _crypto,
                this.Ped10.Value,
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,
                0,
                0,
                10);
            Assert.IsTrue(proof.Verify(verifier));

            // pedA >= 10
            prover = new ProverRangeProofParameters(
                _crypto,
                this.Ped10,
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,
                10,
                0,
                10);
            Assert.IsTrue(prover.Verify());
            proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover));
            verifier = new VerifierRangeProofParameters(
                _crypto,
                this.Ped10.Value,
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,
                10,
                0,
                10);
            Assert.IsTrue(proof.Verify(verifier));

            // pedA < 15
            prover = new ProverRangeProofParameters(
                _crypto,
                this.Ped10,
                VerifierRangeProofParameters.ProofType.LESS_THAN,
                15,
                0,
                15);
            Assert.IsTrue(prover.Verify());
            proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover));
            verifier = new VerifierRangeProofParameters(
                _crypto,
                this.Ped10.Value,
                VerifierRangeProofParameters.ProofType.LESS_THAN,
                15,
                0,
                15);
            Assert.IsTrue(proof.Verify(verifier));

            // pedA <= 15
            prover = new ProverRangeProofParameters(
                _crypto,
                this.Ped10,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                15,
                0,
                15);
            Assert.IsTrue(prover.Verify());
            proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover));
            verifier = new VerifierRangeProofParameters(
                _crypto,
                this.Ped10.Value,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                15,
                0,
                15);
            Assert.IsTrue(proof.Verify(verifier));

            // pedA <= 10
            prover = new ProverRangeProofParameters(
                _crypto,
                this.Ped10,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                10,
                0,
                15);
            Assert.IsTrue(prover.Verify());
            proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover));
            verifier = new VerifierRangeProofParameters(
                _crypto,
                this.Ped10.Value,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                10,
                0,
                15);
            Assert.IsTrue(proof.Verify(verifier));



        }


        [TestMethod]
        public void RP_EndToEndCommitment()
        {

            // pedB > pedA
            ProverRangeProofParameters prover = new ProverRangeProofParameters(
                _crypto,
                Ped11,
                VerifierRangeProofParameters.ProofType.GREATER_THAN,
                Ped5,
                0,
                11);
            Assert.IsTrue(prover.Verify(), "pedB > pedA prover parameters invalid.");
            RangeProof proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover), "pedB > pedA proof failed to verify with prover parameters");
            VerifierRangeProofParameters verifier = new VerifierRangeProofParameters(
                _crypto,
                Ped11.Value,
                VerifierRangeProofParameters.ProofType.GREATER_THAN,
                Ped5.Value,
                0,
                11);
            Assert.IsTrue(proof.Verify(verifier), "pedB > pedA proof failed to verify with verifier parameters");

            // pedB >= pedA
            prover = new ProverRangeProofParameters(
                _crypto,
                Ped11,
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,
                Ped5,
                0,
                11);
            Assert.IsTrue(prover.Verify(), "pedB >= pedA prover parameters invalid.");
            proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover), "pedB >= pedA proof.Verify(prover) failed.");
            verifier = new VerifierRangeProofParameters(
                _crypto,
                Ped11.Value,
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,
                Ped5.Value,
                0,
                11);
            Assert.IsTrue(proof.Verify(verifier), "pedB >= pedA proof.Verify(verifier) failed.");

            // pedA >= pedA
            prover = new ProverRangeProofParameters(
                _crypto,
                Ped5,
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,
                Ped5,
                0,
                10);
            Assert.IsTrue(prover.Verify());
            proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover));
            verifier = new VerifierRangeProofParameters(
                _crypto,
                Ped5.Value,
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,
                Ped5.Value,
                0,
                10);
            Assert.IsTrue(proof.Verify(verifier));

            // pedA < pedB
            prover = new ProverRangeProofParameters(
                _crypto,
                Ped5,
                VerifierRangeProofParameters.ProofType.LESS_THAN,
                Ped11,
                0,
                15);
            Assert.IsTrue(prover.Verify());
            proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover));
            verifier = new VerifierRangeProofParameters(
                _crypto,
                Ped5.Value,
                VerifierRangeProofParameters.ProofType.LESS_THAN,
                Ped11.Value,
                0,
                15);
            Assert.IsTrue(proof.Verify(verifier));

            // pedA <= pedA
            prover = new ProverRangeProofParameters(
                _crypto,
                Ped5,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                Ped5,
                0,
                15);
            Assert.IsTrue(prover.Verify());
            proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover));
            verifier = new VerifierRangeProofParameters(
                _crypto,
                Ped5.Value,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                Ped5.Value,
                0,
                15);
            Assert.IsTrue(proof.Verify(verifier));

            // pedA <= pedB
            prover = new ProverRangeProofParameters(
                _crypto,
                Ped5,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                Ped11,
                0,
                15);
            Assert.IsTrue(prover.Verify());
            proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover));
            verifier = new VerifierRangeProofParameters(
                _crypto,
                Ped5.Value,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                Ped11.Value,
                0,
                15);
            Assert.IsTrue(proof.Verify(verifier));

        }

        [TestMethod]
        public void RPNormalizationTest()
        {
            // 10 > 5 in {-10,10}
            ProverRangeProofParameters prover = new ProverRangeProofParameters(
                _crypto,
                Ped10,
                VerifierRangeProofParameters.ProofType.GREATER_THAN,
                Ped5,
                -10,
                10);
            RangeProof proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover), "1 proof.Verify(prover)");
            VerifierRangeProofParameters verifier = new VerifierRangeProofParameters(
                _crypto,
                Ped10.Value,
                VerifierRangeProofParameters.ProofType.GREATER_THAN,
                Ped5.Value,
                -10,
                10);
            Assert.IsTrue(proof.Verify(verifier), "1 proof.Verify(verifier)");

            // -5 <= 5 in {-10,10}
            prover = new ProverRangeProofParameters(
                _crypto,
                PedN5,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                Ped5,
                -10,
                10);
            proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover), "2 proof.Verify(prover)");
            verifier = new VerifierRangeProofParameters(
                _crypto,
                PedN5.Value,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                Ped5.Value,
                -10,
                10);
            Assert.IsTrue(proof.Verify(verifier), "2 proof.Verify(verifier)");


            // 10 <= 11 in {10, 30}
            prover = new ProverRangeProofParameters(
                _crypto,
                Ped10,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                Ped11,
                10,
                30);
            proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover), "3 proof.Verify(prover)");
            verifier = new VerifierRangeProofParameters(
                _crypto,
                Ped10.Value,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                Ped11.Value,
                10,
                30);
            Assert.IsTrue(proof.Verify(verifier), "3 proof.Verify(verifier)");

            // 10 <= 10 in {10, 30}
            prover = new ProverRangeProofParameters(
                _crypto,
                Ped10,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                10,
                10,
                30);
            proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover), "3 proof.Verify(prover)");
            verifier = new VerifierRangeProofParameters(
                _crypto,
                Ped10.Value,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                10,
                10,
                30);
            Assert.IsTrue(proof.Verify(verifier), "3 proof.Verify(verifier)");

        }


        [TestMethod]
        public void RPBigNormalizationTest()
        {
            // 10 > 5 in {-10,10}
            PedersenCommitment ped2036 = new PedersenCommitment(_crypto.FieldZq.GetElement(2036), _crypto);
            PedersenCommitment ped2040 = new PedersenCommitment(_crypto.FieldZq.GetElement(2040), _crypto);
            ProverRangeProofParameters prover = new ProverRangeProofParameters(
                _crypto,
                ped2036,
                VerifierRangeProofParameters.ProofType.LESS_THAN,
                ped2040,
                2025,
                2040);
            RangeProofAccessor proof = new RangeProofAccessor(prover);
            Assert.IsTrue(proof.Proof.Verify(prover), "1 proof.Verify(prover)");
            Assert.AreEqual(4, proof.A.Length, "A.Length");
            Assert.AreEqual(4, proof.B.Length, "B.Length");


        }



        [TestMethod]
        public void RPKnownBTest()
        {
            // create proof that 4>1 in range [0,10]
            PedersenCommitment ped = new PedersenCommitment(_crypto.FieldZq.GetElement(4), _crypto);
            ProverRangeProofParameters prover = new ProverRangeProofParameters(_crypto, ped, VerifierRangeProofParameters.ProofType.GREATER_THAN, 1, 0, 10);
            RangeProofAccessor proof = new RangeProofAccessor(prover);

            // check A is a valid decomposition of 4
            Assert.IsNotNull(proof.A, "A should not be null");
            Assert.AreEqual<int>(4, proof.A.Length);

            // check that VerifierB and proverB are correct
            Assert.IsNull(proof.B);
            DLRepOfGroupElement[] proverB = proof.DefaultOpenDecompositionOfIntegerB(prover);
            Assert.IsNotNull(proof.VerifierB);
            Assert.IsNotNull(proverB);
            Assert.AreEqual<int>(4, proof.VerifierB.Length, "length should be 4");
            Assert.AreEqual<int>(4, proverB.Length, "length should be 4");

            Assert.AreEqual<GroupElement>(prover.G, proof.VerifierB[0], "closedB[0] should be G");
            Assert.AreEqual<GroupElement>(_crypto.Group.Identity, proof.VerifierB[1], "closedB[1] should be 1");
            Assert.AreEqual<GroupElement>(_crypto.Group.Identity, proof.VerifierB[2], "closedB[2] should be 1");
            Assert.AreEqual<GroupElement>(_crypto.Group.Identity, proof.VerifierB[3], "closedB[3] should be 1");

            DLRepOfGroupElement g = new DLRepOfGroupElement(new FieldZqElement[2] { _crypto.FieldZq.One, _crypto.FieldZq.Zero }, _crypto);
            DLRepOfGroupElement one = new DLRepOfGroupElement(new FieldZqElement[2] { _crypto.FieldZq.Zero, _crypto.FieldZq.Zero }, _crypto);
            Assert.AreEqual<DLRepOfGroupElement>(g, proverB[0], "openB[0] should equal G");
            Assert.AreEqual<DLRepOfGroupElement>(one, proverB[1], "openB[1] should equal 1");
            Assert.AreEqual<DLRepOfGroupElement>(one, proverB[2], "openB[2] should equal 1");
            Assert.AreEqual<DLRepOfGroupElement>(one, proverB[3], "openB[3] should equal 1");
        }

        [TestMethod]
        public void RPAdivBTest()
        {
            // create proof that 4>1 in range [0,10]
            PedersenCommitment ped = new PedersenCommitment(_crypto.FieldZq.GetElement(4), _crypto);
            ProverRangeProofParameters prover = new ProverRangeProofParameters(_crypto, ped, VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO, ped, 0, 10);

            DLRepOfGroupElement[] openA = new DLRepOfGroupElement[10];
            DLRepOfGroupElement[] openB = new DLRepOfGroupElement[10];
            GroupElement[] A = new GroupElement[10];
            GroupElement[] B = new GroupElement[10];
            GroupElement baseG = prover.G;
            GroupElement baseH = prover.H;
            for (int i = 0; i < openA.Length; ++i)
            {
                openA[i] = new PedersenCommitment(
                    baseG,
                    baseH,
                    prover.FieldZq.GetElement((uint) (i + 1)),
                    prover.FieldZq.GetElement((uint) (i + 1)),
                    prover.Group);
                A[i] = (baseG * baseH).Exponentiate(prover.FieldZq.GetElement((uint)(i + 1)));
                Assert.AreEqual(A[i], openA[i].Value, "wrong A value.");

                openB[i] = new PedersenCommitment(
                    baseG,
                    baseH,
                    prover.FieldZq.GetElement((uint)i),
                    prover.FieldZq.GetElement((uint)i),
                    prover.Group);
                B[i] = (baseG * baseH).Exponentiate(prover.FieldZq.GetElement((uint)i));
                Assert.AreEqual(B[i], openB[i].Value, "wrong B value.");
            }
            DLRepOfGroupElement[] openAdivB = RangeProofAccessor.ComputeOpenAdivB(prover, openA, openB);
            GroupElement[] closedAdivB = RangeProofAccessor.ComputeClosedAdivB(prover, A, B);
            GroupElement expectedValue = baseG * baseH;
            for (int i = 0; i < openAdivB.Length; ++i)
            {
                Assert.AreEqual(expectedValue, openAdivB[i].Value, "openAdivB has wrong value.");
                Assert.AreEqual(A[i] * B[i].Exponentiate(prover.FieldZq.One.Negate()), closedAdivB[i], "A[i]/B[i] neq closedAdivB[i]");
                Assert.AreEqual(expectedValue, closedAdivB[i], "closedAdivB has wrong value.");
            }
        }

        [TestMethod]
        public void RPXTest()
        {
            // create proof that 4>1 in range [0,10]
            PedersenCommitment ped = new PedersenCommitment(_crypto.FieldZq.GetElement(4), _crypto);
            ProverRangeProofParameters prover = new ProverRangeProofParameters(_crypto, ped, VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO, ped, 0, 10);

            //now create array openAdivB and closedAdivB
            DLRepOfGroupElement[] openAdivB = new DLRepOfGroupElement[10];
            GroupElement[] closedAdivB = new GroupElement[10];
            for (int i = 0; i < openAdivB.Length; ++i)
            {
                openAdivB[i] = new PedersenCommitment(
                    prover.FieldZq.GetElement((uint)(i + 10)),
                    prover);
                closedAdivB[i] = openAdivB[i].Value;
            }

            // compute openX and closedX
            DLRepOfGroupElement[] openX = RangeProofAccessor.ComputeOpenX(prover, openAdivB);
            Assert.IsNull(openX[0], "openX[0] should be null.");
            GroupElement[] X = new GroupElement[10];
            for (int i = 1; i < openX.Length; ++i)
            {
                X[i] = openX[i].Value;
            }
            ClosedDLRepOfGroupElement[] closedX = RangeProofAccessor.ComputeClosedX(prover, X, closedAdivB);
            Assert.IsNull(closedX[0], "closedX[0] should be null.");

            // now run some tests
            Assert.AreEqual(openAdivB.Length, openX.Length, "openX wrong length");
            Assert.AreEqual(openAdivB.Length, closedX.Length, "closedX wrong length");
            for (int i = 1; i < openX.Length; ++i)
            {
                Assert.AreEqual(openAdivB[i].ExponentAtIndex(0), openX[i].ExponentAtIndex(0), "X has wrong exponent");
                Assert.AreEqual(openX[i].BaseAtIndex(0), closedX[i].BaseAtIndex(0), "openX and closedX have different base0");
                Assert.AreEqual(openAdivB[i].Value, closedX[i].BaseAtIndex(0), "openX and closedX have different base0");
                Assert.AreEqual(openX[i].BaseAtIndex(1), closedX[i].BaseAtIndex(1), "openX and closedX have different base1");
            }
        }

        [TestMethod]
        public void RPComputeOpenETest()
        {
            // create proof that 4>1 in range [0,10]
            PedersenCommitment ped = new PedersenCommitment(_crypto.FieldZq.GetElement(4), _crypto);
            ProverRangeProofParameters prover = new ProverRangeProofParameters(_crypto, ped, VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO, ped, 0, 10);

            DLRepOfGroupElement[] AdivB = new DLRepOfGroupElement[5];
            AdivB[0] = new PedersenCommitment(prover.FieldZq.One.Negate(), prover);
            AdivB[1] = new PedersenCommitment(prover.FieldZq.Zero, prover);
            AdivB[2] = new PedersenCommitment(prover.FieldZq.One, prover);
            AdivB[3] = new PedersenCommitment(prover.FieldZq.Zero, prover);
            AdivB[4] = new PedersenCommitment(prover.FieldZq.Zero, prover);

            DLRepOfGroupElement[] X = RangeProofAccessor.ComputeOpenX(prover, AdivB);
            DLRepOfGroupElement[] D = RangeProofAccessor.ComputeOpenD(prover, AdivB);
            DLRepOfGroupElement[] E = RangeProofAccessor.ComputeOpenE(prover, D, X, AdivB);
            Assert.AreEqual(5, X.Length, "X wrong length.");
            Assert.AreEqual(5, D.Length, "D wrong length.");
            Assert.AreEqual(5, E.Length, "E wrong length.");
            Assert.IsNull(E[0], "E[0] should be null.");
            Assert.IsNull(X[0], "X[0] should be null.");
            Assert.AreEqual(AdivB[0], D[0], "D[0] should equal AdivB[0]");
            for (int i = 1; i < E.Length; ++i)
            {
                GroupElement expectedE = D[i].Value * (D[i - 1].Value * AdivB[i].Value).Exponentiate(prover.FieldZq.One.Negate());
                Assert.AreEqual(expectedE, E[i].Value, "Wrong E value.");
            }
        }

        [TestMethod]
        public void RPSerializationTest1()
        {
            // ped10 > 0
            ProverRangeProofParameters prover = new ProverRangeProofParameters(
                _crypto,
                this.Ped10,
                VerifierRangeProofParameters.ProofType.GREATER_THAN,
                0,
                0,
                10);
            Assert.IsTrue(prover.Verify(), "Prover parameters invalid.");
            RangeProof originalProof = new RangeProof(prover);
            Assert.IsTrue(originalProof.Verify(prover), "original proof does not verify.");

            // serialize the proof
            string serializedProof = CryptoSerializer.Serialize<RangeProof>(originalProof);

            // deserialize the proof
            IssuerParameters ip = new IssuerParameters();
            ip.Gq = prover.Group;
            // TODO: switch to using ip-based de-serialization; need to harmonize with U-Prove SDK code
            RangeProof deserializedProof = ip.Deserialize<RangeProof>(serializedProof); // CryptoSerializer.Deserialize<RangeProof>(serializedProof);

            // make sure it verifies
            Assert.IsTrue(deserializedProof.Verify(prover), "deserialized proof does not verify.");

        }

        [TestMethod]
        public void RPSerializationTest2()
        {
            // ped10 >= 0
            ProverRangeProofParameters prover = new ProverRangeProofParameters(
                _crypto,
                this.Ped10,
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,
                10,
                0,
                10);
            Assert.IsTrue(prover.Verify(), "Prover parameters invalid.");
            RangeProof originalProof = new RangeProof(prover);
            Assert.IsTrue(originalProof.Verify(prover), "original proof does not verify.");

            // serialize the proof
            IssuerParameters ip = new IssuerParameters();
            string serializedProof = ip.Serialize<RangeProof>(originalProof);

            // deserialize the proof
            RangeProof deserializedProof = ip.Deserialize<RangeProof>(serializedProof);

            // make sure it verifies
            Assert.IsTrue(deserializedProof.Verify(prover), "deserialized proof does not verify.");

        }

        [TestMethod]
        public void RPParamSerializationTest1()
        {
            ProverRangeProofParameters prover = new ProverRangeProofParameters(
                _crypto,
                Ped10,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                Ped10,
                -3,
                10);
            string jsonProver = CryptoSerializer.Serialize<ProverRangeProofParameters>(prover);
            ProverRangeProofParameters deserializedProver = CryptoSerializer.Deserialize<ProverRangeProofParameters>(jsonProver);
            RangeProof proof = new RangeProof(prover);
            RangeProof Proof2 = new RangeProof(deserializedProver);

            Assert.IsTrue(proof.Verify(deserializedProver), "proof.Verify(deserializedProver)");
            Assert.IsTrue(Proof2.Verify(deserializedProver), "proof2.verify(deserializedProver)");
            Assert.IsTrue(Proof2.Verify(prover), "proof2.verify(prover)");
            StaticHelperClass.AssertArraysAreEqual(prover.Witnesses, deserializedProver.Witnesses, "witnesses");
            Assert.AreEqual(prover.MaxValue, deserializedProver.MaxValue, "MaxValue");
            Assert.AreEqual(prover.MinValue, deserializedProver.MinValue, "MinValue");
            Assert.AreEqual(prover.RangeNormalizationFactor, deserializedProver.RangeNormalizationFactor, "rangeNormalizationFactor");
            Assert.AreEqual(prover.RangeNormalizedClosedIntegerA, deserializedProver.RangeNormalizedClosedIntegerA, "range normalized closed A");
            Assert.AreEqual(prover.RangeNormalizedClosedIntegerB, deserializedProver.RangeNormalizedClosedIntegerB, "range normalized closed B");
            Assert.AreEqual(prover.RangeNormalizedIntegerB, deserializedProver.RangeNormalizedIntegerB, "range normalized integer B");
            Assert.AreEqual(prover.RangeNormalizedOpenIntegerA, deserializedProver.RangeNormalizedOpenIntegerA, "range normalized open integer A");
            Assert.AreEqual(prover.RangeNormalizedOpenIntegerB, deserializedProver.RangeNormalizedOpenIntegerB, "rangeNoramalized Open integer B");
            Assert.AreEqual(prover.RangeProofType, deserializedProver.RangeProofType, "range proof type");
            Assert.AreEqual(prover.ClosedIntegerA, deserializedProver.ClosedIntegerA, "closed integer A");
            Assert.AreEqual(prover.ClosedIntegerB, deserializedProver.ClosedIntegerB, "closed integer B");
        }

        [TestMethod]
        public void RPParamSerializationTest2()
        {
            ProverRangeProofParameters prover = new ProverRangeProofParameters(
                _crypto,
                Ped10,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                10,
                -3,
                10);
            string jsonProver = CryptoSerializer.Serialize<ProverRangeProofParameters>(prover);
            ProverRangeProofParameters deserializedProver = CryptoSerializer.Deserialize<ProverRangeProofParameters>(jsonProver);
            Assert.IsTrue(deserializedProver.Verify());
            RangeProof proof = new RangeProof(prover);
            RangeProof Proof2 = new RangeProof(deserializedProver);

            Assert.IsTrue(proof.Verify(deserializedProver), "proof.Verify(deserializedProver)");
            Assert.IsTrue(Proof2.Verify(deserializedProver), "proof2.verify(deserializedProver)");
            Assert.IsTrue(Proof2.Verify(prover), "proof2.verify(prover)");
            StaticHelperClass.AssertArraysAreEqual(prover.Witnesses, deserializedProver.Witnesses, "witnesses");
            Assert.AreEqual(prover.MaxValue, deserializedProver.MaxValue, "MaxValue");
            Assert.AreEqual(prover.MinValue, deserializedProver.MinValue, "MinValue");
            Assert.AreEqual(prover.RangeNormalizationFactor, deserializedProver.RangeNormalizationFactor, "rangeNormalizationFactor");
            Assert.AreEqual(prover.RangeNormalizedClosedIntegerA, deserializedProver.RangeNormalizedClosedIntegerA, "range normalized closed A");
            Assert.AreEqual(prover.RangeNormalizedClosedIntegerB, deserializedProver.RangeNormalizedClosedIntegerB, "range normalized closed B");
            Assert.AreEqual(prover.RangeNormalizedIntegerB, deserializedProver.RangeNormalizedIntegerB, "range normalized integer B");
            Assert.AreEqual(prover.RangeNormalizedOpenIntegerA, deserializedProver.RangeNormalizedOpenIntegerA, "range normalized open integer A");
            Assert.AreEqual(prover.RangeNormalizedOpenIntegerB, deserializedProver.RangeNormalizedOpenIntegerB, "rangeNoramalized Open integer B");
            Assert.AreEqual(prover.RangeProofType, deserializedProver.RangeProofType, "range proof type");
            Assert.AreEqual(prover.ClosedIntegerA, deserializedProver.ClosedIntegerA, "closed integer A");
            Assert.AreEqual(prover.ClosedIntegerB, deserializedProver.ClosedIntegerB, "closed integer B");
        }

        [TestMethod]
        public void RPParamSerializationTest3()
        {
            ProverRangeProofParameters prover = new ProverRangeProofParameters(
                _crypto,
                Ped10,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                Ped10,
                -3,
                10);
            RangeProof proof = new RangeProof(prover);

            VerifierRangeProofParameters verifier = new VerifierRangeProofParameters(
                _crypto,
                Ped10.Value,
                VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO,
                Ped10.Value,
                -3,
                10);
            string jsonVerifier = CryptoSerializer.Serialize<VerifierRangeProofParameters>(verifier);
            VerifierRangeProofParameters deserializedVerifier = CryptoSerializer.Deserialize<VerifierRangeProofParameters>(jsonVerifier);

            Assert.IsTrue(proof.Verify(deserializedVerifier), "proof.Verify(deserializedProver)");
            StaticHelperClass.AssertArraysAreEqual(verifier.Witnesses, deserializedVerifier.Witnesses, "witnesses");
            Assert.AreEqual(verifier.MaxValue, deserializedVerifier.MaxValue, "MaxValue");
            Assert.AreEqual(verifier.MinValue, deserializedVerifier.MinValue, "MinValue");
            Assert.AreEqual(verifier.RangeNormalizationFactor, deserializedVerifier.RangeNormalizationFactor, "rangeNormalizationFactor");
            Assert.AreEqual(verifier.RangeNormalizedClosedIntegerA, deserializedVerifier.RangeNormalizedClosedIntegerA, "range normalized closed A");
            Assert.AreEqual(verifier.RangeNormalizedClosedIntegerB, deserializedVerifier.RangeNormalizedClosedIntegerB, "range normalized closed B");
            Assert.AreEqual(verifier.RangeNormalizedIntegerB, deserializedVerifier.RangeNormalizedIntegerB, "range normalized integer B");
            Assert.AreEqual(verifier.RangeProofType, deserializedVerifier.RangeProofType, "range proof type");
            Assert.AreEqual(verifier.ClosedIntegerA, deserializedVerifier.ClosedIntegerA, "closed integer A");
            Assert.AreEqual(verifier.ClosedIntegerB, deserializedVerifier.ClosedIntegerB, "closed integer B");
        }



        [TestMethod]
        public void RPBadProverParametersTest()
        {
            // prover out of range.
            ProverRangeProofParameters prover = new ProverRangeProofParameters(
                _crypto,
                Ped10,
                VerifierRangeProofParameters.ProofType.GREATER_THAN,
                Ped5,
                0,
                9);
            Assert.IsFalse(prover.Verify());

            prover = new ProverRangeProofParameters(
                _crypto,
                Ped5,
                VerifierRangeProofParameters.ProofType.LESS_THAN,
                Ped10,
                6,
                20);
            Assert.IsFalse(prover.Verify());

        }

        [TestMethod]
        public void RPFAgeTest1()
        {
            ProverRangeProofParameters prover = RangeProofParameterFactory.GetAgeProverParameters(
                _crypto,
                5,
                VerifierRangeProofParameters.ProofType.LESS_THAN,
                30);
            Assert.IsTrue(prover.Verify());

            RangeProof proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover), "proof.verify(prover)");

            VerifierRangeProofParameters verifier = RangeProofParameterFactory.GetAgeVerifierParameters(
                _crypto,
                prover.ClosedIntegerA,
                VerifierRangeProofParameters.ProofType.LESS_THAN,
                30);
            Assert.IsTrue(verifier.Verify(), "verifier.verify()");
            Assert.IsTrue(proof.Verify(verifier));
        }

        [TestMethod]
        public void RPFAgeTest2()
        {
            ProverRangeProofParameters prover = RangeProofParameterFactory.GetAgeProverParameters(
                _crypto,
                new PedersenCommitment(_crypto.FieldZq.GetElement(21), _crypto),
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,
                21);
            Assert.IsTrue(prover.Verify());

            RangeProof proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover), "proof.verify(prover)");

            VerifierRangeProofParameters verifier = RangeProofParameterFactory.GetAgeVerifierParameters(
                _crypto,
                prover.ClosedIntegerA,
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,
                21);
            Assert.IsTrue(verifier.Verify(), "verifier.verify()");
            Assert.IsTrue(proof.Verify(verifier));
        }

        [TestMethod]
        public void RPFEncodeDateTimeTest()
        {
            int minYear = 1964;
            DateTime oldDate = new DateTime(1964, 1, 1);
            int encodedOldDate = RangeProofParameterFactory.EncodeYearAndDay(oldDate, minYear);
           Assert.AreEqual(1, encodedOldDate, "encoded old date.");

            DateTime recentDate = new DateTime(2010, 12, 31);
            int encodedRecentDate = RangeProofParameterFactory.EncodeYearAndDay(recentDate, minYear);
            Assert.AreEqual(17201, encodedRecentDate, "encoded recent date.");

            DateTime recentDate2 = new DateTime(2011, 1, 1);
            int encodeRecentDate2 = RangeProofParameterFactory.EncodeYearAndDay(recentDate2, minYear);
            Assert.AreEqual(17203, encodeRecentDate2, "encoded recent date2.");

            DateTime futureDate = new DateTime(2020, 5, 25);
            int encodeFutureDate = RangeProofParameterFactory.EncodeYearAndDay(futureDate, minYear);
            Assert.AreEqual(20642, encodeFutureDate, "encoded future date.");

            DateTime leapYear = new DateTime(2012, 12, 31);
            int encodedLeapyear = RangeProofParameterFactory.EncodeYearAndDay(leapYear, minYear);
            Assert.AreEqual(17934, encodedLeapyear, "encoded recent date.");
        }


        [TestMethod]
        public void RPFDateTimeTest1()
        {
            int minYear = 2000;
            int maxYear = 2020;
            DateTime proverDate = new DateTime(2013,2,25);
            PedersenCommitment committedProverDate = new PedersenCommitment(
                _crypto.FieldZq.GetElement((uint)(RangeProofParameterFactory.EncodeYearAndDay(proverDate, minYear))),
                _crypto);
            DateTime verifierTargetDate = new DateTime(2017, 2, 3);

            ProverRangeProofParameters prover = RangeProofParameterFactory.GetDateTimeProverParameters(
                _crypto,
                committedProverDate,
                VerifierRangeProofParameters.ProofType.LESS_THAN,
                verifierTargetDate,
                minYear,
                maxYear);

            Assert.IsTrue(prover.Verify());

            RangeProof proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover), "proof.verify(prover)");

            VerifierRangeProofParameters verifier = RangeProofParameterFactory.GetDateTimeVerifierParameters(
                _crypto,
                prover.ClosedIntegerA,
                VerifierRangeProofParameters.ProofType.LESS_THAN,
                verifierTargetDate,
                minYear,
                maxYear);
            Assert.IsTrue(proof.Verify(verifier));
        }

        [TestMethod]
        public void RPFDateTimeTest2()
        {
            int minYear = 2000;
            int maxYear = 2020;
            DateTime proverDate = new DateTime(2017, 4, 25);
            PedersenCommitment committedProverYear = new PedersenCommitment(
                _crypto.FieldZq.GetElement((uint) proverDate.Year),
                _crypto);
            PedersenCommitment commitedProverDay = new PedersenCommitment(
                _crypto.FieldZq.GetElement((uint) proverDate.DayOfYear),
                _crypto);

            DateTime verifierTargetDate = new DateTime(2017, 2, 3);

            ProverRangeProofParameters prover = RangeProofParameterFactory.GetDateTimeProverParameters(
                _crypto,
                committedProverYear,
                commitedProverDay,
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,
                verifierTargetDate,
                minYear,
                maxYear);

            Assert.IsTrue(prover.Verify(), "prover.verify().");

            RangeProof proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover), "proof.verify(prover)");

            VerifierRangeProofParameters verifier = RangeProofParameterFactory.GetDateTimeVerifierParameters(
                _crypto,
                committedProverYear.Value,
                commitedProverDay.Value,
                VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO,
                verifierTargetDate,
                minYear,
                maxYear);
            Assert.IsTrue(proof.Verify(verifier), "proof.verify(verifier)");
        }

        [TestMethod]
        public void RPFDayHourTest()
        {
            int minDay = 30;
            int maxDay = 166;
            DateTime proverDate = new DateTime(2014, 3, 5, 10, 0, 0);
            PedersenCommitment committedProverDate = new PedersenCommitment(
                _crypto.FieldZq.GetElement((uint) RangeProofParameterFactory.EncodeDayAndHour(proverDate, minDay)),
                _crypto);
            DateTime verifierTargetDate = new DateTime(2014, 4, 5, 1, 0, 0);

            ProverRangeProofParameters prover = RangeProofParameterFactory.GetDayAndHourProverParameters(
                _crypto,
                committedProverDate,
                VerifierRangeProofParameters.ProofType.LESS_THAN,
                verifierTargetDate,
                minDay,
                maxDay);

            Assert.IsTrue(prover.Verify(), "prover.Verify().");

            RangeProof proof = new RangeProof(prover);
            Assert.IsTrue(proof.Verify(prover), "proof.verify(prover)");

            VerifierRangeProofParameters verifier = RangeProofParameterFactory.GetDayAndHourVerifierParameters(
                _crypto,
                prover.ClosedIntegerA,
                VerifierRangeProofParameters.ProofType.LESS_THAN,
                verifierTargetDate,
                minDay,
                maxDay);
            Assert.IsTrue(proof.Verify(verifier), "proof.Verify(verifier).");
        }

        [TestMethod]
        public void RPFEncodeDayHourTest()
        {
            int minDay = 5;
            DateTime date1 = new DateTime(1972, 1, 5, 8, 0, 0);
            int encodedDate1 = RangeProofParameterFactory.EncodeDayAndHour(date1, minDay);
            Assert.AreEqual(8, encodedDate1, "encoded date1.");

            DateTime date2 = new DateTime(1977, 1, 5, 8, 0, 0);
            int encodeDate2 = RangeProofParameterFactory.EncodeDayAndHour(date2, minDay);
            Assert.AreEqual(8, encodeDate2, "encoded date 2.");

            DateTime date3 = new DateTime(2034, 4, 10, 23, 0, 0);
            int encodeDate3 = RangeProofParameterFactory.EncodeDayAndHour(date3, minDay);
            Assert.AreEqual(2303, encodeDate3, "encoded date 3.");

            DateTime date4 = new DateTime(5067, 1, 6, 8, 0, 0);
            int encodeDate4 = RangeProofParameterFactory.EncodeDayAndHour(date4, minDay);
            Assert.AreEqual(32, encodeDate4, "encoded date 4.");

        }

    }

    #region RangeProofAccessor

    public class RangeProofAccessor
    {
        public ProverRangeProofParameters Prover;
        public RangeProof Proof;
        public Group Group;
        public GroupElement[] A;
        public GroupElement[] B;
        public GroupElement[] VerifierB;
        public GroupElement[] D;
        public GroupElement[] X;
        public BitDecompositionProof ProofBitDecompositionOfA;
        public BitDecompositionProof ProofBitDecompositionOfB;
        public EqualityProof FullRangeProof;
        public static PrivateType StaticAccessor;
        public PrivateObject DynamicAccessor;

        static RangeProofAccessor()
        {
            RangeProofAccessor.StaticAccessor = new PrivateType(typeof(RangeProof));
        }

        public RangeProofAccessor(ProverRangeProofParameters prover)
        {
            // create proof
            this.Prover = prover;
            this.Proof = new RangeProof(prover);

            // copy properties
            this.DynamicAccessor = new PrivateObject(this.Proof);
            this.A = (GroupElement[])DynamicAccessor.GetFieldOrProperty("A");
            this.B = (GroupElement[])DynamicAccessor.GetFieldOrProperty("B");
            if (prover.IntegerBIsKnown)
            {
                this.VerifierB = this.DefaultClosedDecompositionOfIntegerB(prover);
            }
            else
            {
                this.VerifierB = this.B;
            }

            this.D = (GroupElement[])DynamicAccessor.GetFieldOrProperty("D");
            this.X = (GroupElement[])DynamicAccessor.GetFieldOrProperty("X");
            this.ProofBitDecompositionOfA = (BitDecompositionProof)DynamicAccessor.GetFieldOrProperty("ProofBitDecompositionOfA");
            this.ProofBitDecompositionOfB = (BitDecompositionProof)DynamicAccessor.GetFieldOrProperty("ProofBitDecompositionOfB");
            this.FullRangeProof = (EqualityProof)DynamicAccessor.GetFieldOrProperty("FullRangeProof");
            this.Group = (Group)DynamicAccessor.GetFieldOrProperty("Group");
        }

        public DLRepOfGroupElement[] DefaultOpenDecompositionOfIntegerB(VerifierRangeProofParameters verifier)
        {
            object[] parameters = new object[1] { verifier };
            return (DLRepOfGroupElement[])RangeProofAccessor.StaticAccessor.InvokeStatic("DefaultOpenDecompositionOfIntegerB", parameters);

        }
        public GroupElement[] DefaultClosedDecompositionOfIntegerB(VerifierRangeProofParameters verifier)
        {
            object[] parameters = new object[1] { verifier };
            return (GroupElement[])RangeProofAccessor.StaticAccessor.InvokeStatic("DefaultClosedDecompositionOfIntegerB", parameters);
        }


        public static GroupElement[] ComputeClosedAdivB(VerifierRangeProofParameters verifier, GroupElement[] a, GroupElement[] b)
        {
            object[] parameters = new object[3] { verifier, a, b };
            return (GroupElement[])RangeProofAccessor.StaticAccessor.InvokeStatic("ComputeClosedAdivB", parameters);
        }

        public static DLRepOfGroupElement[] ComputeOpenAdivB(ProverRangeProofParameters prover, DLRepOfGroupElement[] openA, DLRepOfGroupElement[] openB)
        {
            object[] parameters = new object[3] { prover, openA, openB };
            return (DLRepOfGroupElement[])RangeProofAccessor.StaticAccessor.InvokeStatic("ComputeOpenAdivB", parameters);
        }

        /// <summary>
        /// WARNING: Invoking this method will modify fields A, B, ProofBitDecompsitionOfA, and ProofBitDecompositionOfB. The proof will become permanently corrupted,
        /// as the X, D, and FullRangeProof fields will not be suitably updated.
        /// </summary>
        /// <param name="prover"></param>
        /// <returns></returns>
        public DLRepOfGroupElement[] CreateBitDecompositionProofs(ProverRangeProofParameters prover)
        {
            object[] parameters = new object[1] { prover };
            DLRepOfGroupElement[] openAdivB = (DLRepOfGroupElement[])DynamicAccessor.Invoke("CreateBitDecompositionProofs", parameters);
            this.A = (GroupElement[])DynamicAccessor.GetFieldOrProperty("A");
            this.B = (GroupElement[])DynamicAccessor.GetFieldOrProperty("B");
            if (prover.IntegerBIsKnown)
            {
                this.VerifierB = this.DefaultClosedDecompositionOfIntegerB(prover);
            }
            else
            {
                this.VerifierB = this.B;
            }
            this.ProofBitDecompositionOfA = (BitDecompositionProof)DynamicAccessor.GetFieldOrProperty("ProofBitDecompositionOfA");
            this.ProofBitDecompositionOfB = (BitDecompositionProof)DynamicAccessor.GetFieldOrProperty("ProofBitDecompositionOfB");
            return openAdivB;
        }

        public static DLRepOfGroupElement[] ComputeOpenX(ProverRangeProofParameters prover, DLRepOfGroupElement[] openAdivB)
        {
            object[] parameters = new object[2] { prover, openAdivB };
            return (DLRepOfGroupElement[])StaticAccessor.InvokeStatic("ComputeOpenX", parameters);
        }

        public static ClosedDLRepOfGroupElement[] ComputeClosedX(VerifierRangeProofParameters verifier, GroupElement[] X, GroupElement[] closedAdivB)
        {
            object[] parameters = new object[3] { verifier, X, closedAdivB };
            return (ClosedDLRepOfGroupElement[])StaticAccessor.InvokeStatic("ComputeClosedX", parameters);
        }

        public static DLRepOfGroupElement[] ComputeOpenE(ProverRangeProofParameters prover, DLRepOfGroupElement[] D, DLRepOfGroupElement[] X, DLRepOfGroupElement[] AdivB)
        {
            object[] parameters = new object[4] { prover, D, X, AdivB };
            return (DLRepOfGroupElement[])StaticAccessor.InvokeStatic("ComputeOpenE", parameters);
        }

        public static DLRepOfGroupElement[] ComputeOpenD(ProverRangeProofParameters prover, DLRepOfGroupElement[] AdivB)
        {
            object[] parameters = new object[2] { prover, AdivB };
            return (DLRepOfGroupElement[])StaticAccessor.InvokeStatic("ComputeOpenD", parameters);
        }

    }
#endregion
}
