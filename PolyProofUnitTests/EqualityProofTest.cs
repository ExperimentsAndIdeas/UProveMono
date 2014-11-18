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
    public class EqualityProofTest
    {
        private static System.Text.UTF8Encoding _encoding = new System.Text.UTF8Encoding();
        public static CryptoParameters _parameters = new CryptoParameters(null, null);
        public static CryptoParameters _crypto = StaticHelperClass.ParameterArray[2];
        public static int _paramIndex = 2;

        /// <summary>
        /// Tests UProve Integration constructor and verify method.
        /// </summary>
        [TestMethod]
        public void EQTwoTokenEqualityTest()
        {
            // Both tokens will not hash attributes
            // but example also works if hashAttributes=true
            bool hashAttributes = true;

            // Setting up IssuerParameters for token1
            byte[] uidP1 = new byte[] { 1, 1, 2, 3, 5, 7 };
            byte[] tokenInformation1 = new byte[] { 1, 2, 3, 4, 5, 6, 7 };
            byte[][] attributes1 = new byte[][] 
            { 
                _encoding.GetBytes("Attribute 1"), 
                _encoding.GetBytes("Attribute 2"), 
                _encoding.GetBytes("Target Attribute"), // this is the attribute we'll compare
                _encoding.GetBytes("Attribute 4") 
            };

            // Setting up IssuerParameters for token2
            byte[] tokenInformation2 = new byte[] { 12, 13, 14, 15, 0, 10 };
            byte[] uidP2 = new byte[] { 3, 1, 4, 1, 5 };
            byte[][] attributes2 = new byte[][] 
            { 
                _encoding.GetBytes("Target Attribute"), // this is the attribute we'll compare
                _encoding.GetBytes("Attribute 6"), 
                _encoding.GetBytes("Attribute 7"), 
                _encoding.GetBytes("Attribute 8") 
            };

            // generate tokens
            ProverPresentationProtocolParameters prover1, prover2;
            VerifierPresentationProtocolParameters verifier1, verifier2;
            StaticHelperClass.GetUProveParameters(hashAttributes, out prover1, out verifier1, tokenInformation1, attributes1, null, uidP1);
            StaticHelperClass.GetUProveParameters(hashAttributes, out prover2, out verifier2, tokenInformation2, attributes2, null, uidP2);

            // Create equality proof
            EqualityProof eqProof =  new EqualityProof(
                prover1, // token1
                3,       // target attribute in token1
                prover2, // token2
                1);      // target attribute in token2

            // ....
            // Send data to verifier, including eqProof
            // ....
            // Verify tokens
            // ...


            // Verify equality proof
            bool success = eqProof.Verify(
                verifier1,
                3,
                verifier2,
                1);
            Assert.IsTrue(success, "Could not verify proof.");
        }


        /// <summary>
        /// Computes an equality proof showing two tokens with different issuer parameters
        /// have two identical attributes.  Only one of the attributes is the same.
        /// 
        /// Issuers have different UidP and TokenInformation.  Both issuers use the same 
        /// ParameterSet.  Theoretically, it is possible to use different generators G in
        /// the two parameters.  In practice, the UProveCrypto library does not allow
        /// generating new parameter sets with different generators.
        /// </summary>
        [TestMethod]
        public void EQTokenIntegrationTest()
        {
            // Both tokens will hash attributes
            // but example also works if hashAttributes=false
            bool hashAttributes = true;

            // Setting up IssuerParameters for token1
            byte[] uidP1 = new byte[] { 1, 1, 2, 3, 5, 7 };
            byte[] tokenInformation1 = new byte[] { 1, 2, 3, 4, 5, 6, 7 };
            byte[][] attributes1 = new byte[][] 
            { 
                _encoding.GetBytes("Attribute 1"), 
                _encoding.GetBytes("Attribute 2"), 
                _encoding.GetBytes("Target Attribute"), // this is the attribute we'll compare
                _encoding.GetBytes("Attribute 4") 
            };

            // Setting up IssuerParameters for token2
            byte[] tokenInformation2 = new byte[] { 12, 13, 14, 15, 0, 10 };
            byte[] uidP2 = new byte[] { 3, 1, 4, 1, 5 };
            byte[][] attributes2 = new byte[][] 
            { 
                _encoding.GetBytes("Target Attribute"), // this is the attribute we'll compare
                _encoding.GetBytes("Attribute 6"), 
                _encoding.GetBytes("Attribute 7"), 
                _encoding.GetBytes("Attribute 8") 
            };

            // generate tokens
            ProverPresentationProtocolParameters prover1, prover2;
            VerifierPresentationProtocolParameters verifier1, verifier2;
            StaticHelperClass.GetUProveParameters(hashAttributes, out prover1, out verifier1, tokenInformation1, attributes1, null, uidP1);
            StaticHelperClass.GetUProveParameters(hashAttributes, out prover2, out verifier2, tokenInformation2, attributes2, null, uidP2);

            CommitmentPrivateValues cpv1, cpv2;
            PresentationProof token1 = PresentationProof.Generate(prover1, out cpv1);
            PresentationProof token2 = PresentationProof.Generate(prover2, out cpv2);

            // Create PedersenCommitments
            // The prover and verifier have a map Committed that contains the relationship between 
            // token attributes and CommitmentPrivateValues.
            int commitmentIndex1 = ClosedPedersenCommitment.GetCommitmentIndex(prover1.Committed, 3); // attribute 3 from prover1
            PedersenCommitment ped1 = new PedersenCommitment(prover1, token1, cpv1, commitmentIndex1);
            int commitmentIndex2 = ClosedPedersenCommitment.GetCommitmentIndex(prover2.Committed, 1); // attribute 1 from prover2
            PedersenCommitment ped2 = new PedersenCommitment(prover2, token2, cpv2, commitmentIndex2);

            // Create EqualityProof
            CryptoParameters crypto = new CryptoParameters(prover1.IP); // Can use prover2.IP
            ProverEqualityParameters equalityProver = new ProverEqualityParameters(ped1, 0, ped2, 0, crypto); // compares committed values in ped1 and ped2
            EqualityProof proof = new EqualityProof(equalityProver);

            // Verify EqualityProof
            commitmentIndex1 = ClosedPedersenCommitment.GetCommitmentIndex(verifier1.Committed, 3); // attribute 3 from prover1
            commitmentIndex2 = ClosedPedersenCommitment.GetCommitmentIndex(verifier2.Committed, 1); // attribute 1 from prover2
            ClosedPedersenCommitment closedPed1 = new ClosedPedersenCommitment(verifier1.IP, token1, commitmentIndex1);
            ClosedPedersenCommitment closedPed2 = new ClosedPedersenCommitment(verifier2.IP, token2, commitmentIndex2);
            VerifierEqualityParameters equalityVerifier = new VerifierEqualityParameters(closedPed1, 0, closedPed2, 0, crypto);
            Assert.IsTrue(proof.Verify(equalityVerifier));
        }


        [TestMethod]
        public void EQTokenAndDLTest()
        {
            // In this example, the token hashes the attribute
            // but example also works if hashAttributes=false
            bool hashAttributes = true;

            // Setting up attributes for token
            byte[][] attributes = new byte[][] 
            { 
                _encoding.GetBytes("Attribute 1"), 
                _encoding.GetBytes("Attribute 2"), 
                _encoding.GetBytes("Teaching Assistant"), // this is the attribute we'll compare
                _encoding.GetBytes("Attribute 4") 
            };

            // generate token
            ProverPresentationProtocolParameters prover;
            VerifierPresentationProtocolParameters verifier;
            StaticHelperClass.GetUProveParameters(hashAttributes, out prover, out verifier, null, attributes);
            OpenUProveToken token = new OpenUProveToken(prover);
            Assert.IsTrue(token.Validate(null), "validate token.");


             // generate pedersen commitment to Teaching Assistant
            PedersenCommitment ped = new PedersenCommitment(prover.IP, 3, _encoding.GetBytes("Teaching Assistant"));

            // Verify they are equal
            Assert.AreEqual(token.AttributeXI(3), ped.CommittedValue, "Token and PedersenCommitment different.");
 
            // Create a proof that the 3rd attribute in token is equal to the committed value in ped.
            ProverEqualityParameters eqProver = new ProverEqualityParameters(
                token, // token
                3,     // 3rd attribute is the 3rd exponent
                ped,   // pedersen commitment
                0,     // committed value is the 0th exponent
                new CryptoParameters(prover.IP));
            EqualityProof proof = new EqualityProof(eqProver);

            // Verify proof
            ClosedUProveToken closedToken = new ClosedUProveToken(verifier);
            Assert.IsTrue(closedToken.AreBasesEqual(token), "token bases.");
            IStatement closedPed = ped.GetStatement();
            Assert.IsTrue(closedPed.AreBasesEqual(ped), "token bases.");
            VerifierEqualityParameters eqVerifier = new VerifierEqualityParameters(
                closedToken, // verifier token information
                3,           // 3rd attribute is the 3nd exponent
                closedPed,   // verifier information about ped
                0,           // committed value is the 0th exponent
                new CryptoParameters(prover.IP));
            Assert.IsTrue(proof.Verify(eqVerifier));
        }

        [TestMethod]
        public void EQEndToEndTest1()
        {
            // create two pedersen commitments to 1
            DLRepOfGroupElement[] dlarray = new DLRepOfGroupElement[2]
            {
                new PedersenCommitment(_parameters.FieldZq.One, _parameters),
                new PedersenCommitment(_parameters.FieldZq.One, _parameters)
            };
            PrettyName alpha = new PrettyName("alpha", 0);
            DoubleIndex d1 = new DoubleIndex(0, 0); // dlarray[0].BaseAtIndex(0)
            DoubleIndex d2 = new DoubleIndex(1, 0); // dlarray[1].BaseAtIndex(0)
            EqualityMap map = new EqualityMap();
            map.Add(alpha, d1);
            map.Add(alpha, d2);

            int index;
            Assert.IsTrue(map.TryRetrieveIntIndex(d1, out index));
            Assert.AreEqual(0, index);
            Assert.IsTrue(map.TryRetrieveIntIndex(d2, out index));
            Assert.AreEqual(0, index);
            

            ProverEqualityParameters peParameters = new ProverEqualityParameters(
                dlarray,
                map,
                _parameters);
            EqualityProof proof = new EqualityProof(peParameters);
            Assert.IsTrue(proof.Verify(peParameters));
        }

        /// <summary>
        /// Test what happens when equality map contains array of unrelated equations
        /// </summary>
        [TestMethod]
        public void EQEndToEndTest2()
        {
            int length=20;
            FieldZqElement[] committedValues = _crypto.FieldZq.GetRandomElements(length, true);
            FieldZqElement[] openings = _crypto.FieldZq.GetRandomElements(length, true);
            PedersenCommitment[] ped = PedersenCommitment.GetCommitments(_crypto, committedValues, openings);

            EqualityMap map = new EqualityMap();
            for (int i = 0; i < length; ++i)
            {
                map.Add(
                    new PrettyName("chi", i),
                    new DoubleIndex(i, 0)
                    );
            }

            ProverEqualityParameters prover = new ProverEqualityParameters(ped, map, _crypto);
            Assert.IsTrue(prover.Verify());

            EqualityProof proof = new EqualityProof(prover);
            Assert.IsTrue(proof.Verify(prover));
        }

        /// <summary>
        /// Test what happens when equality map contains two arrays of related equations
        /// </summary>
        [TestMethod]
        public void EQEndToEndTest3()
        {
            int length = 20;
            FieldZqElement[] committedValues = _crypto.FieldZq.GetRandomElements(length, true);
            FieldZqElement[] openings1 = _crypto.FieldZq.GetRandomElements(length, true);
            FieldZqElement[] openings2 = _crypto.FieldZq.GetRandomElements(length, true);
            PedersenCommitment[] ped1 = PedersenCommitment.GetCommitments(_crypto, committedValues, openings1);
            PedersenCommitment[] ped2 = PedersenCommitment.GetCommitments(_crypto, committedValues, openings2);

            // combine all commitments into allPed
            PedersenCommitment[] allPed = new PedersenCommitment[2 * length];
            for (int i = 0; i < length; ++i)
            {
                allPed[i] = ped1[i];
                allPed[i + length] = ped2[i];
            }

            // create equality map
            EqualityMap map = new EqualityMap();
            for (int i = 0; i < length; ++i)
            {
                map.Add(
                    new PrettyName("chi", i),
                    new DoubleIndex(i, 0)
                );

                map.Add(
                    new PrettyName("chi", i),
                    new DoubleIndex(length+ i, 0)
                );
            }

            ProverEqualityParameters prover = new ProverEqualityParameters(allPed, map, _crypto);
            Assert.IsTrue(prover.Verify());

            EqualityProof proof = new EqualityProof(prover);
            Assert.IsTrue(proof.Verify(prover));
        }

        [TestMethod]
        public void EQSerializationTest()
        {
           int length = 20;
            int fullLength = length * 2;
            DLRepOfGroupElement [] openEquations = StaticHelperClass.GenerateRandomDLRepOfGroupElementArray(length, 5, _paramIndex);
            DLRepOfGroupElement [] allOpenEquations = new DLRepOfGroupElement[fullLength];
            for(int i=0; i<openEquations.Length; ++i)
            {
                allOpenEquations[i] = openEquations[i];
                allOpenEquations[i+length] = openEquations[i];
            }

            // create equality map
            EqualityMap map = new EqualityMap();
            for (int i = 0; i < length; ++i)
            {
                map.Add(
                    new PrettyName("chi", i),
                    new DoubleIndex(i, 0)
                );

                map.Add(
                    new PrettyName("chi", i),
                    new DoubleIndex(length+ i, 0)
                );
                map.Add(
                    new PrettyName("delta", i),
                    new DoubleIndex(i, 4)
                    );
                map.Add(
                    new PrettyName("delta", i),
                    new DoubleIndex(length+i, 4)
                    );

                map.Add(
                    new PrettyName("beta", i),
                    new DoubleIndex(i, 2)
                );
                map.Add(
                    new PrettyName("beta", i),
                    new DoubleIndex(length + i, 2)
                );
            }

            // create proverParameters
            ProverEqualityParameters prover = new ProverEqualityParameters(allOpenEquations, map, _crypto);
            string jsonProver = CryptoSerializer.Serialize<ProverEqualityParameters>(prover);
            ProverEqualityParameters deserializedProver = CryptoSerializer.Deserialize<ProverEqualityParameters>(jsonProver);
            StaticHelperClass.AssertArraysAreEqual(prover.Statements, deserializedProver.Statements, "Prover closedDLEquations");
            StaticHelperClass.AssertArraysAreEqual(prover.Witnesses, deserializedProver.Witnesses, "Prover Witnesses");
            StaticHelperClass.AssertArraysAreEqual(prover.HashDigest, deserializedProver.HashDigest, "equality map hash.");
            StaticHelperClass.AssertArraysAreEqual(prover.Generators, deserializedProver.Generators, "prover Generators");
            for(int i=0; i<prover.Statements.Length; ++i)
            {
               Assert.IsTrue(prover.Statements[i].AreBasesEqual(deserializedProver.Statements[i]), "unequal bases for equation " + i);
            }
            Assert.IsTrue(deserializedProver.Verify(), "deserializedProver.Verify()");

            // create proof
            EqualityProof proof = new EqualityProof(prover);
            Assert.IsTrue(proof.Verify(prover), "Proof.Verify(prover)");
            Assert.IsTrue(proof.Verify(deserializedProver), "proof.Verify(deserializedProver)");
            string jsonProof = CryptoSerializer.Serialize<EqualityProof>(proof);
            // TODO: switch to using ip-based de-serialization; need to harmonize with U-Prove SDK code
            IssuerParameters ip = new IssuerParameters();
            ip.Gq = prover.Group;
            EqualityProof deserializedProof = ip.Deserialize<EqualityProof>(jsonProof); // CryptoSerializer.Deserialize<EqualityProof>(jsonProof);
            Assert.IsTrue(deserializedProof.Verify(prover), "deserializedProof.Verify(prover)");
            Assert.IsTrue(deserializedProof.Verify(deserializedProver), "deserializedProof.Verify(deserializedProver)");
            
            // create verifier
            IStatement[] closedEquations = new ClosedDLRepOfGroupElement[allOpenEquations.Length];
            for (int i = 0; i < allOpenEquations.Length; ++i)
            {
                closedEquations[i] = allOpenEquations[i].GetStatement();
            }
            VerifierEqualityParameters verifier = new VerifierEqualityParameters(closedEquations, map, _crypto);
            Assert.IsTrue(proof.Verify(verifier), "Proof.Verify(verifier)");
            Assert.IsTrue(deserializedProof.Verify(verifier), "proof.Verify(verifier)");
            string jsonVerifier = CryptoSerializer.Serialize<VerifierEqualityParameters>(verifier);
            VerifierEqualityParameters deserializedVerifier = CryptoSerializer.Deserialize<VerifierEqualityParameters>(jsonVerifier);
            Assert.IsTrue(deserializedVerifier.Verify(), "deserializedVerifier.Verify()");
            Assert.IsTrue(deserializedProof.Verify(deserializedVerifier), "deserializedProof.Verify(deserializedVerifier)");

            // create proof from deserialized prover
            EqualityProof newProof = new EqualityProof(deserializedProver);
            Assert.IsTrue(newProof.Verify(deserializedProver), "newProof.verify(deserializedProver)");
            Assert.IsTrue(newProof.Verify(verifier), "newProof.Verify(verifier)");
        }


        [TestMethod]
        public void EQBadVerifierParametersTest()
        {
            int length = 20;
            int fullLength = length * 2;
            DLRepOfGroupElement[] openEquations = StaticHelperClass.GenerateRandomDLRepOfGroupElementArray(length, 5, _paramIndex);
            DLRepOfGroupElement[] allOpenEquations = new DLRepOfGroupElement[fullLength];
            for (int i = 0; i < openEquations.Length; ++i)
            {
                allOpenEquations[i] = openEquations[i];
                allOpenEquations[i + length] = openEquations[i];
            }

            // create equality map
            EqualityMap map = new EqualityMap();
            for (int i = 0; i < length; ++i)
            {
                map.Add(
                    new PrettyName("chi", i),
                    new DoubleIndex(i, 0)
                );

                map.Add(
                    new PrettyName("chi", i),
                    new DoubleIndex(length + i, 0)
                );
                map.Add(
                    new PrettyName("delta", i),
                    new DoubleIndex(i, 19)
                    );
                map.Add(
                    new PrettyName("delta", i),
                    new DoubleIndex(length + i, 19)
                    );

                map.Add(
                    new PrettyName("beta", i),
                    new DoubleIndex(i, 5)
                );
                map.Add(
                    new PrettyName("beta", i),
                    new DoubleIndex(length + i, 5)
                );
            }
        }

 

    }
}
