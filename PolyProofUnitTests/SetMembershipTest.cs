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
    public class SetMembershipTest
    {
        public ProverSetMembershipParameters SMParameters;
        public static CryptoParameters _cryptoParameters = StaticHelperClass.ParameterArray[2];
        private static System.Text.UTF8Encoding _encoding = new System.Text.UTF8Encoding();
        public static FieldZqElement [] ValidDaysOfTheWeek;

        #region Helper Methods

        public FieldZqElement EncodeDay(string day)
        {
            byte[] byteArray = _encoding.GetBytes(day);
            return _cryptoParameters.FieldZq.GetElement(byteArray);

        }

        [ClassInitialize]
        public static void Init(TestContext tc)
        {
                byte[][] days = new byte[][] {
                 _encoding.GetBytes("Sunday"), 
                _encoding.GetBytes("Monday"), 
                _encoding.GetBytes("Tuesday"), 
                _encoding.GetBytes("Wednesday"),
                 _encoding.GetBytes("Thursday"), 
                 _encoding.GetBytes("Friday"), 
                 _encoding.GetBytes("Saturday"), 
                };

            ValidDaysOfTheWeek = new FieldZqElement[days.Length];
            for (int i = 0; i < ValidDaysOfTheWeek.Length; ++i)
            {
                ValidDaysOfTheWeek[i] = _cryptoParameters.FieldZq.GetElement(days[i]);
            }
        }

        public ProverSetMembershipParameters GeneratePSMParameters(int indexOfCommittedValue, int memberSetLength)
        {
            if (indexOfCommittedValue >= memberSetLength)
            {
                throw new ArgumentException("indexOfCommittedValue should be less than memberSetLength");
            }

            FieldZq fieldZq = FieldZq.CreateFieldZq(_cryptoParameters.Group.Q);
            FieldZqElement committedValue = fieldZq.GetRandomElement(true);
            PedersenCommitment ped = new PedersenCommitment(committedValue, _cryptoParameters);
            FieldZqElement[] memberSet = fieldZq.GetRandomElements(memberSetLength, true);
            memberSet[indexOfCommittedValue] = committedValue;

            return new ProverSetMembershipParameters(ped, memberSet, _cryptoParameters);
        }

        public static void AssertCorrectVerifierParameters(
            VerifierSetMembershipParameters verifier,
            CryptoParameters expectedCryptoParameters,
            GroupElement expectedClosedCommitment,
            FieldZqElement[] expectedMemberSet)
        {
            StaticHelperClass.AssertCorrectCryptoParameters(expectedCryptoParameters, verifier);
            Assert.AreEqual(expectedClosedCommitment, verifier.ClosedCommitment, "wrong closed commitment");
            if (expectedMemberSet == null)
            {
                Assert.IsNull(verifier.MemberSet, "Memberset should be null.");
            }
            else
            {
                Assert.AreEqual(expectedMemberSet.Length, verifier.MemberSet.Length, "wrong memberset length.");
                for (int i = 0; i < expectedMemberSet.Length; ++i)
                {
                    Assert.AreEqual(expectedMemberSet[i], verifier.MemberSet[i], "wrong element in memberset.");
                }
            }
        }

        public static void AssertCorrectProverParameters(
            ProverSetMembershipParameters prover,
            CryptoParameters expectedCryptoParameters,
            PedersenCommitment expectedOpenCommitment,
            FieldZqElement [] expectedMemberSet
            )
        {
            // check crypto parameters and everything associated with verifer
            AssertCorrectVerifierParameters(prover, expectedCryptoParameters, expectedOpenCommitment.Value, expectedMemberSet);

            // now check witness
            Assert.AreEqual(expectedOpenCommitment, prover.OpenCommitment, "wrong open commitment.");
            Assert.AreEqual(expectedCryptoParameters.G, prover.OpenCommitment.G, "G value does not match expected crypto parameters.");
            Assert.AreEqual(expectedOpenCommitment.G, prover.OpenCommitment.G, "G value does not match expected Open commitment.");
            Assert.AreEqual(expectedCryptoParameters.H, prover.OpenCommitment.H, "H value does not match expected crypto parameters.");
            Assert.AreEqual(expectedOpenCommitment.H, prover.OpenCommitment.H, "H value does not match expected Open commitment.");

        }

        #endregion

        [TestMethod]
        public void SMUProveIntegrationTest()
        {
            // In this example, the token hashes the attribute
            // but example also works if hashAttributes=false
            bool hashAttributes = true;

            // Setting up attributes for token
            byte[][] tokenAttributes = new byte[][] 
            { 
                _encoding.GetBytes("Attribute 1"), 
                _encoding.GetBytes("Attribute 2"), 
                _encoding.GetBytes("Teaching Assistant"), // this is the attribute we'll compare
                _encoding.GetBytes("Attribute 4") 
            };

            // We will prove that the target token attribute is in this set
            byte[][] setValues = new byte[][] 
            { 
                _encoding.GetBytes("Teaching Assistant"), 
                _encoding.GetBytes("Student"), 
                _encoding.GetBytes("Professor"), // this is the attribute we'll compare
                _encoding.GetBytes("Dean") 
            };

            // generate token
            ProverPresentationProtocolParameters prover;
            VerifierPresentationProtocolParameters verifier;
            StaticHelperClass.GetUProveParameters(hashAttributes, out prover, out verifier, null, tokenAttributes);

            // Create set membership proof
            SetMembershipProof setProof = new SetMembershipProof(
                prover,             // token
                3,                  // target attribute in token
                setValues,          // claim: target attribute is in this set
                null);


            // ...
            // Send token and set membership proof to verifier
            // ...

            bool success = setProof.Verify(
                verifier,                           // verifier token description
                3,                                  // target attribute index
                setValues);                         // check target attribute is in this set

            Assert.IsTrue(success, "Could not verify proof.");
        }

        /// <summary>
        /// Creates a set membership proof in which the prover specifies the random data.
        /// </summary>
        [TestMethod]
        public void SMUProveIntegrationTestWithSMRandom()
        {
            // In this example, the token hashes the attribute
            // but example also works if hashAttributes=false
            bool hashAttributes = true;

            // Setting up attributes for token
            byte[][] tokenAttributes = new byte[][] 
            { 
                _encoding.GetBytes("Attribute 1"), 
                _encoding.GetBytes("Attribute 2"), 
                _encoding.GetBytes("Teaching Assistant"), // this is the attribute we'll compare
                _encoding.GetBytes("Attribute 4") 
            };

            // We will prove that the target token attribute is in this set
            byte[][] setValues = new byte[][] 
            { 
                _encoding.GetBytes("Teaching Assistant"), 
                _encoding.GetBytes("Student"), 
                _encoding.GetBytes("Professor"), // this is the attribute we'll compare
                _encoding.GetBytes("Dean") 
            };

            // generate token
            ProverPresentationProtocolParameters prover;
            VerifierPresentationProtocolParameters verifier;
            StaticHelperClass.GetUProveParameters(hashAttributes, out prover, out verifier, null, tokenAttributes);

            // Get random data from revocation proof
            CryptoParameters crypto = new CryptoParameters(prover.IP);
            SetMembershipProofGenerationRandomData randomData = SetMembershipProofGenerationRandomData.Generate(crypto.FieldZq, setValues.Length - 1);
            
            // Create set membership proof
            SetMembershipProof setProof = new SetMembershipProof(
                prover,             // token
                3,                  // target attribute in token
                setValues,          // claim: target attribute is in this set
                randomData);


            // ...
            // Send token and set membership proof to verifier
            // ...

            bool success = setProof.Verify(
                verifier,                           // verifier token description
                3,                                  // target attribute index
                setValues);                         // check target attribute is in this set

            Assert.IsTrue(success, "Could not verify proof.");
        }

        
        [TestMethod]
        public void SMEndToEndTest()
        {
            // generate prover and verifier parameters
            ProverSetMembershipParameters proverParams = GeneratePSMParameters(0, 10);
            Assert.IsTrue(proverParams.Verify());
            VerifierSetMembershipParameters verifierParams = new VerifierSetMembershipParameters(proverParams.ClosedCommitment, proverParams.MemberSet, proverParams);

            Assert.IsTrue(verifierParams.Verify());
 
            //  create the proof and verify it.
            SetMembershipProof proof = new SetMembershipProof(proverParams);
            Assert.IsTrue(proof.Verify(verifierParams));
            Assert.IsTrue(proof.Verify(proverParams));
        }

        [TestMethod]
        public void SMIndexOfMemberSetE2ETest()
        {
            ProverSetMembershipParameters prover = new ProverSetMembershipParameters(_cryptoParameters);
            for (int day = 0; day < ValidDaysOfTheWeek.Length; ++day)
            {
                prover.setProverParameters(ValidDaysOfTheWeek[day], ValidDaysOfTheWeek);
                SetMembershipProof proof = new SetMembershipProof(prover);
                Assert.IsTrue(proof.Verify(prover), "proof should verify.");
            }

        }

        [TestMethod]
        public void SMGetVerifierParametersTest()
        {
           ProverSetMembershipParameters prover = new ProverSetMembershipParameters(_cryptoParameters);
            prover.setProverParameters(ValidDaysOfTheWeek[1],ValidDaysOfTheWeek);
            Assert.IsTrue(prover.Verify(), "prover parameters should be valid.");

            VerifierSetMembershipParameters verifier = prover.GetVerifierParameters();
            AssertCorrectVerifierParameters(verifier, _cryptoParameters, prover.ClosedCommitment, ValidDaysOfTheWeek);
            Assert.IsNull(verifier.Witnesses, "witnesses should be null.");
        }

        [TestMethod]
        public void SMProverParametersConstructorTest()
        {
            // Test1: compute commitment automatically
            ProverSetMembershipParameters prover = new ProverSetMembershipParameters(_cryptoParameters);
            prover.setProverParameters(ValidDaysOfTheWeek[1], ValidDaysOfTheWeek);
            AssertCorrectProverParameters(prover,
                _cryptoParameters,
                prover.OpenCommitment,  // computed open commitment automatically, so check committed value later
                ValidDaysOfTheWeek);
            Assert.AreEqual(ValidDaysOfTheWeek[1], prover.OpenCommitment.CommittedValue, "wrong committed value.");

            // Test 2: use explicit commitment
            prover = new ProverSetMembershipParameters(_cryptoParameters);
            PedersenCommitment ped = new PedersenCommitment(ValidDaysOfTheWeek[4],_cryptoParameters);
            prover.setProverParameters(ped, ValidDaysOfTheWeek);
            AssertCorrectProverParameters(
                prover,
                _cryptoParameters,
                ped,
                ValidDaysOfTheWeek);

            // Test 3: use constructor to set explicit commitment
            prover = new ProverSetMembershipParameters(ped, ValidDaysOfTheWeek, _cryptoParameters);
            prover.setProverParameters(ped, ValidDaysOfTheWeek);
            AssertCorrectProverParameters(
                prover,
                _cryptoParameters,
                ped,
                ValidDaysOfTheWeek);
        }

        [TestMethod]
        public void SMBadParametersTest()
        {
            // committed value not in memberset
            ProverSetMembershipParameters prover = new ProverSetMembershipParameters(_cryptoParameters);
            prover.setProverParameters(_cryptoParameters.FieldZq.One, ValidDaysOfTheWeek);
            Assert.IsFalse(prover.Verify(), "Verify should fail since committed value not in memberset.");

            // open commitment uses wrong base
            PedersenCommitment ped = new PedersenCommitment(_cryptoParameters.H, _cryptoParameters.G, ValidDaysOfTheWeek[0], ValidDaysOfTheWeek[2],_cryptoParameters.Group);
            prover.setProverParameters(ped, ValidDaysOfTheWeek);
            Assert.IsFalse(prover.Verify(), "Verify should fail since commitment uses wrong bases.");

            // null memberset
            prover.setProverParameters(ValidDaysOfTheWeek[0], null);
            Assert.IsFalse(prover.Verify(), "Verify should fail since memberset is null.");

        }

        [TestMethod]
        public void SMIndexOfCommittedValueTest()
        {
            // place index in set
            ProverSetMembershipParameters prover = new ProverSetMembershipParameters(_cryptoParameters);
            prover.setProverParameters(ValidDaysOfTheWeek[4], ValidDaysOfTheWeek);
            Assert.AreEqual(4, prover.IndexOfCommittedValueInSet, "computed wrong index of committed value.");

            // now index is not in set
            FieldZqElement badday = _cryptoParameters.FieldZq.One;
            prover.setProverParameters(badday, ValidDaysOfTheWeek);
            StaticHelperClass.AssertThrowsException(
                new StaticHelperClass.TryBodyDelegate(() => { int index = prover.IndexOfCommittedValueInSet; }),
                typeof(Exception),
                "Witness not in memberset.");

            // prover parameters not set yet
            prover = new ProverSetMembershipParameters(_cryptoParameters);
            StaticHelperClass.AssertThrowsException(
                new StaticHelperClass.TryBodyDelegate(() => { int index = prover.IndexOfCommittedValueInSet; }),
                typeof(Exception),
                "witness set to null.");
        }

        [TestMethod]
        public void SMIsCommittedValueInSetTest()
        {
            ProverSetMembershipParameters prover = new ProverSetMembershipParameters(_cryptoParameters);
            Assert.IsFalse(prover.IsCommittedValueInSet, "witness set to null so should return false.");

            prover.setProverParameters(prover.FieldZq.One, ValidDaysOfTheWeek);
            Assert.IsFalse(prover.IsCommittedValueInSet, "FieldZq.One is not in MemberSet.");

            prover.setProverParameters(ValidDaysOfTheWeek[4], ValidDaysOfTheWeek);
            Assert.IsTrue(prover.IsCommittedValueInSet, "Committed value is in the set.");

        }

        [TestMethod]
        public void SMGetOpenCommitmentTest()
        {
            ProverSetMembershipParameters prover = new ProverSetMembershipParameters(_cryptoParameters);
            Assert.IsNull(prover.OpenCommitment);

            prover.setProverParameters(ValidDaysOfTheWeek[2], ValidDaysOfTheWeek);
            Assert.IsNotNull(prover.OpenCommitment);
            Assert.AreEqual(ValidDaysOfTheWeek[2], prover.OpenCommitment.CommittedValue);
        }

        /// <summary>
        /// Due to limitations on SetMembershipProof, simulate problems by modifying
        /// parameters for verification.
        /// </summary>
        [TestMethod]
        public void SMBadSetMembershipProofTest()
        {
            ProverSetMembershipParameters prover = new ProverSetMembershipParameters(_cryptoParameters);
            prover.setProverParameters(ValidDaysOfTheWeek[3], ValidDaysOfTheWeek);
            SetMembershipProof proof = new SetMembershipProof(prover);

            // verification fail because verifier parameters don't verify
            VerifierSetMembershipParameters verifier = new VerifierSetMembershipParameters(_cryptoParameters);
            Assert.IsFalse(proof.Verify(verifier), "proof should fail since verifier parameters fail.");

            // verification fail because verifier uses wrong length memberset
            FieldZqElement[] badMemberSet = new FieldZqElement[ValidDaysOfTheWeek.Length + 1];
            for (int i = 0; i < ValidDaysOfTheWeek.Length; ++i)
            {
                badMemberSet[i] = ValidDaysOfTheWeek[i];
            }
            badMemberSet[badMemberSet.Length - 1] = _cryptoParameters.FieldZq.One;
            verifier.setVerifierParameters(prover.ClosedCommitment, badMemberSet);
            Assert.IsFalse(proof.Verify(verifier), "should fail because memberset too long.");

            // verification should fail because memberset too short
            badMemberSet = new FieldZqElement[ValidDaysOfTheWeek.Length - 1];
            for (int i = 0; i < badMemberSet.Length; ++i)
            {
                badMemberSet[i] = ValidDaysOfTheWeek[i];
            }
            verifier.setVerifierParameters(prover.ClosedCommitment, badMemberSet);
            Assert.IsFalse(proof.Verify(verifier), "should fail because memberset too long.");

            // verification should fail because closed commitment is wrong
            verifier.setVerifierParameters(prover.G, prover.MemberSet);
            Assert.IsFalse(proof.Verify(verifier), "should fail because closed commitment is wrong.");

            // verification fail because generators are wrong
            GroupElement [] badGenerators = new GroupElement[2]{_cryptoParameters.H, _cryptoParameters.G};
            CryptoParameters badcrypto = new CryptoParameters(_cryptoParameters.Group, badGenerators, _cryptoParameters.HashFunctionName);
            verifier = new VerifierSetMembershipParameters(badcrypto);
            verifier.setVerifierParameters(prover.ClosedCommitment, prover.MemberSet);
            Assert.IsFalse(proof.Verify(verifier), "should fail because crypto parameters use wrong generators.");

            // verification fail because hash function is wrong
            badcrypto = new CryptoParameters(_cryptoParameters.Group, _cryptoParameters.Generators, "SHA-512");
            verifier = new VerifierSetMembershipParameters(badcrypto);
            verifier.setVerifierParameters(prover.ClosedCommitment, prover.MemberSet);
            Assert.IsFalse(proof.Verify(verifier), "should fail because hash function is wrong.");


        }


        [TestMethod]
        public void SMBadConstructorTest()
        {
            ProverSetMembershipParameters badProver = new ProverSetMembershipParameters(_cryptoParameters);
            StaticHelperClass.AssertThrowsException(
                new StaticHelperClass.TryBodyDelegate(() => { SetMembershipProof proof = new SetMembershipProof(badProver); }),
                typeof(Exception),
                "Constructor SetMembershipProof called with bad prover parameters.");

        }

        [TestMethod]
        public void SMSerializationTest()
        {
            for (int paramIndex = 0; paramIndex < StaticHelperClass.ParameterArray.Length; ++paramIndex)
            {
                // choose parameters
                CryptoParameters crypto = StaticHelperClass.ParameterArray[paramIndex];
                FieldZqElement[] memberSet = crypto.FieldZq.GetRandomElements(10, true);

                // create a set membership proof
                ProverSetMembershipParameters prover = new ProverSetMembershipParameters(crypto);
                prover.setProverParameters(memberSet[3],memberSet);
                SetMembershipProof originalProof = new SetMembershipProof(prover);

                // serialize the proof
                IssuerParameters ip = new IssuerParameters();
                string serializedProof = ip.Serialize<SetMembershipProof>(originalProof);

                // deserialize the proof
                SetMembershipProof deserializedProof = ip.Deserialize<SetMembershipProof>(serializedProof);

                // make sure it verifies
                Assert.IsTrue(deserializedProof.Verify(prover), "deserialized proof does not verify.");

                // serialize the proof again
                string serializedProof2 = ip.Serialize<SetMembershipProof>(deserializedProof);

                // make sure the two serialized proofs are equal
                Assert.AreEqual(serializedProof, serializedProof2, "inconsistent proof serialization.");
            }
        }

        [TestMethod]
        public void SMProverParamSerializationTest()
        {
            // prover test
            ProverSetMembershipParameters prover = new ProverSetMembershipParameters(_cryptoParameters);
            prover.setProverParameters(ValidDaysOfTheWeek[3], ValidDaysOfTheWeek);

            string jsonString = CryptoSerializer.Serialize<ProverSetMembershipParameters>(prover);
            ProverSetMembershipParameters deserializedProver = CryptoSerializer.Deserialize<ProverSetMembershipParameters>(jsonString);
            Assert.AreEqual(prover.Group.GroupName, deserializedProver.Group.GroupName);
            StaticHelperClass.AssertArraysAreEqual(prover.MemberSet, deserializedProver.MemberSet, "MemberSet");
            StaticHelperClass.AssertArraysAreEqual(prover.PublicValues, deserializedProver.PublicValues, "PublicValues");
            StaticHelperClass.AssertArraysAreEqual<DLRepOfGroupElement>(prover.Witnesses, deserializedProver.Witnesses, "Witnesses");
        }

        [TestMethod]
        public void SMVerifierParamSerializationTest()
        {
            // prover test
            VerifierSetMembershipParameters verifier = new VerifierSetMembershipParameters(_cryptoParameters.G,ValidDaysOfTheWeek, _cryptoParameters);

            string jsonString = CryptoSerializer.Serialize<VerifierSetMembershipParameters>(verifier);
            VerifierSetMembershipParameters deserializedVerifier = CryptoSerializer.Deserialize<ProverSetMembershipParameters>(jsonString);
            Assert.AreEqual(verifier.Group.GroupName, deserializedVerifier.Group.GroupName);
            StaticHelperClass.AssertArraysAreEqual(verifier.MemberSet, deserializedVerifier.MemberSet, "MemberSet");
            StaticHelperClass.AssertArraysAreEqual(verifier.PublicValues, deserializedVerifier.PublicValues, "PublicValues");
            StaticHelperClass.AssertArraysAreEqual<DLRepOfGroupElement>(verifier.Witnesses, deserializedVerifier.Witnesses, "Witnesses");
        }


    }
}
