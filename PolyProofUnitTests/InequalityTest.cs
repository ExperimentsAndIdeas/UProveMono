using System.Text;
using System.Threading.Tasks;
using UProveCrypto;
using UProveCrypto.Math;
using UProveCrypto.PolyProof;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PolyProofUnitTests
{
    [TestClass]
    public class InequalityTest
    {
        static System.Text.UTF8Encoding _encoding = new System.Text.UTF8Encoding();

        [TestMethod]
        public void InequalityUProveIntegrationTestKV()
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

            // Create inequality proof
            InequalityProof ieqProof = new InequalityProof(
                prover,                             // token
                3,                                  // target attribute index
                _encoding.GetBytes("Professor"));    // bad attribute value

            // ...
            // Send token and inequality proof to verifier
            // ...

            bool success = ieqProof.Verify(
                verifier,                           // verifier token description
                3,                                  // target attribute index
                _encoding.GetBytes("Professor"));   // bad attribute value

            Assert.IsTrue(success, "Could not verify proof.");
        }

        [TestMethod]
        public void InequalityUProveIntegrationTestUKV()
        {
            // Both tokens will hash attributes
            // but example also works if hashAttributes=false
            bool hashAttributes = true;

            // Setting up IssuerParameters for token1
            byte[] uidP1 = new byte[] { 1, 1, 2, 3, 5, 8 };
            byte[] tokenInformation1 = new byte[] { 1, 2, 3, 4, 5, 6, 7 };
            byte[][] attributes1 = new byte[][] 
            { 
                _encoding.GetBytes("Attribute 1"), 
                _encoding.GetBytes("Attribute 2"), 
                _encoding.GetBytes("Teaching Assistant"), // this is the attribute we'll compare
                _encoding.GetBytes("Attribute 4") 
            };

            // Setting up IssuerParameters for token2
            byte[] tokenInformation2 = new byte[] { 12, 13, 14, 15, 0, 10 };
            byte[] uidP2 = new byte[] { 3, 1, 4, 1, 5 };
            byte[][] attributes2 = new byte[][] 
            { 
                _encoding.GetBytes("Student"), // this is the attribute we'll compare
                _encoding.GetBytes("Attribute 2"), 
                _encoding.GetBytes("Attribute 3"), 
                _encoding.GetBytes("Attribute 4") 
            };

            // generate tokens
            ProverPresentationProtocolParameters prover1, prover2;
            VerifierPresentationProtocolParameters verifier1, verifier2;
            StaticHelperClass.GetUProveParameters(hashAttributes, out prover1, out verifier1, tokenInformation1, attributes1, null, uidP1);
            StaticHelperClass.GetUProveParameters(hashAttributes, out prover2, out verifier2, tokenInformation2, attributes2, null, uidP2);

            // Create Inequality Proof
            InequalityProof ieqProof = new InequalityProof(
                prover1,
                3,
                prover2,
                1);

            // .... Send inequality proof to Verifier ....

            // Verify proof
            bool success =  ieqProof.Verify(
                verifier1,
                3,
                verifier2,
                1);

            Assert.IsTrue(success, "Could not verify proof.");
        }


        [TestMethod]
        public void InequalityE2ETest1()
        {
            CryptoParameters crypto = StaticHelperClass.ParameterArray[0];
            PedersenCommitment X = new PedersenCommitment(crypto.FieldZq.GetElement(20), crypto);

            ProverInequalityProofParameters prover = new ProverInequalityProofParameters(X, crypto.FieldZq.GetElement(45), crypto);
            Assert.IsTrue(prover.Verify(), "prover verify");

            InequalityProof proof = new InequalityProof(prover);
            Assert.IsTrue(proof.Verify(prover), "proof verify(prover)");

            VerifierInequalityProofParameters verifier = new VerifierInequalityProofParameters(X.Value, crypto.FieldZq.GetElement(45), crypto);
            Assert.IsTrue(verifier.Verify(), "verifyer.verify()");
            Assert.IsTrue(proof.Verify(verifier), "proof.verify(verifier)");
        }

        [TestMethod]
        public void InequalityE2ETest2()
        {
            CryptoParameters crypto = StaticHelperClass.ParameterArray[0];
            PedersenCommitment X = new PedersenCommitment(crypto.FieldZq.GetElement(20), crypto);
            PedersenCommitment Y = new PedersenCommitment(crypto.FieldZq.GetElement(34), crypto);

            ProverInequalityProofParameters prover = new ProverInequalityProofParameters(X, Y, crypto);
            Assert.IsTrue(prover.Verify(), "prover verify");

            InequalityProof proof = new InequalityProof(prover);
            Assert.IsTrue(proof.Verify(prover), "proof verify(prover)");

            VerifierInequalityProofParameters verifier = new VerifierInequalityProofParameters(X.Value, Y.Value, crypto);
            Assert.IsTrue(verifier.Verify(), "verifyer.verify()");
            Assert.IsTrue(proof.Verify(verifier), "proof.verify(verifier)");
        }

        [TestMethod]
        public void InequalityParamKnownValueTest()
        {
            CryptoParameters crypto = StaticHelperClass.ParameterArray[1];
            FieldZqElement x = crypto.FieldZq.GetRandomElement(false);
            FieldZqElement value = x + crypto.FieldZq.One;

            // inequality does not hold
            PedersenCommitment X = new PedersenCommitment(x, crypto);
            ProverInequalityProofParameters badProver = new ProverInequalityProofParameters(X, x, crypto);
            Assert.IsFalse(badProver.Verify(), "x=value");

            // X uses wrong bases
            PedersenCommitment badX = new PedersenCommitment(crypto.H, crypto.G, x, x, crypto.Group);
            badProver = new ProverInequalityProofParameters(badX, value, crypto);
            Assert.IsFalse(badProver.Verify(), "bad bases in X");

            //good parameters ok
            ProverInequalityProofParameters prover = new ProverInequalityProofParameters(X, value, crypto);
            Assert.IsTrue(prover.Verify(), "prover verify");
            VerifierInequalityProofParameters verifier = new VerifierInequalityProofParameters(X.Value, value, crypto);
            Assert.IsTrue(verifier.Verify(), "verifier ok.");
        }

        [TestMethod]
        public void InequalityParamUnknownValueTest()
        {
            CryptoParameters crypto = StaticHelperClass.ParameterArray[1];
            FieldZqElement x = crypto.FieldZq.GetRandomElement(false);
            FieldZqElement y = x + crypto.FieldZq.One;

            // inequality does not hold
            PedersenCommitment X = new PedersenCommitment(x, crypto);
            PedersenCommitment Y = new PedersenCommitment(y, crypto);
            PedersenCommitment badY = new PedersenCommitment(x, crypto);
            ProverInequalityProofParameters badProver = new ProverInequalityProofParameters(X, badY, crypto);
            Assert.IsFalse(badProver.Verify(), "x=y");

            // X uses wrong bases
            PedersenCommitment badX = new PedersenCommitment(crypto.H, crypto.G, x, x, crypto.Group);
            badProver = new ProverInequalityProofParameters(badX, Y, crypto);
            Assert.IsFalse(badProver.Verify(), "bad bases in X");

            // Y uses wrong bases
            badProver = new ProverInequalityProofParameters(Y, badX, crypto);
            Assert.IsFalse(badProver.Verify(), "bad bases in Y");

            //good parameters ok
            ProverInequalityProofParameters prover = new ProverInequalityProofParameters(X, Y, crypto);
            Assert.IsTrue(prover.Verify(), "prover verify");
            VerifierInequalityProofParameters verifier = new VerifierInequalityProofParameters(X.Value, Y.Value, crypto);
            Assert.IsTrue(verifier.Verify(), "verifier ok.");
        }

        /// <summary>
        /// Tests serialization of prover and verifier parameters. Checks using
        /// all possible parameter sets
        /// </summary>
        [TestMethod]
        public void InequalityParamsSerializationTest()
        {
            for (int i = 0; i < StaticHelperClass.ParameterArray.Length; ++i)
            {
                CryptoParameters crypto = StaticHelperClass.ParameterArray[i];
                FieldZqElement x = crypto.FieldZq.GetElement(1000);
                FieldZqElement y = crypto.FieldZq.GetElement(2000);
                PedersenCommitment X = new PedersenCommitment(x, crypto);
                PedersenCommitment Y = new PedersenCommitment(y, crypto);

                VerifierInequalityProofParameters verifier = new VerifierInequalityProofParameters(X.Value, Y.Value, crypto);
                string json = CryptoSerializer.Serialize<VerifierInequalityProofParameters>(verifier);
                VerifierInequalityProofParameters deserialized = CryptoSerializer.Deserialize<VerifierInequalityProofParameters>(json);
                StaticHelperClass.AssertProofParametersAreEqual(verifier, deserialized, "Verifier X Y");

                verifier = new VerifierInequalityProofParameters(X.Value, y, crypto);
                json = CryptoSerializer.Serialize<VerifierInequalityProofParameters>(verifier);
                deserialized = CryptoSerializer.Deserialize<VerifierInequalityProofParameters>(json);
                StaticHelperClass.AssertProofParametersAreEqual(verifier, deserialized, "Verifier X value");

                ProverInequalityProofParameters prover = new ProverInequalityProofParameters(X, Y, crypto);
                json = CryptoSerializer.Serialize<ProverInequalityProofParameters>(prover);
                ProverInequalityProofParameters dProver = CryptoSerializer.Deserialize<ProverInequalityProofParameters>(json);
                StaticHelperClass.AssertProofParametersAreEqual(dProver, prover, "Prover X Y");

                prover = new ProverInequalityProofParameters(X, y, crypto);
                json = CryptoSerializer.Serialize<ProverInequalityProofParameters>(prover);
                dProver = CryptoSerializer.Deserialize<ProverInequalityProofParameters>(json);
                StaticHelperClass.AssertProofParametersAreEqual(dProver, prover, "Prover X value");
            }
        }

        /// <summary>
        /// Tests proof serialization using all possible parameter sets
        /// </summary>
        [TestMethod]
        public void InequalityProofSerializationTest()
        {
            for (int i = 0; i < StaticHelperClass.ParameterArray.Length; ++i)
            {
                CryptoParameters crypto = StaticHelperClass.ParameterArray[i];
                FieldZqElement x =crypto.FieldZq.GetElement(1000);
                FieldZqElement y = crypto.FieldZq.GetElement(2000);
                PedersenCommitment X = new PedersenCommitment(x, crypto);
                PedersenCommitment Y = new PedersenCommitment(y, crypto);

                 ProverInequalityProofParameters prover = new ProverInequalityProofParameters(X, Y, crypto);
                 InequalityProof proof = new InequalityProof(prover);
                 string json = CryptoSerializer.Serialize<InequalityProof>(proof);
                 InequalityProof deserialized = CryptoSerializer.Deserialize<InequalityProof>(json);
                 Assert.IsTrue(proof.Verify(prover), "Verify proof");
                 Assert.AreEqual(proof.A, deserialized.A, "A");
                 Assert.AreEqual(proof.B, deserialized.B, "B");

                  prover = new ProverInequalityProofParameters(X, y, crypto);
                  proof = new InequalityProof(prover);
                  json = CryptoSerializer.Serialize<InequalityProof>(proof);
                  deserialized = CryptoSerializer.Deserialize<InequalityProof>(json);
                  Assert.IsTrue(proof.Verify(prover), "Verify proof");
                 Assert.AreEqual(proof.A, deserialized.A, "A");
                 Assert.AreEqual(proof.B, deserialized.B, "B");           
            }
        }

        /// <summary>
        /// Computes an inequality proof showing two tokens with different issuer parameters
        /// have two different attributes.
        /// 
        /// Issuers have different UidP and TokenInformation.  Both issuers use the same 
        /// ParameterSet.  Theoretically, it is possible to use different generators G in
        /// the two parameters.  In practice, the UProveCrypto library does not allow
        /// generating new parameter sets with different generators.
        /// </summary>
        [TestMethod]
        public void InequalityTokenIntegrationTest()
        {
            // Both tokens will hash attributes
            // but example also works if hashAttributes=false
            bool hashAttributes = true;

            // Setting up IssuerParameters for token1
            byte[] uidP1 = new byte[] { 1, 1, 2, 3, 5, 8 };
            byte[] tokenInformation1 = new byte[] { 1, 2, 3, 4, 5, 6, 7 };
            byte[][] attributes1 = new byte[][] 
            { 
                _encoding.GetBytes("Attribute 1"), 
                _encoding.GetBytes("Attribute 2"), 
                _encoding.GetBytes("Teaching Assistant"), // this is the attribute we'll compare
                _encoding.GetBytes("Attribute 4") 
            };

            // Setting up IssuerParameters for token2
            byte[] tokenInformation2 = new byte[] { 12, 13, 14, 15, 0, 10 };
            byte[] uidP2 = new byte[] { 3, 1, 4, 1, 5 };
            byte[][] attributes2 = new byte[][] 
            { 
                _encoding.GetBytes("Student"), // this is the attribute we'll compare
                _encoding.GetBytes("Attribute 2"), 
                _encoding.GetBytes("Attribute 3"), 
                _encoding.GetBytes("Attribute 4") 
            };

            // generate tokens
            ProverPresentationProtocolParameters prover1, prover2;
            VerifierPresentationProtocolParameters verifier1, verifier2;
            StaticHelperClass.GetUProveParameters(hashAttributes, out prover1, out verifier1, tokenInformation1, attributes1, null, uidP1);
            StaticHelperClass.GetUProveParameters(hashAttributes, out prover2, out verifier2, tokenInformation2, attributes2, null, uidP2);

            CommitmentPrivateValues cpv1, cpv2;
            PresentationProof proof1 = PresentationProof.Generate(prover1, out cpv1);
            PresentationProof proof2 = PresentationProof.Generate(prover2, out cpv2);

            // Create PedersenCommitments
            // The prover and verifier have a map Committed that contains the relationship between 
            // token attributes and CommitmentPrivateValues.
            int commitmentIndex1 = ClosedPedersenCommitment.GetCommitmentIndex(prover1.Committed, 3); // attribute 3 from prover1
            PedersenCommitment ped1 = new PedersenCommitment(prover1, proof1, cpv1, commitmentIndex1);
            int commitmentIndex2 = ClosedPedersenCommitment.GetCommitmentIndex(prover2.Committed, 1); // attribute 1 from prover2
            PedersenCommitment ped2 = new PedersenCommitment(prover2, proof2, cpv2, commitmentIndex2);

            // Create InequalityProof
            CryptoParameters crypto = new CryptoParameters(prover1.IP); // Can use prover2.IP
            ProverInequalityProofParameters inequalityProver = new ProverInequalityProofParameters(ped1, ped2, crypto); // compares committed values in ped1 and ped2
            InequalityProof ineQProof = new InequalityProof(inequalityProver);

            // Verify InequalityProof
            commitmentIndex1 = ClosedPedersenCommitment.GetCommitmentIndex(verifier1.Committed, 3); // attribute 3 from prover1
            commitmentIndex2 = ClosedPedersenCommitment.GetCommitmentIndex(verifier2.Committed, 1); // attribute 1 from prover2
            ClosedPedersenCommitment closedPed1 = new ClosedPedersenCommitment(verifier1.IP, proof1, commitmentIndex1);
            ClosedPedersenCommitment closedPed2 = new ClosedPedersenCommitment(verifier2.IP, proof2, commitmentIndex2);
            VerifierInequalityProofParameters inequalityVerifier = new VerifierInequalityProofParameters(closedPed1.Value, closedPed2.Value, crypto);
            Assert.IsTrue(ineQProof.Verify(inequalityVerifier));

            // test U-Prove wrapper
            InequalityProof ineQProof2 = InequalityProof.GenerateUProveInequalityProof(
                new EQProofUProveProverData(prover1, cpv1, proof1, 3),
                new EQProofUProveProverData(prover2, cpv2, proof2, 1));
            InequalityProof.VerifyUProveEqualityProof(
                new EQProofUProveVerifierData(verifier1, proof1, 3),
                new EQProofUProveVerifierData(verifier2, proof2, 1),
                ineQProof2);
        }

        /// <summary>
        /// Computes an inequality proof showing a token attribute is not equal to a constant
        /// </summary>
        [TestMethod]
        public void InequalityTokenIntegration2Test()
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

            CommitmentPrivateValues cpv;
            PresentationProof proof = PresentationProof.Generate(prover, out cpv);

            // computing target constant - "Student"
            byte[] targetAttribute = _encoding.GetBytes("Student");
            int targetAttributeIndex = 3 - 1; // We will compare "Student" to the third token attribute.
            FieldZqElement targetValue =  ProtocolHelper.ComputeXi(prover.IP, targetAttributeIndex, targetAttribute); // this is what "Student" would be encoded as if it was the third token attribute

            // Create PedersenCommitments
            // The prover and verifier have a map Committed that contains the relationship between 
            // token attributes and CommitmentPrivateValues.
            int commitmentIndex = ClosedPedersenCommitment.GetCommitmentIndex(prover.Committed, 3); // attribute 3 from prover1
            PedersenCommitment ped = new PedersenCommitment(prover, proof, cpv, commitmentIndex);
            Assert.AreNotEqual(targetValue, ped.CommittedValue, "Committed value is not Student.");

            // Check that "Teaching Assistant" is the commited value of the pedesen commitment.
            FieldZqElement expectedCommittedValue = ProtocolHelper.ComputeXi(prover.IP, targetAttributeIndex, _encoding.GetBytes("Teaching Assistant"));
            Assert.AreEqual(expectedCommittedValue, ped.CommittedValue, "Committed value is Teaching Assistant.");

            // Create InequalityProof
            CryptoParameters crypto = new CryptoParameters(prover.IP); // Can use prover2.IP
            ProverInequalityProofParameters inequalityProver = new ProverInequalityProofParameters(ped, targetValue, crypto); // compares committed values in ped1 and ped2
            InequalityProof ineQproof = new InequalityProof(inequalityProver);

            // Verify InequalityProof
            commitmentIndex = ClosedPedersenCommitment.GetCommitmentIndex(verifier.Committed, 3); // attribute 3 from prover
            ClosedPedersenCommitment closedPed = new ClosedPedersenCommitment(verifier.IP, proof, commitmentIndex);
            VerifierInequalityProofParameters inequalityVerifier = new VerifierInequalityProofParameters(closedPed.Value, targetValue, crypto);
            Assert.IsTrue(ineQproof.Verify(inequalityVerifier));

            // test U-Prove wrapper
            InequalityProof ineQProof2 = InequalityProof.GenerateUProveInequalityProof(
                new EQProofUProveProverData(prover, cpv, proof, 3), targetAttribute);
            InequalityProof.VerifyUProveEqualityProof(
                new EQProofUProveVerifierData(verifier, proof, 3), targetAttribute, ineQProof2);
        }
    }
}
