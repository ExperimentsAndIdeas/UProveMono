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
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using UProveCrypto;
using UProveCrypto.Math;
using UProveCrypto.PolyProof;
using System.Collections;


namespace PolyProofUnitTests
{
    /// <summary>
    /// Summary description for BitDecompositionTest
    /// </summary>
    [TestClass]
    public class BitDecompositionTest
    {
        public BitDecompositionTest()
        {
            //
            // TODO: Add constructor logic here
            //
        }

        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        //
        // You can use the following additional attributes as you write your tests:
        //
        // Use ClassInitialize to run code before running the first test in the class
        // [ClassInitialize()]
        // public static void MyClassInitialize(TestContext testContext) { }
        //
        // Use ClassCleanup to run code after all tests in a class have run
        // [ClassCleanup()]
        // public static void MyClassCleanup() { }
        //
        // Use TestInitialize to run code before running each test 
        // [TestInitialize()]
        // public void MyTestInitialize() { }
        //
        // Use TestCleanup to run code after each test has run
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        //
        #endregion


        // will perform tests using several different parameter sets
        private static CryptoParameters [] _parameters;

        [ClassInitialize]
        public static void Init(TestContext context)
        {
            // create parameter sets
            _parameters = new CryptoParameters[6];
            _parameters[0] =  new CryptoParameters(ECParameterSets.ParamSet_EC_P256_V1, null);
            _parameters[1] =  new CryptoParameters(ECParameterSets.ParamSet_EC_P384_V1, null);
            _parameters[2] =  new CryptoParameters(ECParameterSets.ParamSet_EC_P521_V1, null);
            _parameters[3] =  new CryptoParameters(SubgroupParameterSets.ParamSetL1024N160V1, null);
            _parameters[4] =  new CryptoParameters(SubgroupParameterSets.ParamSetL2048N256V1, null);
            _parameters[5] = new CryptoParameters(SubgroupParameterSets.ParamSetL3072N256V1, null);
            //            _parameters[6] = new CryptoParameters(ECParameterSets.ParamSet_EC_BN254_V1, null);

        }

        [TestMethod]
        public void BDConstructorCastTest()
        {
            FieldZqElement bigNum = _parameters[0].FieldZq.GetElement(129);
            PedersenCommitment bigNumCommit = new PedersenCommitment(bigNum, _parameters[0]);
            int decompositionLength = 15;


            ProverBitDecompositionParameters proverParams = new ProverBitDecompositionParameters(
                bigNumCommit,
                decompositionLength,
                _parameters[0]);

            Assert.IsInstanceOfType(proverParams.OpenCommitment, typeof(PedersenCommitment), "OpenCommitment wrong type");
            Assert.IsInstanceOfType(proverParams.ClosedCommitment, typeof(GroupElement), "ClosedCommitment wrong type");

            Assert.IsInstanceOfType(proverParams.OpenCommitment, typeof(PedersenCommitment), "OpenCommitment wrong type");
            Assert.IsInstanceOfType(proverParams.ClosedCommitment, typeof(GroupElement), "ClosedCommitment wrong type");
            for (int i = 0; i < proverParams.DecompositionLength; ++i)
            {
                Assert.IsInstanceOfType(proverParams.OpenBitDecomposition(i), typeof(PedersenCommitment), "OpenBitDecomposition(i) returned wrong type");
                Assert.IsInstanceOfType(proverParams.ClosedBitDecomposition(i), typeof(GroupElement), "ClosedBitDecomposition returned wrong type");
            }


        }



        [TestMethod]
        public void BDEndToEnd()
        {
            FieldZqElement bigNum = _parameters[0].FieldZq.GetElement(2056);
            PedersenCommitment bigNumCommit = new PedersenCommitment(bigNum,_parameters[0]);
            int decompositionLength = 15;


            ProverBitDecompositionParameters proverParams = new ProverBitDecompositionParameters(
                bigNumCommit,
                decompositionLength,
                _parameters[0]);

            BitDecompositionProof proof = new BitDecompositionProof(proverParams);
            Assert.IsTrue(proof.Verify(proverParams), "could not verify proof with prover params");

            VerifierBitDecompositionParameters verifierParams = new VerifierBitDecompositionParameters(
                proverParams.ClosedCommitment,
                proverParams.ClosedBitDecomposition(),
                proverParams);
            Assert.IsTrue(proof.Verify(verifierParams), "could not verify proof with verifier parameters");
        }


        [TestMethod]
        public void BDDecompositionTest()
        {
            FieldZqElement zero;
            FieldZqElement one;
            FieldZqElement two;
            FieldZqElement five;
            FieldZqElement ten;
            BitArray dec;
            FieldZqElement recompose;
            for (int paramIndex = 0; paramIndex < _parameters.Length; ++paramIndex)
            {
                FieldZq field = _parameters[paramIndex].FieldZq;
                zero = field.Zero;
                one = field.One;
                two = field.GetElement(2);
                five = field.GetElement(5);
                ten = field.GetElement(10);

                 dec = VerifierBitDecompositionParameters.GetBitDecomposition(one, 10, field);
                 recompose = VerifierBitDecompositionParameters.GetBitComposition(dec, field);
                Assert.AreEqual(one, recompose);
                Assert.AreEqual(true, dec.Get(0), "first bit should be one");
                Assert.AreEqual(false, dec.Get(1), "second  bit should be zero");
                Assert.AreEqual(10, dec.Length, "decomposition length should be 10");

                dec = VerifierBitDecompositionParameters.GetBitDecomposition(two, 20, field);
                recompose = VerifierBitDecompositionParameters.GetBitComposition(dec, field);
                Assert.AreEqual(20, dec.Length, "decomposition length should be 10");
                Assert.AreEqual(two, recompose);
                Assert.AreEqual(false, dec[0], "first bit is 0");
                Assert.AreEqual(true, dec[1], "second bit is 1");
                Assert.AreEqual(false, dec[2], "third bit is 0");
                Assert.AreEqual(false, dec[19], "last bit is 0");

                dec = VerifierBitDecompositionParameters.GetBitDecomposition(five, 30, field);
                recompose = VerifierBitDecompositionParameters.GetBitComposition(dec, field);
                Assert.AreEqual(30, dec.Length, "decomposition length should be 30");
                Assert.AreEqual(five, recompose);
                Assert.AreEqual(true, dec[0], "first bit is 1");
                Assert.AreEqual(false, dec[1], "second bit is 0");
                Assert.AreEqual(true, dec[2], "third bit is 1");
                Assert.AreEqual(false, dec[3], "fourth bit is 0");
                Assert.AreEqual(false, dec[4], "fifth bit is 0");
                Assert.AreEqual(false, dec[29], "last bit is 0");

                dec = VerifierBitDecompositionParameters.GetBitDecomposition(ten, 30, field);
                recompose = VerifierBitDecompositionParameters.GetBitComposition(dec, field);
                Assert.AreEqual(30, dec.Length, "decomposition length should be 30");
                Assert.AreEqual(ten, recompose);
                Assert.AreEqual(false, dec[0], "first bit is 0");
                Assert.AreEqual(true, dec[1], "second bit is 1");
                Assert.AreEqual(false, dec[2], "third bit is 0");
                Assert.AreEqual(true, dec[3], "fourth bit is 1");
                Assert.AreEqual(false, dec[4], "fifth bit is 0");
                Assert.AreEqual(false, dec[29], "last bit is 0");


                FieldZqElement random = field.GetRandomElement(true);
                dec = VerifierBitDecompositionParameters.GetBitDecomposition(random, 0, field);
                recompose = VerifierBitDecompositionParameters.GetBitComposition(dec, field);
                Assert.AreEqual(random, recompose, "recomposition failed");
            }
        }
            

        [TestMethod]
        public void BDProverSerializationTest()
        {
            FieldZqElement bigNum = _parameters[0].FieldZq.GetElement(2056);
            PedersenCommitment bigNumCommit = new PedersenCommitment(bigNum,_parameters[0]);
            int decompositionLength = 15;
            ProverBitDecompositionParameters prover = new ProverBitDecompositionParameters(
                bigNumCommit,
                decompositionLength,
                _parameters[0]);

            string jsonString = CryptoSerializer.Serialize<ProverBitDecompositionParameters>(prover);
            ProverBitDecompositionParameters deserializedProver = CryptoSerializer.Deserialize<ProverBitDecompositionParameters>(jsonString);
            Assert.AreEqual(prover.Group.GroupName, deserializedProver.Group.GroupName);
            StaticHelperClass.AssertArraysAreEqual(prover.PublicValues, deserializedProver.PublicValues, "PublicValues");
            StaticHelperClass.AssertArraysAreEqual<DLRepOfGroupElement>(prover.Witnesses, deserializedProver.Witnesses, "Witnesses");
        }

        [TestMethod]
        public void BDVerifierSerializationTest()
        {
            VerifierBitDecompositionParameters verifier = new VerifierBitDecompositionParameters(
                _parameters[0].G, _parameters[0].Generators, _parameters[0]);

            string jsonString = CryptoSerializer.Serialize<VerifierBitDecompositionParameters>(verifier);
            VerifierBitDecompositionParameters deserializedVerifier = CryptoSerializer.Deserialize<VerifierBitDecompositionParameters>(jsonString);
            Assert.AreEqual(verifier.Group.GroupName, deserializedVerifier.Group.GroupName);
            StaticHelperClass.AssertArraysAreEqual(verifier.PublicValues, deserializedVerifier.PublicValues, "PublicValues");
            StaticHelperClass.AssertArraysAreEqual<DLRepOfGroupElement>(verifier.Witnesses, deserializedVerifier.Witnesses, "Witnesses");
        }


        [TestMethod]
        public void BDSerializationTest()
        {
            FieldZqElement bigNum = _parameters[0].FieldZq.GetElement(2056);
            PedersenCommitment bigNumCommit = new PedersenCommitment(bigNum, _parameters[0]);
            int decompositionLength = 15;
            ProverBitDecompositionParameters prover = new ProverBitDecompositionParameters(
                bigNumCommit,
                decompositionLength,
                _parameters[0]);

            BitDecompositionProof proof = new BitDecompositionProof(prover);
            Assert.IsTrue(proof.Verify(prover), "original proof verification.");
            string jsonProof = CryptoSerializer.Serialize<BitDecompositionProof>(proof);
            // TODO: switch to using ip-based de-serialization; need to harmonize with U-Prove SDK code
            IssuerParameters ip = new IssuerParameters();
            ip.Gq = prover.Group;
            BitDecompositionProof deserializedProof = ip.Deserialize<BitDecompositionProof>(jsonProof);// CryptoSerializer.Deserialize<BitDecompositionProof>(jsonProof);
            Assert.IsTrue(deserializedProof.Verify(prover), "deserialized proof verfication");
            

            string jsonProver = CryptoSerializer.Serialize<ProverBitDecompositionParameters>(prover);
            ProverBitDecompositionParameters deserializedProver = CryptoSerializer.Deserialize<ProverBitDecompositionParameters>(jsonProver);
            Assert.IsTrue(deserializedProof.Verify(deserializedProver), "deserialized proof with deserialized prover.");

            BitDecompositionProof proof2 = new BitDecompositionProof(deserializedProver);
            Assert.IsTrue(proof2.Verify(deserializedProver), "proof2.verify(deserializedProver)");
            Assert.IsTrue(proof2.Verify(prover), "Proof2.verify(prover)");
        
        }


        [TestMethod]
        public void BDBadCompositionTest()
        {
            PedersenCommitment[] ped = new PedersenCommitment[2];
            ped[0] = new PedersenCommitment(_parameters[0].G, _parameters[0].H, _parameters[0].FieldZq.One, _parameters[0].FieldZq.One, _parameters[0].Group);
            ped[1] = new PedersenCommitment(_parameters[1].G, _parameters[1].H, _parameters[1].FieldZq.One, _parameters[1].FieldZq.One, _parameters[1].Group);
            PedersenCommitment composition=ped[0];
            FieldZq field = _parameters[0].FieldZq;

            PrivateType bdproof = new PrivateType(typeof(BitDecompositionProof));
            object [] inputParameters = new object[3]{ ped, _parameters[0].FieldZq, composition};
            bool success = (bool)bdproof.InvokeStatic("ComposeCommitments", inputParameters);
            Assert.IsFalse(success, "success");
        }

        [TestMethod]
        public void BDBadProofTest()
        {
            FieldZqElement bigNum = _parameters[0].FieldZq.GetElement(30);
            PedersenCommitment bigNumCommit = new PedersenCommitment(bigNum, _parameters[0]);
            int decompositionLength = 8;


            ProverBitDecompositionParameters proverParams = new ProverBitDecompositionParameters(
                bigNumCommit,
                decompositionLength,
                _parameters[0]);
            BitDecompositionProof proof = new BitDecompositionProof(proverParams);
            PrivateObject proofAccessor = new PrivateObject(proof);

            SetMembershipProof[] smProof =(SetMembershipProof[]) proofAccessor.GetField("bitCommitmentProof");
            SetMembershipProof[] badSmProof = smProof;
            SetMembershipProof tmp = smProof[1];
            badSmProof[1] = badSmProof[0];
            proofAccessor.SetFieldOrProperty("bitCommitmentProof", badSmProof);
            Assert.IsFalse(proof.Verify(proverParams), "bad set membeship proof.");
            proofAccessor.SetFieldOrProperty("bitCommitmentProof", smProof);
            smProof[1] = tmp;
            Assert.IsTrue(proof.Verify(proverParams), "good set membership proof.");

            EqualityProof eqProof = (EqualityProof)proofAccessor.GetField("compositionProof");
            PrivateObject eqProofAccessor = new PrivateObject(eqProof);
            GroupElement [] b =(GroupElement[]) eqProofAccessor.GetField("b");
            b[1] = b[0];
            eqProofAccessor.SetField("b", b);
            Assert.IsFalse(proof.Verify(proverParams), "bad equality proof");
        }

        [TestMethod]
        public void BDBadProverParameterTest()
        {
            ProverBitDecompositionParameters prover = new ProverBitDecompositionParameters(
                new PedersenCommitment(_parameters[2].FieldZq.GetElement(10), _parameters[2]),
                4,
                _parameters[2]);


            prover.Witnesses[3] = new PedersenCommitment(_parameters[2].FieldZq.GetElement(2), _parameters[2]);
            StaticHelperClass.AssertThrowsException
                (
                    () => { BitDecompositionProof proof = new BitDecompositionProof(prover); },
                    typeof(Exception),
                    "Bad prover parameters."
                    ); 
        }

        [TestMethod]
        public void BDBadProverTest()
        {
            ProverBitDecompositionParameters prover = new ProverBitDecompositionParameters(
                new PedersenCommitment(_parameters[2].FieldZq.GetElement(10), _parameters[2]),
                4,
                _parameters[2]);

            BitDecompositionProof proof = new BitDecompositionProof(prover);
            PrivateObject proverAccessor = new PrivateObject(prover);
            PedersenCommitment[] witnesses = (PedersenCommitment[] ) proverAccessor.GetFieldOrProperty("Witnesses");
            witnesses[witnesses.Length - 1] = new PedersenCommitment(_parameters[2].FieldZq.GetElement(10), _parameters[2]);
            Assert.IsFalse(proof.Verify(prover));

        }

    }
}
