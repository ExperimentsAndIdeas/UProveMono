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
    public class PedersenCommitmentTest
    {
        // will perform tests using several different parameter sets
        private static CryptoParameters [] _parameters;

        private static ProverPresentationProtocolParameters _proverParams;
        private static VerifierPresentationProtocolParameters _verifierParams;


        [ClassInitialize]
        public static void Init(TestContext context)
        {
            // create parameter sets
            _parameters = new CryptoParameters[6];
            _parameters[0] = new CryptoParameters(ECParameterSets.ParamSet_EC_P256_V1, null);
            _parameters[1] = new CryptoParameters(ECParameterSets.ParamSet_EC_P384_V1, null);
            _parameters[2] = new CryptoParameters(ECParameterSets.ParamSet_EC_P521_V1, null);
            _parameters[3] = new CryptoParameters(SubgroupParameterSets.ParamSetL1024N160V1, null);
            _parameters[4] = new CryptoParameters(SubgroupParameterSets.ParamSetL2048N256V1, null);
            _parameters[5] = new CryptoParameters(SubgroupParameterSets.ParamSetL3072N256V1, null);
//            _parameters[6] = new CryptoParameters(ECParameterSets.ParamSet_EC_BN254_V1, null);


            // generate prover parameters using recommended parameters.
            StaticHelperClass.GetUProveParameters(true, out _proverParams, out _verifierParams);
        }

        [TestMethod]
        public void SimpleConstructorTest()
        {
            for (int i = 0; i < _parameters.Length; ++i)
            {
                FieldZqElement committedValue = _parameters[i].FieldZq.GetRandomElement(true);
                GroupElement g = _parameters[i].G;
                GroupElement h = _parameters[i].H;

                PedersenCommitment pedCom1 = new PedersenCommitment(committedValue, _parameters[i]);
                FieldZqElement opening = pedCom1.ExponentAtIndex(1);

                Assert.AreEqual(g, pedCom1.BaseAtIndex(0), "pedcom1 has wrong base_0");
                Assert.AreEqual(h, pedCom1.BaseAtIndex(1), "pedcom1 has wrong base_1");
                Assert.AreEqual(committedValue, pedCom1.CommittedValue, "pedcom1 used wrong committed value");
                GroupElement expectedCommitmentValue = g.Exponentiate(committedValue) * h.Exponentiate(opening);
                Assert.AreEqual(expectedCommitmentValue, pedCom1.Value, "pedcom1 computed wrong value");


                PedersenCommitment pedCom2 = new PedersenCommitment(g, h, committedValue, opening, _parameters[i].Group);
                Assert.AreEqual(pedCom1, pedCom2, "pedcom1 and pedcom2 different");

                FieldZqElement[] exponents = new FieldZqElement[2]{committedValue,opening};
                GroupElement[] bases = new GroupElement[2] { g, h };
                PedersenCommitment pedCom3 = new PedersenCommitment(bases, exponents, _parameters[i].Group);
                Assert.AreEqual(pedCom1, pedCom3, "pedcom1 and pedcom3 different");
                Assert.AreEqual(pedCom2, pedCom3, "pedcom2 and pedcom3 different");
            }
        }

        public void DLtoPedConstructorTest()
        {
            for (int paramIndex = 0; paramIndex < _parameters.Length; ++paramIndex)
            {
                GroupElement[] bases = StaticHelperClass.GenerateRandomBases(2, paramIndex);
                FieldZqElement[] exponents = StaticHelperClass.GenerateRandomExponents(2, paramIndex);
                DLRepOfGroupElement dl = new DLRepOfGroupElement(bases, exponents, _parameters[paramIndex].Group);
                PedersenCommitment ped = new PedersenCommitment(dl);

                Assert.IsTrue(ped.Validate(), "ped should be a valid pedersen commitment.");
                Assert.AreEqual(bases[0], ped.G, "Wrong G value.");
                Assert.AreEqual(bases[1], ped.H, "Wrong H value.");
                Assert.AreEqual(exponents[0], ped.CommittedValue, "wrong committed value.");
                Assert.AreEqual(exponents[1], ped.Opening, "wrong opening.");

                GroupElement expectedValue = _parameters[paramIndex].Group.MultiExponentiate(bases, exponents);
                Assert.AreEqual(expectedValue, ped.Value, "wrong value.");
            }


        }


        public void PedCommitmentBadConstructorTest()
        {
            int paramIndex=6;
            GroupElement[] bases = null;
            FieldZqElement[] exponents = null;
            Group group = _parameters[paramIndex].Group;
            PedersenCommitment ped;

            // null input
            bool threwException=false;
            try
            {
                ped = new PedersenCommitment(bases, exponents, group);
            }
            catch (Exception)
            {
                threwException = true;
            }
            Assert.IsTrue(threwException, "should throw exception on null input.");

            // wrong length bases & exponent arrays
            threwException = false;
            bases = StaticHelperClass.GenerateRandomBases(1, paramIndex);
            exponents = StaticHelperClass.GenerateRandomExponents(1, paramIndex);
            try
            {
                ped = new PedersenCommitment(bases, exponents, group);
            }
            catch (Exception)
            {
                threwException = true;
            }
            Assert.IsTrue(threwException, "should throw exception when bases and exponents are arrays of length 1.");

            // wrong length bases & exponent arrays
            threwException = false;
            bases = StaticHelperClass.GenerateRandomBases(3, paramIndex);
            exponents = StaticHelperClass.GenerateRandomExponents(3, paramIndex);
            try
            {
                ped = new PedersenCommitment(bases, exponents, group);
            }
            catch (Exception)
            {
                threwException = true;
            }
            Assert.IsTrue(threwException, "should throw exception when bases and exponents are arrays of length 3.");
        }

        [TestMethod]
        public void DLRepToPedBadConstructorTest()
        {
            int paramIndex = 5;
            GroupElement[] bases = null;
            FieldZqElement[] exponents = null;
            Group group = _parameters[paramIndex].Group;
            PedersenCommitment ped;


            // wrong length bases & exponent arrays
            bool threwException = false;
            bases = StaticHelperClass.GenerateRandomBases(1, paramIndex);
            exponents = StaticHelperClass.GenerateRandomExponents(1, paramIndex);
            DLRepOfGroupElement dl = new DLRepOfGroupElement(bases, exponents, group);
            try
            {
                ped = new PedersenCommitment(dl);
            }
            catch (Exception)
            {
                threwException = true;
            }
            Assert.IsTrue(threwException, "should throw exception when dl representation length is 1.");

            // wrong length bases & exponent arrays
            threwException = false;
            bases = StaticHelperClass.GenerateRandomBases(3, paramIndex);
            exponents = StaticHelperClass.GenerateRandomExponents(3, paramIndex);
            dl = new DLRepOfGroupElement(bases, exponents, group);
            try
            {
                ped = new PedersenCommitment(dl);
            }
            catch (Exception)
            {
                threwException = true;
            }
            Assert.IsTrue(threwException, "should throw exception when bases and exponents are arrays of length 3.");
     

        }

        [TestMethod]
        public void PresentationProofConstructorTest()
        {
            // generate array of commitments using PresentationProof
            CommitmentPrivateValues cpv;
            Assert.IsNotNull(_proverParams, "prover params null");
            PresentationProof proof = PresentationProof.Generate(_proverParams, out cpv);

            Assert.IsNotNull(proof.Commitments, "proof failed to generate commitments");
            Assert.IsNotNull(cpv, "failed to output cpv");
            Assert.IsNotNull(cpv.TildeO, "cpv.TildeO is null");
            CommitmentValues [] expectedCommitmentValues = proof.Commitments;

            // generate array of commitments using Pedersen Commitment constructor
            PedersenCommitment [] proverCommitments = PedersenCommitment.ArrayOfPedersenCommitments(_proverParams, proof, cpv);

            // compare values
            GroupElement expectedG = _proverParams.IP.Gq.G;
            GroupElement expectedH = _proverParams.IP.G[1];
            for (int commitIndex = 0; commitIndex < expectedCommitmentValues.Length; ++commitIndex)
            {
                int attributeIndex = _proverParams.Committed[commitIndex] -1;
                FieldZqElement expectedCommittedValue = ProtocolHelper.ComputeXi(_proverParams.IP, attributeIndex, _proverParams.Attributes[attributeIndex]);
                Assert.AreEqual(expectedCommittedValue, proverCommitments[commitIndex].CommittedValue, "wrong committed value");
                Assert.AreEqual(cpv.TildeO[commitIndex], proverCommitments[commitIndex].Opening, "opening does not match tildeO");
                Assert.AreEqual(expectedG, proverCommitments[commitIndex].G, "base g wrong");
                Assert.AreEqual(expectedH, proverCommitments[commitIndex].H, "base h wrong");
                Assert.AreEqual(expectedCommitmentValues[commitIndex].TildeC, proverCommitments[commitIndex].Value, "wrong value");
            }

            // generate array of closed pedersen commitments
            ClosedPedersenCommitment[] verifierCommitments = ClosedPedersenCommitment.ArrayOfClosedPedersenCommitments(_verifierParams.IP, proof);

            // compare bases and values to actualCommitments
            Assert.IsTrue(ClosedPedersenCommitment.AreBasesEqual(verifierCommitments), "all closed commitments should have same bases.");
            Assert.IsTrue(verifierCommitments[0].AreBasesEqual(proverCommitments[0]), "all closed commitments should have same bases as open commitments");
            Assert.AreEqual(proverCommitments.Length,verifierCommitments.Length, "should be as many open and closed commitments");
            for(int i=0; i< verifierCommitments.Length; ++i)
            {
                Assert.AreEqual(verifierCommitments[i].Value, proverCommitments[i].Value, "open and closed commitments should be equal.");
            }
        }

        [TestMethod]
        public void PedCommitmentIndexTest()
        {
            int[] commited = new int[3] { 1, 3, 7 };

            int commitmentIndex = ClosedPedersenCommitment.GetCommitmentIndex(commited, 1);
            int expectedCommitmentIndex = 0;
            Assert.AreEqual(expectedCommitmentIndex, commitmentIndex, "wrong attribute index.");

            commitmentIndex = ClosedPedersenCommitment.GetCommitmentIndex(commited, 3);
            expectedCommitmentIndex = 1;
            Assert.AreEqual(expectedCommitmentIndex, commitmentIndex, "wrong attribute index.");

            commitmentIndex = ClosedPedersenCommitment.GetCommitmentIndex(commited, 7);
            expectedCommitmentIndex = 2;
            Assert.AreEqual(expectedCommitmentIndex, commitmentIndex, "wrong attribute index.");

            bool threwException = false;
            try
            {
                commitmentIndex = ClosedPedersenCommitment.GetCommitmentIndex(commited, 2);
            }
            catch (Exception) {
                threwException = true;
            }
            Assert.IsTrue(threwException, "ClosedPedersenCommitment.GetCommitmentIndex should have thrown exception on input 1");

        }

        [TestMethod]
        public void ClosedDLRepToClosedPedTest()
        {
            GroupElement[] bases = StaticHelperClass.GenerateRandomBases(2, 3);
            GroupElement value = StaticHelperClass.GenerateRandomValue(3);
            ClosedDLRepOfGroupElement udl = new ClosedDLRepOfGroupElement(bases, value, _parameters[3].Group);
            ClosedPedersenCommitment closedPed = new ClosedPedersenCommitment(udl);
            Assert.AreEqual(2, closedPed.RepresentationLength, "representation length should be 2");
            Assert.AreEqual(bases[0], closedPed.G, "G value should be bases[0]");
            Assert.AreEqual(bases[1], closedPed.H, "H value incorrect.");
            Assert.AreEqual(value, closedPed.Value, "value incorrect.");
            Assert.IsTrue(closedPed.Validate(), "should be valid closed pederson commitment.");
        }

        [TestMethod]
        public void GetAttributeIndexTest()
        {
            int[] commited = new int[5] { 4, 5, 5, 3, 12 };
            for (int commitmentIndex = 0; commitmentIndex < commited.Length; ++commitmentIndex)
            {
                Assert.AreEqual(commited[commitmentIndex] - 1, ClosedPedersenCommitment.GetAttributeIndex(commited, commitmentIndex), "Could not get correct attribute index.");
            }
        }

        [TestMethod]
        public void Get_G_H_Tests()
        {
            for (int i = 0; i < _parameters.Length; ++i)
            {
                GroupElement[] bases = StaticHelperClass.GenerateRandomBases(2, i);
                GroupElement value = _parameters[i].Generators[0];
                ClosedPedersenCommitment ped = new ClosedPedersenCommitment(bases, value, _parameters[i].Group);
                Assert.AreEqual(bases[0], ped.G, "Failed to get G.");
                Assert.AreEqual(bases[1], ped.H, "Failed to get H.");
                Assert.IsTrue(ped.Validate());

            }

        }


        [TestMethod]
        public void UnknownDLRepConstructorTest()
        {
            for (int i = 0; i < _parameters.Length; ++i)
            {
                FieldZqElement committedValue = _parameters[i].FieldZq.GetRandomElement(true);
                GroupElement g = _parameters[i].G;
                GroupElement h = _parameters[i].H;

                PedersenCommitment pedCom = new PedersenCommitment(committedValue, _parameters[i]);
                IStatement udl = pedCom.GetStatement();
                Assert.IsFalse(pedCom.Equals(udl), "pedCom does not equal udl due to class hierarchy");
                Assert.IsTrue(PedersenCommitment.IsValidOpenClosedPair(pedCom, udl), "should be valid open closed pair.");
            }
        }

        [TestMethod]
        public void ClosedPedConstructorTests()
        {
            GroupElement[] badbases = StaticHelperClass.GenerateRandomBases(3, 0);
            GroupElement value = badbases[2];
            ClosedDLRepOfGroupElement baddl = new ClosedDLRepOfGroupElement(badbases, value, _parameters[0].Group);
            bool threwException = false;
            try
            {
                ClosedPedersenCommitment ped = new ClosedPedersenCommitment(badbases,value, _parameters[0].Group);
            }
            catch(Exception)
            {
                threwException = true;
            }
            Assert.IsTrue(threwException, "ClosedPedersenCommitment constructor should throw Exception when length of bases is not 2");
            threwException = false;
            try
            {
                ClosedPedersenCommitment ped = new ClosedPedersenCommitment(baddl);
            }
            catch (Exception)
            {
                threwException = true;
            }


            badbases = StaticHelperClass.GenerateRandomBases(1, 0);
            baddl = new ClosedDLRepOfGroupElement(badbases, value, _parameters[0].Group);
            threwException = false;
            try
            {
                ClosedPedersenCommitment ped = new ClosedPedersenCommitment(badbases, value, _parameters[0].Group);
            }
            catch (Exception)
            {
                threwException = true;
            }
            Assert.IsTrue(threwException, "ClosedPedersenCommitment constructor should throw Exception when length of bases is 1.");
            threwException = false;
            try
            {
                ClosedPedersenCommitment ped = new ClosedPedersenCommitment(baddl);
            }
            catch (Exception)
            {
                threwException = true;
            }
            Assert.IsTrue(threwException, "ClosedPedersenCommitment constructor should throw Exception when length of bases is 1.");

        }

    }
}
