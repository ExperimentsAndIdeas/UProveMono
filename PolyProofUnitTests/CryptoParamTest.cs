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
    public class CryptoParamTest
    {


        [TestMethod]
        public void CryptoUProveConstructorTest()
        {
            ProverPresentationProtocolParameters prover;
            VerifierPresentationProtocolParameters verifier;
            StaticHelperClass.GetUProveParameters(false, out prover, out verifier);

            CryptoParameters crypto = new CryptoParameters(prover.IP);
            Assert.AreEqual(prover.IP.Gq, crypto.Group);
            Assert.AreEqual(prover.IP.UidH, crypto.HashFunctionName);
            Assert.AreEqual(prover.IP.Gq.G, crypto.G);
            Assert.AreEqual(prover.IP.G[1], crypto.H);
            Assert.AreEqual(prover.IP.Zq.One, crypto.FieldZq.One);
            Assert.IsTrue(crypto.Verify(), "Verify should pass.");

        }

        [TestMethod]
        public void CryptoParameterSetConstructorTest()
        {
            ParameterSet ps = StaticHelperClass.Parameters;
            CryptoParameters crypto = new CryptoParameters(ps, null);
            Assert.AreEqual(ps.Group, crypto.Group);
            Assert.AreEqual(CryptoParameters.DefaultHashFunctionName, crypto.HashFunctionName);
            Assert.AreEqual(ps.G[0], crypto.G);
            Assert.AreEqual(ps.G[1], crypto.H);
            Assert.IsTrue(crypto.Verify(), "Verify should pass.");

        }

        [TestMethod]
        public void CryptoNullInputToConstructorTest()
        {
            CryptoParameters crypto = new CryptoParameters(null, null, null);

            Assert.IsNull(crypto.G, "generator G is null.");
            Assert.IsNull(crypto.H, "generator H is null.");
            Assert.IsFalse(crypto.Verify(), "Verify should fail since group and generators are empty.");
        }

        [TestMethod]
        public void CryptoSerializationTest()
        {
            foreach (CryptoParameters crypto in StaticHelperClass.ParameterArray)
            {
                // serialize the parameters
                string serialized = CryptoSerializer.Serialize<CryptoParameters>(crypto);

                // deserialize the parameters
                CryptoParameters deserialized = CryptoSerializer.Deserialize<CryptoParameters>(serialized);
                Assert.IsTrue(deserialized.Verify(), "crypto parameters invalid.");
                Assert.AreEqual(crypto.Group.GroupName, deserialized.Group.GroupName, "Wrong group name.");
                Assert.AreEqual(crypto.Group.Q, deserialized.Group.Q, "wrong modulus.");
                Assert.AreEqual(crypto.Generators.Length, deserialized.Generators.Length, "wrong number of generators.");
                Assert.AreEqual(crypto.G, deserialized.G, "wrong generator G.");
                Assert.AreEqual(crypto.H, deserialized.H, "wrong generator H.");
                Assert.AreEqual(crypto.HashFunctionName, deserialized.HashFunctionName, "wrong hash function.");

            }

        }
    }
}
