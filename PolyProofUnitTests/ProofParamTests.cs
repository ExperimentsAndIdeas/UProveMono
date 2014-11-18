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
using UProveCrypto.PolyProof;
using UProveCrypto.Math;
using UProveCrypto;

namespace PolyProofUnitTests
{
    [TestClass]
    public class ProofParamTests
    {
        
        [TestMethod]
        public void PPVerifyFailsTest()
        {
            CryptoParameters crypto = new CryptoParameters(null, null);
            ProofParameters pp = new ProofParameters(crypto);
            Assert.IsFalse(pp.Verify());
            pp.setProverParameters(null);
            Assert.IsFalse(pp.Verify());
            pp.setVerifierParameters(null);
            Assert.IsFalse(pp.Verify());

            pp.setVerifierParameters(new GroupElement[0]);
            Assert.IsTrue(pp.Verify());

            pp.setProverParameters(new DLRepOfGroupElement[0]);
            Assert.IsTrue(pp.Verify());
  
        }

        [TestMethod]
        public void PPSerializationTest()
        {
            int paramIndex = 4;
            ProofParameters original = new ProofParameters(StaticHelperClass.ParameterArray[paramIndex]);
            DLRepOfGroupElement [] witnesses = new DLRepOfGroupElement[10];
            GroupElement[] bases = new GroupElement[5]{
                original.Generators[0],
                original.Generators[1],
                original.Generators[2],
                original.Generators[3],
                original.Generators[4]
            };
            for(int i=0; i<10; ++i)
            {
              FieldZqElement[] exponents = StaticHelperClass.GenerateRandomExponents(5, paramIndex);
              witnesses[i] = new DLRepOfGroupElement(bases, exponents, original.Group);
            }
            original.setProverParameters(witnesses);

            string serializedParams = CryptoSerializer.Serialize<ProofParameters>(original);
            ProofParameters deserialized = CryptoSerializer.Deserialize<ProofParameters>(serializedParams);

            Assert.AreEqual(original.ProverParameters, deserialized.ProverParameters, "ProverParameters field improperly deserialized");
            StaticHelperClass.AssertArraysAreEqual(original.Generators, deserialized.Generators, "Generators.");
            StaticHelperClass.AssertArraysAreEqual(original.PublicValues, deserialized.PublicValues, "Public Values.");
            StaticHelperClass.AssertArraysAreEqual(original.Witnesses, deserialized.Witnesses, "Witnesses");
            Assert.AreEqual(original.Group.G, deserialized.Group.G, "Group.group.g");
        }
    }
}
