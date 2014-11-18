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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using UProveCrypto;
using UProveCrypto.PolyProof;

namespace PolyProofUnitTests
{
    [TestClass]
    public class UProveTokenTest
    {

        [TestMethod]
        public void TokenConstructorTest()
        {
            // generate prover parameters using recommended parameters.
            ProverPresentationProtocolParameters proverParams;
            VerifierPresentationProtocolParameters verifierParams;
            StaticHelperClass.GetUProveParameters(false, out proverParams, out verifierParams);

            // create token
            OpenUProveToken token = new OpenUProveToken(proverParams);

            // get expected public key
            Assert.AreEqual(proverParams.KeyAndToken.Token.H, token.PublicKey, "check public key");
            Assert.IsTrue(token.Validate(null), "validate token.");
        }

        [TestMethod]
        public void TokenSerializationTest()
        {
            // generate prover parameters using recommended parameters.
            ProverPresentationProtocolParameters proverParams;
            VerifierPresentationProtocolParameters verifierParams;
            StaticHelperClass.GetUProveParameters(false, out proverParams, out verifierParams);

            // create token
            OpenUProveToken token = new OpenUProveToken(proverParams);

            // Serialize token
            string serialized = CryptoSerializer.Serialize<OpenUProveToken>(token);
            OpenUProveToken newToken = CryptoSerializer.Deserialize<OpenUProveToken>(serialized, null,token.G);

            Assert.AreEqual(token, newToken, "token");
        }

    }
}
