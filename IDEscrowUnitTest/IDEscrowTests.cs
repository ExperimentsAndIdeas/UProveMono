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

using IDEscrow;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using UProveCrypto;
using UProveCrypto.Math;

// Unit tests for identity escrow module.  
// Note that these have to be run in order, and the tests share alot
// of state via static variables (this is to avoid re-computing everything
// for each test, which would be slow).  There is an ordered
// list of tests included in the project (called IDEscrowUnits.orderedtest)
// gregz 11/2/2012


namespace IDEscrowUnitTest
{
    [TestClass]
    public class IDEscrowTests
    {
        private static byte[] tokenID = { 1, 2, 3, 4 };
        private static byte[] additionalInfo = { 5, 6, 7, 8, 9, 10 };


        private static IssuerParameters ip;
        [TestMethod]
        public void SetupIssuerParameters()
        {
            // Generate issuer parameters (need the group params)
            byte[][] A = new byte[][] { };
            byte[] TI = null;
            //byte[] PI = null;
            IssuerSetupParameters isp = new IssuerSetupParameters();
            isp.UidP = new byte[] { 65, 65, 65 };
            isp.E = new byte[] { 0 };
            IssuerKeyAndParameters ikap = isp.Generate();
            IssuerProtocolParameters ipp = new IssuerProtocolParameters(ikap);
            ipp.Attributes = A;
            ipp.NumberOfTokens = 1;
            ipp.TokenInformation = TI;
            ip = ikap.IssuerParameters;
        }

        private static IDEscrowParams ieParam;
        [TestMethod]
        public void SetupIEParameters()
        {
            ieParam = new IDEscrowParams(ip);

            // Serialize a copy
            string ieParamStr = ip.Serialize(ieParam);

            // check that we didn't send any null fields
            Assert.IsFalse(ieParamStr.Contains(":null"));

            IDEscrowParams ieParam2 = ip.Deserialize<IDEscrowParams>(ieParamStr);
            Assert.IsTrue(ieParam.Equals(ieParam2));

        }

        private static IDEscrowPrivateKey sk;
        private static IDEscrowPublicKey pk;
        [TestMethod]
        public void TestIEKeyGen()
        {
            string skStr;
            string pkStr;
            sk = new IDEscrowPrivateKey(ieParam);
            pk = new IDEscrowPublicKey(ieParam, sk);
            Assert.IsTrue(pk.Verify(ieParam, sk));

            skStr = ip.Serialize(sk);
            pkStr = ip.Serialize(pk);
            Assert.IsFalse(skStr.Contains(":null"));
            Assert.IsFalse(pkStr.Contains(":null"));

            IDEscrowPrivateKey sk2 = ip.Deserialize<IDEscrowPrivateKey>(skStr);
            IDEscrowPublicKey pk2 = ip.Deserialize<IDEscrowPublicKey>(pkStr);

            Assert.IsTrue(pk.Equals(pk2));
            Assert.IsTrue(sk.Equals(sk2));
            Assert.IsTrue(pk2.Verify(ieParam));
            Assert.IsTrue(pk2.Verify(ieParam, sk2));
        }

        private static GroupElement Cxb, PE;
        private static IDEscrowCiphertext ctext;
        [TestMethod]
        public void TestIEEncrypt()
        {
            // Create a commitment and attribute value. 
            // Need g, g1, Cxb, xb, ob
            FieldZq F = ip.Zq;
            FieldZqElement xb = F.GetRandomElement(true);
            FieldZqElement ob = F.GetRandomElement(true);
            Cxb = ip.Gq.G.Exponentiate(xb);    // Cxb = g^xb
            Cxb = Cxb.Multiply(ip.G[1].Exponentiate(ob));   // Cxb = (g^xb)*(g1^ob)

            // Create the pseudonym (which will be used later to check that decryption is correct)
            PE = ieParam.Ge.Exponentiate(xb);               

            // Encrypt
            ctext = IDEscrowFunctions.VerifiableEncrypt(ieParam, pk, tokenID, Cxb, xb, ob, additionalInfo);

            // Serialize
            string ctextStr = ip.Serialize(ctext);
            Assert.IsFalse(ctextStr.Contains(":null"));
            
            // deserialize and compare
            IDEscrowCiphertext ctext2 = ip.Deserialize<IDEscrowCiphertext>(ctextStr);
            Assert.IsTrue(ctext.Equals(ctext2));

        }

        [TestMethod]
        public void TestIEVerify()
        {
            // Verify
            bool isValid = IDEscrowFunctions.Verify(ieParam, ctext, tokenID, pk, Cxb);
            Assert.IsTrue(isValid);
        }

        [TestMethod]
        public void TestIEDecrypt()
        {
            // Decrypt
            GroupElement PEPrime = IDEscrowFunctions.Decrypt(ieParam, ctext, sk);
            Assert.IsTrue(PE.Equals(PEPrime));
        }

        [TestMethod]
        public void TestIEWithSerialized()
        {
            // Does a complete encrypt/decrypt sequence from serialized values. 
            // Kind of redundant because each of the testmethods above test serialization
            // of individual data types

            //Serialize and deserialize all objects
            IDEscrowParams ieParam2 = ip.Deserialize<IDEscrowParams>(ip.Serialize(ieParam));
            IDEscrowPublicKey pk2 = ip.Deserialize<IDEscrowPublicKey>(ip.Serialize(pk));
            IDEscrowPrivateKey sk2 = ip.Deserialize<IDEscrowPrivateKey>(ip.Serialize(sk));

            // Encrypt
            FieldZq F = ip.Zq;
            FieldZqElement xb2 = F.GetRandomElement(true);
            FieldZqElement ob2 = F.GetRandomElement(true);
            GroupElement Cxb2 = ip.Gq.G.Exponentiate(xb2);    // Cxb = g^xb
            Cxb2 = Cxb2.Multiply(ip.G[1].Exponentiate(ob2));   // Cxb = (g^xb)*(g1^ob)
            GroupElement PE2 = ieParam2.Ge.Exponentiate(xb2);

            IDEscrowCiphertext ctext2 = IDEscrowFunctions.VerifiableEncrypt(ieParam2, pk2, tokenID, Cxb2, xb2, ob2, additionalInfo);
            ctext2 = ip.Deserialize<IDEscrowCiphertext>(ip.Serialize(ctext2));

            // Verify
            bool isValid = IDEscrowFunctions.Verify(ieParam2, ctext2, tokenID, pk2, Cxb2);
            Assert.IsTrue(isValid);

            // Decrypt
            GroupElement PEPrime = IDEscrowFunctions.Decrypt(ieParam2, ctext2, sk2);
            Assert.IsTrue(PE2.Equals(PEPrime));
        }

        [TestMethod]
        public void TestIEWithRealToken()
        {
            /********** begin: this section of code taken from EndToEndTest.cs, TestMethod PseudonymAndCommitmentsTest *****/
            System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();

            // Issuer setup
            IssuerSetupParameters isp = new IssuerSetupParameters();
            isp.UidP = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            isp.E = new byte[] { (byte)1, (byte)1, (byte)1, (byte)1 };
            isp.UseRecommendedParameterSet = true;
            isp.S = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            IssuerKeyAndParameters ikap = isp.Generate();
            IssuerParameters ip2 = ikap.IssuerParameters;

            // Issuance
            byte[][] attributes = new byte[][] { encoding.GetBytes("Attribute 1"), encoding.GetBytes("Attribute 2"), encoding.GetBytes("Attribute 3"), encoding.GetBytes("Attribute 4") };
            byte[] tokenInformation = new byte[] { };
            byte[] proverInformation = new byte[] { };
            int numberOfTokens = 1;

            IssuerProtocolParameters ipp = new IssuerProtocolParameters(ikap);
            ipp.Attributes = attributes;
            ipp.NumberOfTokens = numberOfTokens;
            ipp.TokenInformation = tokenInformation;
            Issuer issuer = ipp.CreateIssuer();
            FirstIssuanceMessage msg1 = issuer.GenerateFirstMessage();
            ProverProtocolParameters ppp = new ProverProtocolParameters(ip2);
            ppp.Attributes = attributes;
            ppp.NumberOfTokens = numberOfTokens;
            ppp.TokenInformation = tokenInformation;
            ppp.ProverInformation = proverInformation;
            Prover prover = ppp.CreateProver();
            SecondIssuanceMessage msg2 = prover.GenerateSecondMessage(msg1);
            ThirdIssuanceMessage msg3 = issuer.GenerateThirdMessage(msg2);
            UProveKeyAndToken[] upkt = prover.GenerateTokens(msg3);

            // Pseudonym
            int[] disclosed = new int[0];
            int[] committed = new int[] { 2, 4 };
            byte[] message = encoding.GetBytes("this is the presentation message, this can be a very long message");
            byte[] scope = encoding.GetBytes("scope");
            PresentationProof proof;
            FieldZqElement[] tildeO;

            // Valid presentation
            proof = PresentationProof.Generate(ip2, disclosed, committed, 1, scope, message, null, null, upkt[0], attributes, out tildeO);
            try { proof.Verify(ip2, disclosed, committed, 1, scope, message, null, upkt[0].Token); }
            catch { Assert.Fail("Proof failed to verify"); }
            /******** end code from EndToEndTest.cs ***********/

            // Use the commitment to attribute x_2 for ID escrow
            GroupElement Cx2 = proof.Commitments[0].TildeC;         // x2 is the first committed attribute
            FieldZqElement x2 = ProtocolHelper.ComputeXi(ip2, 1, attributes[1]);       // attributes[] is zero indexed.
            FieldZqElement tildeO2 = tildeO[0];

            // double check that Cx2 is computed as we expect.
            GroupElement Cx2Prime = ip2.Gq.G.Exponentiate(x2);
            Cx2Prime = Cx2Prime.Multiply(ip2.G[1].Exponentiate(tildeO2));
            Assert.IsTrue(Cx2Prime.Equals(Cx2));

            // Setup
            IDEscrowParams ieParam3 = new IDEscrowParams(ip2);
            IDEscrowPrivateKey priv = new IDEscrowPrivateKey(ieParam3);                      // we can't re-use the keypair above, it was created with different issuer params
            IDEscrowPublicKey pub = new IDEscrowPublicKey(ieParam3, priv);
            byte[] tokenID = ProtocolHelper.ComputeTokenID(ip2, upkt[0].Token);
            // additionalInfo is defined above. 

            // Encrypt
            IDEscrowCiphertext ctext = IDEscrowFunctions.VerifiableEncrypt(ieParam3, pub, tokenID, Cx2, x2, tildeO2, additionalInfo);
            // Verify
            Assert.IsTrue(IDEscrowFunctions.Verify(ieParam3, ctext, tokenID, pub, Cx2));
            // Decrypt
            GroupElement PE = IDEscrowFunctions.Decrypt(ieParam3, ctext, priv);

            Assert.IsTrue(PE.Equals(ieParam3.Ge.Exponentiate(x2)));   // Ensure PE == (ge)^x2

        }

    }
}
