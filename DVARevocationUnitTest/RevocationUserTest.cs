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
using System.Collections.Generic;
using UProveCrypto;
using UProveCrypto.DVARevocation;
using UProveCrypto.Math;

namespace DVARevocationUnitTest
{
    /// <summary>
    /// Summary description for RevocationUserTest
    /// </summary>
    [TestClass]
    public class RevocationUserTest
    {
        private static IssuerParameters ip;
        private static FieldZqElement xid;
        private static byte[][] attributes;
        private static UProveKeyAndToken upkt;
        private RevocationAuthority RA;

        public RevocationUserTest()
        {
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
        // Use ClassInitialize to run code before running the first test in the class
        [ClassInitialize()]
        public static void MyClassInitialize(TestContext testContext)
        {
            //
            // generate issuer parameters
            //
            IssuerSetupParameters isp = new IssuerSetupParameters();
            isp.UidP = new byte[] { (byte)0 };
            isp.NumberOfAttributes = 1;
            isp.E = new byte[] { (byte)0 };  // encode xid directly has an 
            IssuerKeyAndParameters ikap = isp.Generate();
            ip = ikap.IssuerParameters;

            //
            // issue a token
            //
            xid = ip.Gq.FieldZq.GetRandomElement(false);
            IssuerProtocolParameters ipp = new IssuerProtocolParameters(ikap);
            ProverProtocolParameters ppp = new ProverProtocolParameters(ip);
            attributes = new byte[][] { xid.ToByteArray() };
            ipp.Attributes = ppp.Attributes = attributes;
            ipp.NumberOfTokens = ppp.NumberOfTokens = 1;
            Issuer issuer = ipp.CreateIssuer();
            Prover prover = ppp.CreateProver();
            upkt = prover.GenerateTokens(issuer.GenerateThirdMessage(prover.GenerateSecondMessage(issuer.GenerateFirstMessage())))[0];

        }

        // Use ClassCleanup to run code after all tests in a class have run
        // [ClassCleanup()]
        // public static void MyClassCleanup() { }
        //
        // Use TestInitialize to run code before running each test 
        [TestInitialize()]
        public void MyTestInitialize()
        {
            // instantiate the revocation authority
            RA = RevocationAuthority.GenerateRevocationAuthority(ip);
        }
        //
        // Use TestCleanup to run code after each test has run
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        //
        #endregion

        [TestMethod]
        public void UpdateWitnessTest()
        {
            // TODO: test deletion
            RAParameters rap = RA.RAParameters;
            FieldZqElement[] revoked = rap.group.FieldZq.GetRandomElements(5, true);
            GroupElement oldAccumulator = null;
            RevocationWitness oldWitness = null;

            // a 2nd RA with matching key and params
            RevocationAuthority RA2 = new RevocationAuthority(rap, RA.PrivateKey);
            HashSet<FieldZqElement> revokedSet2 = new HashSet<FieldZqElement>();
            HashSet<FieldZqElement> revokedSet = null;
            for (int i = 0; i < revoked.Length; i++)
            {
                // add some revoked values, and update the accumulator and witness
                revokedSet = new HashSet<FieldZqElement>(new FieldZqElement[] { revoked[i] });
                RA.UpdateAccumulator(revokedSet);
                GroupElement accumulator = RA.Accumulator;
                RevocationWitness witness = RevocationUser.UpdateWitness(rap, xid, revoked[i], null, oldAccumulator, accumulator, oldWitness);

                // update the revoked values with the accumulated revoked set, and have RA2 calculate the witness
                // for the user; they should match
                RA2.Accumulator = null; // reset the accumulator of RA2
                revokedSet2.Add(revoked[i]);
                RA2.UpdateAccumulator(revokedSet2);
                GroupElement accumulator2 = RA2.Accumulator;
                RevocationWitness witness2 = RA2.ComputeRevocationWitness(revokedSet2, xid);
                Assert.AreEqual(accumulator, accumulator2, "accumulators are different");
                Assert.AreEqual(witness.d, witness2.d, "witness d values are different");
                Assert.AreEqual(witness.W, witness2.W, "witness W values are different");
                Assert.AreEqual(witness.Q, witness2.Q, "witness Q values are different");

                oldWitness = witness;
                oldAccumulator = accumulator;
            }
        }


        [TestMethod]
        public void GenerateNonRevocationProofTest()
        {
            RAParameters rap = RA.RAParameters;
            HashSet<FieldZqElement> revokedValues = new HashSet<FieldZqElement>(rap.group.FieldZq.GetRandomElements(10, false));
            RA.UpdateAccumulator(revokedValues);

            // generate proof when xid is not revoked
            byte[] message = new byte[] { (byte)0 };
            ProverPresentationProtocolParameters pppp = new ProverPresentationProtocolParameters(ip, null, message, upkt, attributes);
            pppp.Committed = new int[] { 1 };
            CommitmentPrivateValues cpv;
            PresentationProof pp = PresentationProof.Generate(pppp, out cpv);
            int revocationCommitmentIndex = 0;
            NonRevocationProof nrp = RevocationUser.GenerateNonRevocationProof(ip, rap, RA.ComputeRevocationWitness(revokedValues, xid), revocationCommitmentIndex, pp, cpv, 1, attributes);
            RA.VerifyNonRevocationProof(ip, revocationCommitmentIndex, pp, nrp);
        }
    }
}
