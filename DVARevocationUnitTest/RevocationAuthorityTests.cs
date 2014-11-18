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
using System;
using System.Collections.Generic;
using UProveCrypto;
using UProveCrypto.DVARevocation;
using UProveCrypto.Math;

namespace DVARevocationUnitTest
{
    [TestClass]
    public class RevocationAuthorityTests
    {
        [TestMethod]
        public void GenerateRevocationAuthorityTest()
        {
            IssuerSetupParameters isp = new IssuerSetupParameters();
            isp.UidP = new byte[] { (byte)0 };
            isp.NumberOfAttributes = 1;
            IssuerParameters ip = isp.Generate().IssuerParameters;
            RevocationAuthority RA1 = RevocationAuthority.GenerateRevocationAuthority(ip);
            Assert.AreEqual(RA1.RAParameters.gt, RA1.Accumulator);

            // generate a 2nd RA
            RevocationAuthority RA2 = RevocationAuthority.GenerateRevocationAuthority(ip.Gq.GroupName, ip.UidH);
            Assert.AreEqual(RA1.RAParameters.g, RA2.RAParameters.g);
            Assert.AreEqual(RA1.RAParameters.g1, RA2.RAParameters.g1);
            Assert.AreEqual(RA1.RAParameters.gt, RA2.RAParameters.gt);
            Assert.AreEqual(RA1.RAParameters.group, RA2.RAParameters.group);
        }

        [TestMethod]
        public void AccumulatorTest()
        {
            RevocationAuthority RA = RevocationAuthority.GenerateRevocationAuthority(SubgroupParameterSets.ParamSet_SG_2048256_V1Name, "SHA-256");
            FieldZq Zq = RA.RAParameters.group.FieldZq;
            GroupElement emptyAccumulator = RA.Accumulator;
            HashSet<FieldZqElement> revokedValues1 = new HashSet<FieldZqElement>(Zq.GetRandomElements(5, false));
            
            // add and remove values, accumulator should be empty
            RA.UpdateAccumulator(revokedValues1, revokedValues1);
            Assert.AreEqual(emptyAccumulator, RA.Accumulator);
            // again with different API
            RA.UpdateAccumulator(revokedValues1, null);
            RA.UpdateAccumulator(null, revokedValues1);
            Assert.AreEqual(emptyAccumulator, RA.Accumulator);

            // add and remove values, accumulator should be as it started
            // fill in some values
            RA.UpdateAccumulator(revokedValues1);
            GroupElement V = RA.Accumulator;
            // add more values
            HashSet<FieldZqElement> revokedValues2 = new HashSet<FieldZqElement>(Zq.GetRandomElements(5, false));
            RA.UpdateAccumulator(revokedValues2);
            // remove the last set of values, accumulator should be as it was before
            RA.UpdateAccumulator(null, revokedValues2);
            Assert.AreEqual(V, RA.Accumulator);
                    
            // add private key negation to revocation set
            try
            {
                var privateKeyNegation = new HashSet<FieldZqElement>();
                privateKeyNegation.Add(RA.PrivateKey.Negate());
                RA.UpdateAccumulator(privateKeyNegation, null);
                Assert.Fail("Exception expected");
            }
            catch (ArgumentException)
            {
                // expected
            }

        }

        [TestMethod]
        public void TestSerialization()
        {
            // generate a new revocation authority
            IssuerSetupParameters isp = new IssuerSetupParameters();
            isp.UidP = new byte[] { (byte)0 };
            isp.NumberOfAttributes = 1;
            IssuerParameters ip = isp.Generate().IssuerParameters;
            RevocationAuthority RA = RevocationAuthority.GenerateRevocationAuthority(ip);

            // TODO: make a getDefaulHashForGroup method
            RevocationAuthority.GenerateRevocationAuthority(SubgroupParameterSets.ParamSet_SG_2048256_V1Name, "SHA-256");
            // set a random accumulator
            RA.Accumulator = RA.RAParameters.gt.Exponentiate(RA.RAParameters.group.FieldZq.GetRandomElement(false));
            RevocationAuthority RA2 = ip.Deserialize<RevocationAuthority>(ip.Serialize<RevocationAuthority>(RA));

            Assert.AreEqual(RA.PrivateKey, RA2.PrivateKey);
            Assert.AreEqual(RA.RAParameters.g, RA2.RAParameters.g);
            Assert.AreEqual(RA.RAParameters.g1, RA2.RAParameters.g1);
            Assert.AreEqual(RA.RAParameters.gt, RA2.RAParameters.gt);
            Assert.AreEqual(RA.RAParameters.K, RA2.RAParameters.K);
            Assert.AreEqual(RA.RAParameters.uidh, RA2.RAParameters.uidh);
            Assert.AreEqual(RA.Accumulator, RA2.Accumulator);

        }
    }
}
