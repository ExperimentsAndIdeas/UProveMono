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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UProveCrypto;
using UProveCrypto.Math;
using UProveCrypto.PolyProof;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PolyProofUnitTests
{
    public static class StaticHelperClass
    {
        private static System.Text.UTF8Encoding _encoding = new System.Text.UTF8Encoding();
        private static byte [] _e0;
        private static byte []_e1;


        // will perform tests using several different parameter sets
        private static CryptoParameters[] _parameters;

        public static GroupElement[] GetGenerators(CryptoParameters cp, int replen)
        {
            GroupElement[] output = new GroupElement[replen];
            for (int i = 0; i < replen; ++i)
            {
                output[i] = cp.Generators[i];
            }
            return output;
        }




        public static FieldZqElement[] GenerateRandomExponents(int outputLength, int paramIndex)
        {
            FieldZqElement[] exponents = _parameters[paramIndex].FieldZq.GetRandomElements(outputLength, true);
            return exponents;
        }

        public static GroupElement[] GenerateRandomBases(int outputLength, int paramIndex)
        {
            FieldZqElement[] exponents = _parameters[paramIndex].FieldZq.GetRandomElements(outputLength, true);
            GroupElement g = _parameters[paramIndex].Generators[0];
            GroupElement[] bases = new GroupElement[outputLength];
            for (int i = 0; i < bases.Length; ++i)
            {
                bases[i] = g.Exponentiate(exponents[i]);
            }
            return bases;
        }

        public static DLRepOfGroupElement GenerateRandomDLRepOfGroupElement(int representationLength, int paramIndex)
        {
            GroupElement[] bases = StaticHelperClass.GenerateRandomBases(representationLength, paramIndex);
            FieldZqElement[] exponents = StaticHelperClass.GenerateRandomExponents(representationLength, paramIndex);
            return new DLRepOfGroupElement(bases, exponents, ParameterArray[paramIndex].Group);
        }

        public static DLRepOfGroupElement[] GenerateRandomDLRepOfGroupElementArray(int arrayLength, int representationLength, int paramIndex)
        {
            DLRepOfGroupElement[] output = new DLRepOfGroupElement[arrayLength];
            for (int i = 0; i < arrayLength; ++i)
            {
                output[i] = GenerateRandomDLRepOfGroupElement(representationLength, paramIndex);
            }
            return output;
        }

        public static GroupElement GenerateRandomValue(int paramIndex)
        {
            FieldZqElement exponent = _parameters[paramIndex].FieldZq.GetRandomElement(true);
            return _parameters[paramIndex].Generators[0].Exponentiate(exponent);

        }




        public static ParameterSet Parameters
        {
            get
            { 
//                return ECParameterSets.ParamSet_EC_BN254_V1; 
                return ECParameterSets.ParamSet_EC_P256_V1;
            }
        }

        public static CryptoParameters[] ParameterArray
        {
            get
            {
                return _parameters;
            }
        }


        static StaticHelperClass()
        {
            StaticHelperClass._e0 = new byte[] { (byte)0, (byte)0, (byte)0, (byte)0 };
            StaticHelperClass._e1 = new byte[] { (byte)1, (byte)1, (byte)1, (byte)1 };
            _parameters = new CryptoParameters[6];
            _parameters[0] = new CryptoParameters(ECParameterSets.ParamSet_EC_P256_V1, null);
            _parameters[1] = new CryptoParameters(ECParameterSets.ParamSet_EC_P384_V1, null);
            _parameters[2] = new CryptoParameters(ECParameterSets.ParamSet_EC_P521_V1, null);
            _parameters[3] = new CryptoParameters(SubgroupParameterSets.ParamSetL1024N160V1, null);
            _parameters[4] = new CryptoParameters(SubgroupParameterSets.ParamSetL2048N256V1, null);
            _parameters[5] = new CryptoParameters(SubgroupParameterSets.ParamSetL3072N256V1, null);
//            _parameters[6] = new CryptoParameters(ECParameterSets.ParamSet_EC_BN254_V1, null);

        }

        public static void AssertCorrectCryptoParameters(CryptoParameters expected, CryptoParameters actual)
        {
            Assert.IsTrue(actual.Verify(), "parameters should be valid.");
            Assert.AreEqual(expected.Group, actual.Group, "wrong group copied.");
            Assert.AreEqual(expected.FieldZq, actual.FieldZq, "wrong field.");
            Assert.AreEqual(expected.G, actual.G, "wrong generator G");
            Assert.AreEqual(expected.H, actual.H, "wrong generator H.");
            Assert.AreEqual(expected.HashFunctionName, actual.HashFunctionName, "wrong hash function.");
        }

        public static void AssertArraysAreEqual(object [] expected, object [] actual, string msg)
        {
            if((expected == null) && (actual == null))
            {
                return;
            }
            Assert.AreEqual(expected.Length, actual.Length, msg + ": different array lengths.");
            Assert.AreEqual(expected.GetType(), actual.GetType(), msg + ": different types.");
            for(int i=0; i<expected.Length; ++i)
            {
                Assert.AreEqual(expected[i], actual[i], msg + ": different element " + i);
            }
        }

        public static void AssertArraysAreEqual<T>(T [] expected, T [] actual, string msg)
        {
            if ((expected == null) && (actual == null))
            {
                return;
            }
            if (expected == null)
            {
                Assert.IsNull(actual);
            }
            if ((expected != null))
            {
                Assert.IsNotNull(actual);
            }

            Assert.AreEqual(expected.Length, actual.Length, msg + ": different array lengths.");
            for (int i = 0; i < expected.Length; ++i)
            {
                Assert.AreEqual(expected[i], actual[i], msg + ": different element " + i);
            }
        }

        public static void AssertProofParametersAreEqual(ProofParameters A, ProofParameters B, string msg)
        {
            Assert.AreEqual(A.ProverParameters, B.ProverParameters, msg + " Prover parameters");
            Assert.AreEqual(A.GetType(), B.GetType(), msg + " different classes");
            Assert.AreEqual(A.Group.GroupName, B.Group.GroupName, msg + " Groups");
            Assert.AreEqual(A.Group.Q, B.Group.Q, msg + " Q");
            StaticHelperClass.AssertArraysAreEqual(A.Generators, B.Generators, msg + " Generators");
            StaticHelperClass.AssertArraysAreEqual<GroupElement>(A.PublicValues, B.PublicValues, msg + " Public values");
            StaticHelperClass.AssertArraysAreEqual<DLRepOfGroupElement>(A.Witnesses, B.Witnesses, msg + " Witnesses");
        }


        public delegate void TryBodyDelegate();
        public static void AssertThrowsException(TryBodyDelegate statementBlock, Type expectedExceptionType, string message)
        {
            try
            {
                statementBlock();
            }
            catch (Exception e)
            {
                Assert.IsInstanceOfType(e, expectedExceptionType, "Wrong type of exception thrown.");
                return;
            }
            Assert.Fail("Should have thrown exception: " + message);
        }


        public static void GetUProveParameters(
            bool hashAttributes,
            out ProverPresentationProtocolParameters proverParams,
            out VerifierPresentationProtocolParameters verifierParams,
            byte [] customTokenInformation = null,
            byte [][] customAttributes = null,
            GroupElement [] customGenerators = null,
            byte [] customUidP = null
            )
        {
            // Issuer setup
            IssuerSetupParameters isp = new IssuerSetupParameters();
            if (customUidP == null)
            {
                isp.UidP = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            }
            else
            {
                isp.UidP = customUidP;
            }

            if (hashAttributes)
            {
                isp.E = _e1;
            }
            else
            {
                isp.E = _e0;
            }


            isp.S = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };

            if (customGenerators != null)
            {
                isp.ParameterSet = IssuerSetupParameters.GetDefaultParameterSet();
                PrivateObject customParams = new PrivateObject(isp.ParameterSet);
                customParams.SetField("G", customGenerators);
            }
            else
            {
                isp.UseRecommendedParameterSet = true;
            }

            IssuerKeyAndParameters ikap = isp.Generate();
            IssuerParameters ip = ikap.IssuerParameters;

            // Issuance
            byte[][] attributes = new byte[][] 
            { 
                _encoding.GetBytes("Attribute 1"), 
                _encoding.GetBytes("Attribute 2"), 
                _encoding.GetBytes("Attribute 3"), 
                _encoding.GetBytes("Attribute 4") 
            };
            if (customAttributes != null)
            {
                attributes = customAttributes;
            }

            byte[] tokenInformation = new byte[] { };
            if (customTokenInformation != null)
            {
                tokenInformation = customTokenInformation;
            }
            byte[] proverInformation = new byte[] { };
            int numberOfTokens = 1;

            IssuerProtocolParameters ipp = new IssuerProtocolParameters(ikap);
            ipp.Attributes = attributes;
            ipp.NumberOfTokens = numberOfTokens;
            ipp.TokenInformation = tokenInformation;
            Issuer issuer = ipp.CreateIssuer();
            FirstIssuanceMessage msg1 = issuer.GenerateFirstMessage();
            ProverProtocolParameters ppp = new ProverProtocolParameters(ip);
            ppp.Attributes = attributes;
            ppp.NumberOfTokens = numberOfTokens;
            ppp.TokenInformation = tokenInformation;
            ppp.ProverInformation = proverInformation;
//            ppp.BatchValidationSecurityLevel = -1;
            Prover prover = ppp.CreateProver();
            SecondIssuanceMessage msg2 = prover.GenerateSecondMessage(msg1);
            ThirdIssuanceMessage msg3 = issuer.GenerateThirdMessage(msg2);
            UProveKeyAndToken[] upkt = prover.GenerateTokens(msg3, true);

            // Pseudonym
            int[] disclosed = new int[0];
            int[] committed = new int[] { 1, 3, 4, 2 };
            byte[] message = _encoding.GetBytes("this is the presentation message, this can be a very long message");
            byte[] scope = _encoding.GetBytes("scope");

            //Generate prover
             proverParams = new ProverPresentationProtocolParameters(ip, disclosed, message, upkt[0], attributes);
            proverParams.Committed = committed;

            //Generate verifier
             verifierParams = new VerifierPresentationProtocolParameters(ip, disclosed, message, upkt[0].Token);
            verifierParams.Committed = committed;
        }
    }

}
