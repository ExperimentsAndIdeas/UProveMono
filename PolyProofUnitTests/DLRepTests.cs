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
    public class DLRepTests
    {
        // will perform tests using several different parameter sets
        private static CryptoParameters[] _parameters;

        public static GroupElement[] GetGenerators(CryptoParameters cp, int replen)
        {
            GroupElement [] output = new GroupElement[replen];
            for(int i=0; i<replen; ++i)
            {
                output[i]=cp.Generators[i];
            }
            return output;
        }



        /// <summary>
        /// Initializes _parameterSet with 7 different sets using EC and Subgroup parameters.
        /// Computes associated _fieldZq for each set.
        /// </summary>
        /// <param name="context"></param>
        [ClassInitialize]
        public static void Init(TestContext context)
        {
            // create parameter sets
            _parameters = StaticHelperClass.ParameterArray;
        }

        /// <summary>
        /// Tests the DLRepOfGroupElement(bases, exponents) constructor.
        /// Creates random representations and checks if the bases and exponents
        /// are copied correctly, and that the value is computed correctly.
        /// </summary>
        [TestMethod]
        public void BaseConstructorTest()
        {
            for(int paramIndex =0; paramIndex<_parameters.Length; ++paramIndex)
            {
                int replen = 10;
                FieldZqElement[] exponents = StaticHelperClass.GenerateRandomExponents(replen, paramIndex);
                GroupElement[] bases = StaticHelperClass.GenerateRandomBases(replen, paramIndex);
                DLRepOfGroupElement dl = new DLRepOfGroupElement(bases, exponents, _parameters[paramIndex].Group);

                // check bases and exponents got copied correctly, and value was computed correctly
                GroupElement expectedValue= _parameters[paramIndex].Group.Identity;
                for (int baseIndex = 0; baseIndex < bases.Length; ++baseIndex)
                {
                    Assert.AreEqual(bases[baseIndex], dl.BaseAtIndex(baseIndex), "Wrong base");
                    Assert.AreEqual(exponents[baseIndex], dl.ExponentAtIndex(baseIndex), "wrong exponent");
                    expectedValue = expectedValue * bases[baseIndex].Exponentiate(exponents[baseIndex]);
                }
                Assert.AreEqual(expectedValue, dl.Value, "Incorrect Value");
            }
        }

        /// <summary>
        /// Tests the null constructor.
        /// </summary>
        [TestMethod]
        public void NullConstructorTest()
        {
            DLRepOfGroupElement dl = new DLRepOfGroupElement();
            Assert.AreEqual(0, dl.RepresentationLength, "dl.representation length should be 0");
            Assert.IsNull(dl.Value, "Value is null");
        }

        /// <summary>
        /// Tests the constructor DLRepOfGroupElement(exponents, parameterSet)
        /// using random exponents.
        /// </summary>
        [TestMethod]
        public void ParameterSetConstructorTest()
        {
            int replength = 6;
            for (int paramIndex = 0; paramIndex < _parameters.Length; ++paramIndex)
            {
                FieldZqElement[] exponents = StaticHelperClass.GenerateRandomExponents(replength, paramIndex);
                GroupElement[] expectedBases = GetGenerators(_parameters[paramIndex],replength);
                DLRepOfGroupElement dl = new DLRepOfGroupElement(exponents, _parameters[paramIndex]);

                // check bases and exponents got copied correctly, and value was computed correctly
                GroupElement expectedValue = _parameters[paramIndex].Group.Identity;
                for (int baseIndex = 0; baseIndex < replength; ++baseIndex)
                {
                    GroupElement expectedBase = expectedBases[baseIndex];
                    Assert.AreEqual(expectedBase, dl.BaseAtIndex(baseIndex), "Wrong base");
                    Assert.AreEqual(exponents[baseIndex], dl.ExponentAtIndex(baseIndex), "wrong exponent");
                    expectedValue = expectedValue * expectedBase.Exponentiate(exponents[baseIndex]);
                }
                Assert.AreEqual(expectedValue, dl.Value, "Incorrect Value");
            }
        }

        /// <summary>
        /// Makes sure the constructors do the same thing as ComputeValue
        /// </summary>
        [TestMethod]
        public void ComputeValueTest()
        {
            for (int paramIndex = 0; paramIndex < _parameters.Length; ++paramIndex)
            {
                int replen = 10;
                FieldZqElement[] exponents = StaticHelperClass.GenerateRandomExponents(replen, paramIndex);
                GroupElement[] bases = StaticHelperClass.GenerateRandomBases(replen, paramIndex);

                DLRepOfGroupElement actualDL = new DLRepOfGroupElement(bases, exponents, _parameters[paramIndex].Group);
                GroupElement expectedValue = _parameters[paramIndex].Group.MultiExponentiate(bases, exponents);

                Assert.AreEqual(expectedValue, actualDL.Value, "different values");
                Assert.AreEqual(exponents.Length, actualDL.RepresentationLength, "different number of bases");
                for (int baseIndex = 0; baseIndex < actualDL.RepresentationLength; ++baseIndex)
                {
                    Assert.AreEqual(bases[baseIndex], actualDL.BaseAtIndex(baseIndex), "different base");
                    Assert.AreEqual(exponents[baseIndex], actualDL.ExponentAtIndex(baseIndex), "different exponent");
                }
            }
        }

        /// <summary>
        /// Makes sure the constructors do the same thing as ComputeValue
        /// </summary>
        [TestMethod]
        public void ComputeValueWithParametersTest()
        {
            for (int paramIndex = 0; paramIndex < _parameters.Length; ++paramIndex)
            {
                int replen = 14;
                GroupElement[] bases =GetGenerators( _parameters[paramIndex],replen);
                FieldZqElement[] exponents = StaticHelperClass.GenerateRandomExponents(replen, paramIndex);

                DLRepOfGroupElement actualDL = new DLRepOfGroupElement(exponents, _parameters[paramIndex]);
                DLRepOfGroupElement expectedDL = new DLRepOfGroupElement(bases, exponents, _parameters[paramIndex].Group);

                //compare expectedDL and actualDL
                Assert.IsNotNull(actualDL, "actualDl null");
                Assert.IsNotNull(expectedDL, "expectedDL null");
                Assert.AreEqual(expectedDL.Value, actualDL.Value, "different values");
                Assert.AreEqual(expectedDL.RepresentationLength, actualDL.RepresentationLength, "different number of bases");

                Assert.AreEqual(expectedDL, actualDL, "ComputeValue created different objects");
            }
        }

        [TestMethod]
        public void BaseAndExponentAtIndexTest()
        {
            int replen = 25;
            for (int paramIndex = 0; paramIndex < _parameters.Length; ++paramIndex)
            {
                GroupElement [] bases = StaticHelperClass.GenerateRandomBases(replen,paramIndex);
                FieldZqElement [] exponents = StaticHelperClass.GenerateRandomExponents(replen,paramIndex);
                DLRepOfGroupElement dl = new DLRepOfGroupElement(bases, exponents, _parameters[paramIndex].Group);

                Assert.AreEqual(replen, dl.RepresentationLength, "incorrect representation length");
                for (int i = 0; i < replen; ++i)
                {
                    Assert.AreEqual(bases[i], dl.BaseAtIndex(i), "wrong base");
                    Assert.AreEqual(exponents[i], dl.ExponentAtIndex(i), "wrong exponent");
                }
            }
        }


        [TestMethod]
        public void EqualsTest()
        {
            int replen1 = 12;
            int replen2 = 11;
            for (int paramIndex = 0; paramIndex < _parameters.Length; ++paramIndex)
            {
                FieldZqElement[] exponents1 = _parameters[paramIndex].FieldZq.GetRandomElements(replen1, true);
                FieldZqElement[] exponents2 = _parameters[paramIndex].FieldZq.GetRandomElements(replen2, true);
                DLRepOfGroupElement dl1 = new DLRepOfGroupElement(exponents1, _parameters[paramIndex]);
                DLRepOfGroupElement dl2 = new DLRepOfGroupElement(exponents1, _parameters[paramIndex]);
                DLRepOfGroupElement dl3 = new DLRepOfGroupElement(exponents2, _parameters[paramIndex]);

                Assert.IsTrue(dl1.Equals(dl1), "dl1 should equal itself");
                Assert.IsTrue(dl1.Equals(dl2), "dl1 should equal dl2");
                Assert.IsTrue(dl2.Equals(dl1), "dl2 should equal dl1");
                Assert.IsFalse(dl2.Equals(dl3), "dl2 should not equal dl3");
                Assert.IsFalse(dl3.Equals(dl2), "dl3 should not equal dl2");
                Assert.IsFalse(dl3.Equals(exponents1[0]), "wrong class input!");

                DLRepOfGroupElement nulldl = new DLRepOfGroupElement();
                Assert.IsFalse(dl1.Equals(nulldl), "not equal to nulldl");
                Assert.IsFalse(nulldl.Equals(dl1), "nulldl not equal to dl1");
                Assert.IsTrue(nulldl.Equals(nulldl), "nulldl equal to itself");

                GroupElement[] bases = new GroupElement[replen1];
                for (int i = 0; i < bases.Length; ++i)
                {
                    bases[i] = _parameters[paramIndex].Group.Identity;
                }
                DLRepOfGroupElement dl4 = new DLRepOfGroupElement(bases, exponents1, _parameters[paramIndex].Group);
                Assert.IsFalse(dl1.Equals(dl4), "dl1 and dl4 different due to bases");
                Assert.IsFalse(dl4.Equals(dl1), "dl4 and dl1 different due to bases");
            }
        }

        [TestMethod]
        public void AreBasesEqualTest()
        {
            for (int i = 0; i < _parameters.Length; ++i)
            {
                GroupElement[] bases0 = GetGenerators(_parameters[i], 6);
                GroupElement[] bases1 = GetGenerators(_parameters[i], 6);
                bases1[5] = bases1[5] * bases1[3];


                ClosedDLRepOfGroupElement dl = new ClosedDLRepOfGroupElement(bases0, _parameters[i].G, _parameters[i].Group);
                ClosedDLRepOfGroupElement dlWithSameBases = new ClosedDLRepOfGroupElement(bases0, _parameters[i].H, _parameters[i].Group);
                ClosedDLRepOfGroupElement dlWithDiffBases = new ClosedDLRepOfGroupElement(bases1, _parameters[i].G, _parameters[i].Group);

                Assert.IsTrue(dl.AreBasesEqual(dlWithSameBases), "bases are the same.");
                Assert.IsTrue(dlWithSameBases.AreBasesEqual(dl), "bases are same");
                Assert.IsFalse(dl.AreBasesEqual(dlWithDiffBases), "bases are different.");

                ClosedDLRepOfGroupElement[] sameBaseArray = new ClosedDLRepOfGroupElement[4] { dlWithSameBases, dl, dlWithSameBases, dl };
                ClosedDLRepOfGroupElement[] diffBaseArray = new ClosedDLRepOfGroupElement[4] { dl, dl, dl, dlWithDiffBases };
                Assert.IsTrue(ClosedDLRepOfGroupElement.AreBasesEqual(sameBaseArray), "Bases are identical");
                Assert.IsFalse(ClosedDLRepOfGroupElement.AreBasesEqual(diffBaseArray), "Bases are different");
            }
        }

        [TestMethod]
        public void ExponentiateTest()
        {
            for(int paramIndex=0; paramIndex<_parameters.Length; ++paramIndex)
            {
                GroupElement[] bases = StaticHelperClass.GenerateRandomBases(8, paramIndex);
                FieldZqElement[] exponent = StaticHelperClass.GenerateRandomExponents(1, paramIndex);
                GroupElement value = _parameters[paramIndex].Generators[0];
                ClosedDLRepOfGroupElement udl = new ClosedDLRepOfGroupElement(bases, value, _parameters[paramIndex].Group);

                ClosedDLRepOfGroupElement actualUDL = udl.Exponentiate(exponent[0]);
                Assert.IsTrue(actualUDL.AreBasesEqual(udl), "bases should be the same.");
                Assert.AreEqual(udl.Value.Exponentiate(exponent[0]), actualUDL.Value, "Value computed incorrectly.");
            }
        }

        [TestMethod]
        public void TryStrictMultiplySucceedTest()
        {
            for (int paramIndex = 0; paramIndex < _parameters.Length; ++paramIndex)
            {
                GroupElement[] bases = StaticHelperClass.GenerateRandomBases(8, paramIndex);

                GroupElement[] values = StaticHelperClass.GenerateRandomBases(10, paramIndex);
                ClosedDLRepOfGroupElement[] udlArray = new ClosedDLRepOfGroupElement[values.Length];
                GroupElement expectedProduct = _parameters[paramIndex].Group.Identity;
                for (int udlIndex = 0; udlIndex < udlArray.Length; ++udlIndex)
                {
                    udlArray[udlIndex] = new ClosedDLRepOfGroupElement(bases, values[udlIndex], _parameters[paramIndex].Group);
                    expectedProduct *= values[udlIndex];
                }

                ClosedDLRepOfGroupElement product;
                bool success = ClosedDLRepOfGroupElement.TryStrictMultiply(udlArray, out product);
                Assert.IsTrue(success, "TryStrictMultiply should have succeeded.");
                Assert.IsNotNull(product, "product should be set to not null");
                Assert.IsTrue(product.AreBasesEqual(udlArray[0]), "product should have same bases as other members of udlArray");
                Assert.AreEqual(expectedProduct, product.Value, "Product of values computed incorrectly");
            }
        }

        [TestMethod]
        public void ClosedDLTryStrictMultiplyFailTest()
        {
            int paramIndex = 0;
            GroupElement[] bases = StaticHelperClass.GenerateRandomBases(8, paramIndex);

            GroupElement[] values = StaticHelperClass.GenerateRandomBases(10, paramIndex);
            ClosedDLRepOfGroupElement[] udlArray = new ClosedDLRepOfGroupElement[values.Length];
            GroupElement expectedProduct = _parameters[paramIndex].Group.Identity;
            for (int udlIndex = 0; udlIndex < udlArray.Length; ++udlIndex)
            {
                udlArray[udlIndex] = new ClosedDLRepOfGroupElement(bases, values[udlIndex], _parameters[paramIndex].Group);
                expectedProduct *= values[udlIndex];
            }

            // fail with different bases
            GroupElement[] wrongBases = StaticHelperClass.GenerateRandomBases(8, paramIndex);
            udlArray[udlArray.Length - 1] = new ClosedDLRepOfGroupElement(wrongBases, values[0], _parameters[paramIndex].Group);
            ClosedDLRepOfGroupElement product = udlArray[0];
            bool success = ClosedDLRepOfGroupElement.TryStrictMultiply(udlArray, out product);
            Assert.IsFalse(success, "TryStrictMultiply should have failed");
            Assert.IsNull(product, "product should be set to null");

            success = ClosedDLRepOfGroupElement.TryStrictMultiply(null, out product);
            Assert.IsFalse(success, "TryStrictMultiply should have failed");
            Assert.IsNull(product, "product should be set to null");

            wrongBases = StaticHelperClass.GenerateRandomBases(18, paramIndex);
            udlArray[udlArray.Length - 1] = new ClosedDLRepOfGroupElement(wrongBases, values[0], _parameters[paramIndex].Group);
            product = udlArray[0];
            success = ClosedDLRepOfGroupElement.TryStrictMultiply(udlArray, out product);
            Assert.IsFalse(success, "TryStrictMultiply should have failed");
            Assert.IsNull(product, "product should be set to null");


        }

        [TestMethod]
        public void TryStrictMultiplyWithExponentsTest()
        {
            bool success;
            DLRepOfGroupElement [] dlArray;
            FieldZqElement [] exponents;
            DLRepOfGroupElement product;

            for (int paramIndex = 0; paramIndex < _parameters.Length; ++paramIndex)
            {
                dlArray = new DLRepOfGroupElement[128];
                GroupElement expectedProduct = _parameters[paramIndex].Group.Identity;
                for (int i = 0; i < dlArray.Length; ++i)
                {
                    exponents = StaticHelperClass.GenerateRandomExponents(5, paramIndex);
                    dlArray[i] = new DLRepOfGroupElement(exponents, _parameters[paramIndex]);
                    expectedProduct *= dlArray[i].Value;
                }

                DLRepOfGroupElement actualProduct;
                success = DLRepOfGroupElement.TryStrictMultiply(dlArray, out actualProduct);
                Assert.IsTrue(success, "TryStrictMultiply should have succeeded.");
                Assert.IsNotNull(actualProduct, "actualProduct should be set to a value.");
                Assert.IsTrue(actualProduct.AreBasesEqual(dlArray[0]), "Bases should be the same.");
                Assert.AreEqual(expectedProduct, actualProduct.Value, "Value computed incorrectly.");
            }

            // fail on null/ empty input
            DLRepOfGroupElement dl;
            success = DLRepOfGroupElement.TryStrictMultiply(null, out dl);
            Assert.IsFalse(success);

            DLRepOfGroupElement[] emptyArray = new DLRepOfGroupElement[0];
            success = DLRepOfGroupElement.TryStrictMultiply(emptyArray, out dl);
            Assert.IsFalse(success);

            // fail because bases are different
            dlArray = new DLRepOfGroupElement[5];
            GroupElement [] bases =  StaticHelperClass.GenerateRandomBases(8,5);
            for(int dlIndex=0; dlIndex<dlArray.Length-1; ++ dlIndex)
            {
                exponents = StaticHelperClass.GenerateRandomExponents(8,5);
                dlArray[dlIndex] = new DLRepOfGroupElement(bases, exponents, _parameters[5].Group);
            }
            GroupElement [] badBases = StaticHelperClass.GenerateRandomBases(8, 5);
            exponents = StaticHelperClass.GenerateRandomExponents(8,5); 
            dlArray[dlArray.Length-1] = new DLRepOfGroupElement(badBases, exponents, _parameters[5].Group);
            success = DLRepOfGroupElement.TryStrictMultiply(dlArray, out product);
            Assert.IsFalse(success, "should fail since one of the elements in dlArray has different bases.");
        }

        [TestMethod]
        public void OpenClosedPairTest()
        {
            GroupElement[] bases = StaticHelperClass.GenerateRandomBases(4, 0);
            GroupElement[] goodBases = StaticHelperClass.GenerateRandomBases(4,0);
            FieldZqElement[] exponents = StaticHelperClass.GenerateRandomExponents(4, 0);

            DLRepOfGroupElement dl = new DLRepOfGroupElement(goodBases, exponents, _parameters[0].Group);
            IStatement expectedClosed = dl.GetStatement();
            ClosedDLRepOfGroupElement badClosed = new ClosedDLRepOfGroupElement(bases, dl.Value, dl.Group);

            Assert.IsTrue(DLRepOfGroupElement.IsValidOpenClosedPair(dl, expectedClosed), "should be valid.");
            Assert.IsFalse(DLRepOfGroupElement.IsValidOpenClosedPair(dl, badClosed), "bad pair due to wrong bases.");

            badClosed = new ClosedDLRepOfGroupElement(goodBases, bases[0], _parameters[0].Group);
            Assert.IsFalse(DLRepOfGroupElement.IsValidOpenClosedPair(dl, badClosed), "bad pair due to wrong value.");


            Assert.IsFalse(DLRepOfGroupElement.IsValidOpenClosedPair(null, null), "should fail on null input.");
        }

        [TestMethod]
        public void DLRepEqualBadBaseTest()
        {
            GroupElement[] bases = StaticHelperClass.GenerateRandomBases(8, 0);
            FieldZqElement[] exponents = StaticHelperClass.GenerateRandomExponents(8, 0);

            DLRepOfGroupElement dl = new DLRepOfGroupElement(bases, exponents, _parameters[0].Group);
            bases[7]=bases[3];
            DLRepOfGroupElement badDL = new DLRepOfGroupElement(bases, exponents, _parameters[0].Group);
            Assert.IsFalse(dl.Equals(badDL), "should fail due to bad base.");
            Assert.IsFalse(badDL.Equals(dl), "should fail due to bad base.");

        }

        [TestMethod]
        public void DLRepEqualsWrongExponentTest()
        {
            GroupElement[] bases = StaticHelperClass.GenerateRandomBases(8, 0);
            FieldZqElement[] exponents = StaticHelperClass.GenerateRandomExponents(8, 0);

            DLRepOfGroupElement dl = new DLRepOfGroupElement(bases, exponents, _parameters[0].Group);
            exponents[7] = exponents[2];
            DLRepOfGroupElement badDL = new DLRepOfGroupElement(bases, exponents, _parameters[0].Group);
            Assert.IsFalse(dl.Equals(badDL), "should fail due to bad exponent.");
            Assert.IsFalse(badDL.Equals(dl), "should fail due to bad exponent.");
        }

        [TestMethod]
        public void DLAreBasesEqualBadInputTest()
        {
            GroupElement[] bases1 = StaticHelperClass.GenerateRandomBases(10, 0);
            ClosedDLRepOfGroupElement udl = new ClosedDLRepOfGroupElement(bases1, bases1[0], _parameters[0].Group);

            GroupElement[] bases2 = new GroupElement[9];
            for (int i = 0; i < bases2.Length; ++i)
            {
                bases2[i] = bases1[i];
            }
            ClosedDLRepOfGroupElement udlbad = new ClosedDLRepOfGroupElement(bases2, bases1[0], _parameters[0].Group);
            Assert.IsFalse(udl.AreBasesEqual(udlbad), "different bases due to different rep length");
            Assert.IsFalse(udlbad.AreBasesEqual(udl), "different bases due to different rep length");


            udlbad = null;
            Assert.IsFalse(udl.AreBasesEqual(udlbad), "different bases since udlbad is null");


            // testing on array input
            ClosedDLRepOfGroupElement[] udlArray = null;
            Assert.IsFalse(ClosedDLRepOfGroupElement.AreBasesEqual(udlArray), "fails on null input.");
           
            udlArray = new ClosedDLRepOfGroupElement[0];
            Assert.IsFalse(ClosedDLRepOfGroupElement.AreBasesEqual(udlArray), "fails on empty array input.");

            udlArray = new ClosedDLRepOfGroupElement[1] { udl };
            Assert.IsTrue(ClosedDLRepOfGroupElement.AreBasesEqual(udlArray), "array of one element should pass");

        }

        [TestMethod]
        public void ClosedDLHashCodeTest()
        {
            GroupElement[] bases = StaticHelperClass.GenerateRandomBases(11, 0);
            GroupElement value = bases[1];
            ClosedDLRepOfGroupElement udl = new ClosedDLRepOfGroupElement(bases, value, _parameters[0].Group);
            Assert.AreEqual(bases[0].GetHashCode(), udl.GetHashCode(), "should retrieve hashcode from bases[0]");

            bases = new GroupElement[0];
            udl = new ClosedDLRepOfGroupElement(bases, value, _parameters[0].Group);
            Assert.AreEqual(0, udl.GetHashCode(), "hash code for 0 replength closed dl rep should be 0");
        }

        [TestMethod]
        public void ComputeValueBadInputTest()
        {
            GroupElement[] bases = StaticHelperClass.GenerateRandomBases(8, 1);
            FieldZqElement [] exponents =StaticHelperClass.GenerateRandomExponents(9,1);

            bool threwException = false;
            try
            {
                DLRepOfGroupElement dl = new DLRepOfGroupElement(bases, exponents, _parameters[1].Group);
            }
            catch (Exception)
            {
                threwException = true;
            }
            Assert.IsTrue(threwException, "should throw exception when given 8 bases and 9 exponents.");


           exponents = StaticHelperClass.GenerateRandomExponents(8, 1);

            threwException = false;
            try
            {
                DLRepOfGroupElement dl = new DLRepOfGroupElement(null,exponents,_parameters[1].Group);
            }
            catch (Exception)
            {
                threwException = true;
            }
            Assert.IsTrue(threwException, "should throw exception on null bases");

            threwException = false;
            try
            {
                DLRepOfGroupElement dl = new DLRepOfGroupElement(bases, null, _parameters[1].Group);
            }
            catch (Exception)
            {
                threwException = true;
            }
            Assert.IsTrue(threwException, "should throw exception on null exponents");

            threwException = false;
            try
            {
                DLRepOfGroupElement dl = new DLRepOfGroupElement(bases, exponents,null);
            }
            catch (Exception)
            {
                threwException = true;
            }
            Assert.IsTrue(threwException, "should throw exception on null group");

            threwException = false;
            try
            {
                DLRepOfGroupElement dl = new DLRepOfGroupElement(bases, exponents, _parameters[4].Group);
            }
            catch (Exception)
            {
                threwException = true;
            }
            Assert.IsTrue(threwException, "should throw exception on wrong Group");

            threwException = false;
            bases = new GroupElement[0];
            exponents = new FieldZqElement[0];
            try
            {
                DLRepOfGroupElement dl = new DLRepOfGroupElement(bases, exponents, _parameters[4].Group);
            }
            catch (Exception)
            {
                threwException = true;
            }
            Assert.IsTrue(threwException, "should throw exception on zero length bases and exponents arrays");


        }

        [TestMethod]
        public void DLGetHashCodeTest()
        {
            FieldZqElement[] exponents = StaticHelperClass.GenerateRandomExponents(8, 1);
            DLRepOfGroupElement dl = new DLRepOfGroupElement(exponents,_parameters[1]);
            Assert.AreEqual(dl.BaseAtIndex(0).GetHashCode(),dl.GetHashCode());
        }
        
    }
}
