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
    public class EqualityMapTest
    {
        public static string DefaultHashFunction = CryptoParameters.DefaultHashFunctionName;


        [TestMethod]
        public void MapAddCountTest()
        {
            PrettyName alpha0 = new PrettyName("alpha", 0);
            PrettyName alpha1 = new PrettyName("alpha", 1);
            PrettyName beta0 = new PrettyName("beta", 0);
            PrettyName beta1 = new PrettyName("beta", 1);

            EqualityMap map = new EqualityMap();
            Assert.AreEqual(0, map.CountEquationAndExponentIndices);
            Assert.AreEqual(0, map.CountPrettyName);

            // add double indexes with pretty name alpha0
            int expectedDoubleIndexCount = 0;
            for (int dlIndex = 0; dlIndex < 10; ++dlIndex)
            {
                for (int baseIndex = 0; baseIndex < 10; ++baseIndex)
                {
                    map.Add(alpha0, new DoubleIndex(dlIndex, baseIndex));
                    ++expectedDoubleIndexCount;
                    Assert.AreEqual(expectedDoubleIndexCount, map.CountEquationAndExponentIndices);
                    Assert.AreEqual(1, map.CountPrettyName);
                }
            }

            // add double indexes with pretty name alpha1
            map.Add(alpha1, new DoubleIndex(10, 0));
            ++expectedDoubleIndexCount;
            Assert.AreEqual(expectedDoubleIndexCount, map.CountEquationAndExponentIndices);
            Assert.AreEqual(2, map.CountPrettyName);

            map.Add(beta0, new DoubleIndex(10, 1));
            ++expectedDoubleIndexCount;
            Assert.AreEqual(expectedDoubleIndexCount, map.CountEquationAndExponentIndices);
            Assert.AreEqual(3, map.CountPrettyName);

            map.Add(beta1, new DoubleIndex(10, 2));
            ++expectedDoubleIndexCount;
            Assert.AreEqual(expectedDoubleIndexCount, map.CountEquationAndExponentIndices);
            Assert.AreEqual(4, map.CountPrettyName);
        }

        [TestMethod]
        public void TryRetrieveIntIndexTest()
        {
            PrettyName alpha0 = new PrettyName("alpha", 0);
            PrettyName alpha1 = new PrettyName("alpha", 1);

            EqualityMap map = new EqualityMap();
            Assert.AreEqual(0, map.CountEquationAndExponentIndices);
            Assert.AreEqual(0, map.CountPrettyName);

            // add double indexes with pretty name alpha0 and alpha1
            int actualIndex;
            for (int dlIndex = 0; dlIndex < 10; ++dlIndex)
            {
                for (int baseIndex = 0; baseIndex < 10; ++baseIndex)
                {
                    DoubleIndex di0 = new DoubleIndex(dlIndex, baseIndex);
                    DoubleIndex di0clone = new DoubleIndex(dlIndex, baseIndex);
                    map.Add(alpha0, di0);
                    Assert.IsTrue(map.TryRetrieveIntIndex(di0, out actualIndex));
                    Assert.AreEqual(0, actualIndex, "could not retrieve correct index for di0");
                    Assert.IsTrue(map.TryRetrieveIntIndex(di0clone, out actualIndex));
                    Assert.AreEqual(0, actualIndex, "could not retrieve correct index for di0clone");

                    DoubleIndex di1 = new DoubleIndex(dlIndex + 100, baseIndex);
                    DoubleIndex di1clone = new DoubleIndex(dlIndex + 100, baseIndex);
                    map.Add(alpha1, di1);
                    Assert.IsTrue(map.TryRetrieveIntIndex(di1, out actualIndex));
                    Assert.AreEqual(1, actualIndex, "could not retrieve correct index for di1clone");
                    Assert.IsTrue(map.TryRetrieveIntIndex(di1clone, out actualIndex));
                    Assert.AreEqual(1, actualIndex, "could not retrieve correct index for di1clone");
                }
            }
        }

        [TestMethod]
        public void EQMapHashTest()
        {
            EqualityMap map1 = new EqualityMap();
            map1.Add(new PrettyName("alpha", 0), new DoubleIndex(0, 0));
            map1.Add(new PrettyName("alpha", 2), new DoubleIndex(1, 1));
            byte[] hash1 = map1.Hash(CryptoParameters.DefaultHashFunctionName);
            byte[] hash2 = map1.Hash(CryptoParameters.DefaultHashFunctionName);
            StaticHelperClass.AssertArraysAreEqual<byte>(hash1, hash2, "hash1 vs hash2 of same map.");

            EqualityMap map2 = new EqualityMap();
            map2.Add(new PrettyName("alpha", 2), new DoubleIndex(1, 1));
            map2.Add(new PrettyName("alpha", 0), new DoubleIndex(0, 0));
            byte[] hash3 = map2.Hash(CryptoParameters.DefaultHashFunctionName);
            byte[] hash4 = map2.Hash(CryptoParameters.DefaultHashFunctionName);

            StaticHelperClass.AssertArraysAreEqual<byte>(hash3, hash4, "hash3 vs hash4 of same map.");
            StaticHelperClass.AssertArraysAreEqual<byte>(hash1, hash3, "hash1 vs hash3.");
        }

        [TestMethod]
        public void EQMapHashTest2()
        {
            int length = 20;
            // create equality map
            EqualityMap map = new EqualityMap();
            for (int i = 0; i < length; ++i)
            {
                map.Add(
                    new PrettyName("chi", i),
                    new DoubleIndex(i, 0)
                );

                map.Add(
                    new PrettyName("chi", i),
                    new DoubleIndex(length + i, 0)
                );
            }

            byte[] hash1 = map.Hash(DefaultHashFunction);
            byte[] hash2 = map.Hash(DefaultHashFunction);
            StaticHelperClass.AssertArraysAreEqual<byte>(hash1, hash2, "same map hash.");

            // create parallel map in different order
            EqualityMap map2 = new EqualityMap();
            for (int i = 0; i < length; ++i)
            {
                map2.Add(
                    new PrettyName("chi", i),
                    new DoubleIndex(length + i, 0)
                );
            }
            for (int i = 0; i < length; ++i)
            {

                map2.Add(
                        new PrettyName("chi", i),
                         new DoubleIndex(i, 0)
                         );
            }
            byte[] hash3 = map2.Hash(DefaultHashFunction);
            byte[] hash4 = map2.Hash(DefaultHashFunction);
            StaticHelperClass.AssertArraysAreEqual<byte>(hash3, hash4, "map2 hash.");
            StaticHelperClass.AssertArraysAreEqual<byte>(hash1, hash3, "hash1 vs hash 3.");


        }

        [TestMethod]
        public void EQMapSerializationTest()
        {
            int length = 20;
            // create equality map
            EqualityMap map = new EqualityMap();
            for (int i = 0; i < length; ++i)
            {
                map.Add(
                    new PrettyName("chi", i),
                    new DoubleIndex(i, 0)
                );

                map.Add(
                    new PrettyName("chi", i),
                    new DoubleIndex(length + i, 0)
                );

                map.Add(
    new PrettyName("delta", i),
    new DoubleIndex(i, 4)
);

                map.Add(
                    new PrettyName("delta", i),
                    new DoubleIndex(length + i, 4)
                );
            }

            string jsonString = CryptoSerializer.Serialize<EqualityMap>(map);
            EqualityMap deserializedMap = CryptoSerializer.Deserialize<EqualityMap>(jsonString);

            byte[] hash1 = map.Hash(DefaultHashFunction);
            byte[] hash2 = deserializedMap.Hash(DefaultHashFunction);
            StaticHelperClass.AssertArraysAreEqual(hash1, hash2, "hash of deserialized map.");

        }


    }
}
