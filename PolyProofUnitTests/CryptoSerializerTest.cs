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
using UProveCrypto;
using UProveCrypto.Math;
using UProveCrypto.PolyProof;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Runtime.Serialization;

namespace PolyProofUnitTests
{
    [TestClass]
    public class CryptoSerializerTest
    {
        CryptoParameters crypto = StaticHelperClass.ParameterArray[0];
        int paramIndex = 0;

        [TestMethod]
        public void CSGroupElementArrayTest()
        {
            GroupElement[] input = StaticHelperClass.GenerateRandomBases(10, paramIndex);
            string[] output = CryptoSerializer.SerializeGroupElementArray(input, "blah");

            Assert.AreEqual(input.Length, output.Length, "serialized array length different.");

            GroupElement[] deserialized = CryptoSerializer.DeserializeGroupElementArray(output, "blah", crypto.Group);
            StaticHelperClass.AssertArraysAreEqual(input, deserialized, "deserialized");
        }

        [TestMethod]
        public void CSFieldZqElementArrayTest()
        {
            FieldZqElement[] input = StaticHelperClass.GenerateRandomExponents(10, paramIndex);
            string[] output = CryptoSerializer.SerializeFieldZqElementArray(input, "blah");

            Assert.AreEqual(input.Length, output.Length, "serialized array length different.");

            FieldZqElement[] deserialized = CryptoSerializer.DeserializeFieldZqElementArray(output, "blah", crypto.Group);
            StaticHelperClass.AssertArraysAreEqual(input, deserialized, "deserialized");
        }

        [TestMethod]
        public void CSGroupElementArrayTest2()
        {
            GroupElement[] input = StaticHelperClass.GenerateRandomBases(10, paramIndex);
            string[] serialized = CryptoSerializer.SerializeGroupElementArray(input, 3, 4, "blah");
            Assert.AreEqual(4, serialized.Length, "serialized array length");
            
            GroupElement[] output = CryptoSerializer.DeserializeGroupElementArray(serialized, 3, 10, "output", crypto.Group);
            GroupElement [] expectedOutput = new GroupElement[10]
            {
                null,
                null,
                null,
                input[3],
                input[4],
                input[5],
                input[6],
                null,
                null,
                null
            };
            StaticHelperClass.AssertArraysAreEqual(expectedOutput, output, "output");


            GroupElement[] output2 = CryptoSerializer.DeserializeGroupElementArray(serialized, 0, 10, "output2", crypto.Group);
            GroupElement[] expectedOutput2 = new GroupElement[10]
            {
                input[3],
                input[4],
                input[5],
                input[6],
                null,
                null,
                null,
                null,
                null,
                null
            };
            StaticHelperClass.AssertArraysAreEqual(expectedOutput2, output2, "output2");

            GroupElement[] output3 = CryptoSerializer.DeserializeGroupElementArray(serialized, 6, 10, "output3", crypto.Group);
            GroupElement[] expectedOutput3 = new GroupElement[10]
            {
                null,
                null,
                null,
                null,
                null,
                null,
                input[3],
                input[4],
                input[5],
                input[6]
            };
            StaticHelperClass.AssertArraysAreEqual(expectedOutput3, output3, "output3");

        }

        [TestMethod]
        public void CSFieldZqElementArrayTest2()
        {
            FieldZqElement[] input = StaticHelperClass.GenerateRandomExponents(10, paramIndex);
            string[] serialized = CryptoSerializer.SerializeFieldZqElementArray(input, 3, 4, "blah");
            Assert.AreEqual(4, serialized.Length, "serialized array length");

            FieldZqElement[] output = CryptoSerializer.DeserializeFieldZqElementArray(serialized, 3, 10, "output", crypto.Group);
            FieldZqElement[] expectedOutput = new FieldZqElement[10]
            {
                null,
                null,
                null,
                input[3],
                input[4],
                input[5],
                input[6],
                null,
                null,
                null
            };
            StaticHelperClass.AssertArraysAreEqual(expectedOutput, output, "output");


            FieldZqElement[] output2 = CryptoSerializer.DeserializeFieldZqElementArray(serialized, 0, 10, "output2", crypto.Group);
            FieldZqElement[] expectedOutput2 = new FieldZqElement[10]
            {
                input[3],
                input[4],
                input[5],
                input[6],
                null,
                null,
                null,
                null,
                null,
                null
            };
            StaticHelperClass.AssertArraysAreEqual(expectedOutput2, output2, "output2");

            FieldZqElement[] output3 = CryptoSerializer.DeserializeFieldZqElementArray(serialized, 6, 10, "output3", crypto.Group);
            FieldZqElement[] expectedOutput3 = new FieldZqElement[10]
            {
                null,
                null,
                null,
                null,
                null,
                null,
                input[3],
                input[4],
                input[5],
                input[6]
            };
            StaticHelperClass.AssertArraysAreEqual(expectedOutput3, output3, "output3");

        }

        [TestMethod]
        public void CSBadDeserializeGroupElementArrayTest()
        {
            GroupElement[] input = StaticHelperClass.GenerateRandomBases(10, paramIndex);
            string[] serialized = CryptoSerializer.SerializeGroupElementArray(input, 3, 4, "blah");
            Assert.AreEqual(4, serialized.Length, "serialized array length");

            StaticHelperClass.TryBodyDelegate negativeStartIndex = 
                new StaticHelperClass.TryBodyDelegate(
                    () => {             
                    GroupElement[] output = CryptoSerializer.DeserializeGroupElementArray(serialized, -1, 10, "blah", crypto.Group);
                    });
            StaticHelperClass.AssertThrowsException(negativeStartIndex,typeof(Exception), "negative start index");


            StaticHelperClass.TryBodyDelegate startIndexTooLarge = 
                new StaticHelperClass.TryBodyDelegate(
                    () => {             
                    GroupElement[] output = CryptoSerializer.DeserializeGroupElementArray(serialized, 8, 10, "blah", crypto.Group);
                    });
            StaticHelperClass.AssertThrowsException(startIndexTooLarge,typeof(Exception), "start index too large");

            StaticHelperClass.TryBodyDelegate startIndexWaytooLarge = 
                new StaticHelperClass.TryBodyDelegate(
                    () => {
                        GroupElement[] output = CryptoSerializer.DeserializeGroupElementArray(serialized, 11, 10, "blah", crypto.Group);
                    });
            StaticHelperClass.AssertThrowsException(startIndexWaytooLarge,typeof(Exception), "start index greater than output length ");
        }


        [TestMethod]
        public void CSBadDeserializeFieldZqElementArrayTest()
        {
            FieldZqElement[] input = StaticHelperClass.GenerateRandomExponents(10, paramIndex);
            string[] serialized = CryptoSerializer.SerializeFieldZqElementArray(input, 3, 4, "blah");
            Assert.AreEqual(4, serialized.Length, "serialized array length");

            StaticHelperClass.TryBodyDelegate negativeStartIndex =
                new StaticHelperClass.TryBodyDelegate(
                    () =>
                    {
                        FieldZqElement[] output = CryptoSerializer.DeserializeFieldZqElementArray(serialized, -1, 10, "blah", crypto.Group);
                    });
            StaticHelperClass.AssertThrowsException(negativeStartIndex, typeof(Exception), "negative start index");


            StaticHelperClass.TryBodyDelegate startIndexTooLarge =
                new StaticHelperClass.TryBodyDelegate(
                    () =>
                    {
                        FieldZqElement[] output = CryptoSerializer.DeserializeFieldZqElementArray(serialized, 8, 10, "blah", crypto.Group);
                    });
            StaticHelperClass.AssertThrowsException(startIndexTooLarge, typeof(Exception), "start index too large");

            StaticHelperClass.TryBodyDelegate startIndexWaytooLarge =
                new StaticHelperClass.TryBodyDelegate(
                    () =>
                    {
                        FieldZqElement[] output = CryptoSerializer.DeserializeFieldZqElementArray(serialized, 11, 10, "blah", crypto.Group);
                    });
            StaticHelperClass.AssertThrowsException(startIndexWaytooLarge, typeof(Exception), "start index greater than output length ");
        }



        [TestMethod]
        public void CSBadSerializeGroupElementArrayTest()
        {
            GroupElement[] input = StaticHelperClass.GenerateRandomBases(10, paramIndex);

            StaticHelperClass.TryBodyDelegate negativeLength = 
                new StaticHelperClass.TryBodyDelegate(
                    () => {             
                    string[] serialized = CryptoSerializer.SerializeGroupElementArray(input, 3, -1, "blah");
                    });
            StaticHelperClass.AssertThrowsException(negativeLength,typeof(Exception), "negative output length");

            // zero output length
            string[] output = CryptoSerializer.SerializeGroupElementArray(input, 3, 0, "blah");
            Assert.AreEqual(0, output.Length, "output.Length.");

            // output length too long
            StaticHelperClass.TryBodyDelegate outputLengthTooLarge =
        new StaticHelperClass.TryBodyDelegate(
            () =>
            {
                string[] serialized = CryptoSerializer.SerializeGroupElementArray(input, 3, 9, "blah");
            });
            StaticHelperClass.AssertThrowsException(outputLengthTooLarge, typeof(Exception), "Output length too large");

            // copy index negative
            StaticHelperClass.TryBodyDelegate startIndexNegative =
        new StaticHelperClass.TryBodyDelegate(
            () =>
            {
                string[] serialized = CryptoSerializer.SerializeGroupElementArray(input, -1, 4, "blah");
            });
            StaticHelperClass.AssertThrowsException(startIndexNegative, typeof(Exception), "Start index is negative.");
        }

        [TestMethod]
        public void CSBadSerializeFieldZqElementArrayTest()
        {
            FieldZqElement[] input = StaticHelperClass.GenerateRandomExponents(10, paramIndex);

            StaticHelperClass.TryBodyDelegate negativeLength =
                new StaticHelperClass.TryBodyDelegate(
                    () =>
                    {
                        string[] serialized = CryptoSerializer.SerializeFieldZqElementArray(input, 3, -1, "blah");
                    });
            StaticHelperClass.AssertThrowsException(negativeLength, typeof(Exception), "negative output length");

            // zero output length
            string[] output = CryptoSerializer.SerializeFieldZqElementArray(input, 3, 0, "blah");
            Assert.AreEqual(0, output.Length, "output.Length.");

            // output length too long
            StaticHelperClass.TryBodyDelegate outputLengthTooLarge =
        new StaticHelperClass.TryBodyDelegate(
            () =>
            {
                string[] serialized = CryptoSerializer.SerializeFieldZqElementArray(input, 3, 9, "blah");
            });
            StaticHelperClass.AssertThrowsException(outputLengthTooLarge, typeof(Exception), "Output length too large");

            // copy index negative
            StaticHelperClass.TryBodyDelegate startIndexNegative =
        new StaticHelperClass.TryBodyDelegate(
            () =>
            {
                string[] serialized = CryptoSerializer.SerializeFieldZqElementArray(input, -1, 4, "blah");
            });
            StaticHelperClass.AssertThrowsException(startIndexNegative, typeof(Exception), "Start index is negative.");

            string[] jsonStrings = new string[32];
            StaticHelperClass.AssertThrowsException(
                () => { CryptoSerializer.DeserializeFieldZqElementArray(jsonStrings, 0, 0, "field", null); },
                typeof(SerializationException),
                "Group is null.");
        
        }


        [TestMethod]
        public void CSDLRepTest()
        {
            DLRepOfGroupElement[] input = StaticHelperClass.GenerateRandomDLRepOfGroupElementArray(10, 7, this.paramIndex);
            for (int i = 0; i < input.Length; ++i)
            {
                Group group = input[i].Group;
                GroupElement [] bases = new GroupElement[input[i].RepresentationLength];
                FieldZqElement [] exponents = new FieldZqElement[input[i].RepresentationLength];
                for(int j=0; j<input[i].RepresentationLength; ++j)
                {
                    bases[j] = input[i].BaseAtIndex(j);
                    exponents[j] =input[i].ExponentAtIndex(j);
                }
                DLRepOfGroupElement expected = new DLRepOfGroupElement(bases, exponents, group);
                expected.Value = input[i].Value;
                
                input[i].IsGroupSerializable = false;
                input[i].AreBasesSerializable = false;
                string serializedNN = CryptoSerializer.Serialize<DLRepOfGroupElement>(input[i]);
                DLRepOfGroupElement outputNN = CryptoSerializer.Deserialize<DLRepOfGroupElement>(serializedNN, group, bases);
                Assert.AreEqual(input[i], outputNN, "outputNN");
                
                
                input[i].IsGroupSerializable = false;
                input[i].AreBasesSerializable = true;
                string serializedNB = CryptoSerializer.Serialize<DLRepOfGroupElement>(input[i]);
                DLRepOfGroupElement outputNB = CryptoSerializer.Deserialize<DLRepOfGroupElement>(serializedNB, group);
                Assert.AreEqual(input[i], outputNB, "outputNB");
                

                input[i].IsGroupSerializable = true;
                input[i].AreBasesSerializable = false;
                string serializedAN = CryptoSerializer.Serialize<DLRepOfGroupElement>(input[i]);
                DLRepOfGroupElement outputAN = CryptoSerializer.Deserialize<DLRepOfGroupElement>(serializedAN, null, bases);
                Assert.AreEqual(expected, outputAN, "outputAN");
                
                input[i].IsGroupSerializable = true;
                input[i].AreBasesSerializable = true;
                string serializedAB = CryptoSerializer.Serialize<DLRepOfGroupElement>(input[i]);
                DLRepOfGroupElement outputAB = CryptoSerializer.Deserialize<DLRepOfGroupElement>(serializedAB, null, null);
                Assert.AreEqual(input[i], outputAB, "outputAB");
            }
        }

        [TestMethod]
        public void CSClosedDLRepArrayTest()
        {
            int arrayLength = 10;
            DLRepOfGroupElement[] openInput = StaticHelperClass.GenerateRandomDLRepOfGroupElementArray(10, 7, this.paramIndex);
            ClosedDLRepOfGroupElement []  input = new ClosedDLRepOfGroupElement[arrayLength];
            for(int i=0; i<input.Length; ++i)
            {
                GroupElement[] bases = StaticHelperClass.GenerateRandomBases(10, this.paramIndex);
                GroupElement value = bases[0];
                input[i] = new ClosedDLRepOfGroupElement(bases, value, crypto.Group);
            }

            string[] serialized = CryptoSerializer.Serialize(input, false);
            ClosedDLRepOfGroupElement[] output = CryptoSerializer.Deserialize<ClosedDLRepOfGroupElement>(serialized, crypto.Group);
            StaticHelperClass.AssertArraysAreEqual(input, output, "no group");


            string[] serialized2 = CryptoSerializer.Serialize(input, true);
            ClosedDLRepOfGroupElement[] output2 = CryptoSerializer.Deserialize<ClosedDLRepOfGroupElement>(serialized, crypto.Group);
            StaticHelperClass.AssertArraysAreEqual(input, output2, "group");
        }


        [TestMethod]
        public void CSDLRepArrayTestNoGroup()
        {
            DLRepOfGroupElement[] input = StaticHelperClass.GenerateRandomDLRepOfGroupElementArray(10, 7, this.paramIndex);
            FieldZqElement [][] inputExponents = new FieldZqElement[10][];
            for(int dlIndex=0; dlIndex<10; ++dlIndex)
            {
                inputExponents[dlIndex] = new FieldZqElement[7];
                for(int exponentIndex=0; exponentIndex<7; ++exponentIndex)
                {
                    inputExponents[dlIndex][exponentIndex] = input[dlIndex].ExponentAtIndex(exponentIndex);
                }
            }


            string[] serializedTT =CryptoSerializer.Serialize(input, false,true);
            DLRepOfGroupElement[] outputTT = CryptoSerializer.Deserialize<DLRepOfGroupElement>(serializedTT, this.crypto.Group);
            StaticHelperClass.AssertArraysAreEqual(input, outputTT, "outputTT");

            string[] serializedNT = CryptoSerializer.Serialize(input, false, false);
            GroupElement[] newBases = StaticHelperClass.GenerateRandomBases(input[0].RepresentationLength, this.paramIndex);
            DLRepOfGroupElement[] outputNT = CryptoSerializer.Deserialize<DLRepOfGroupElement>(serializedNT, this.crypto.Group, newBases);
            Assert.AreEqual(input.Length, outputNT.Length, "outputNT.Length");
            for (int i = 0; i < outputNT.Length; ++i)
            {
                DLRepOfGroupElement expected = new DLRepOfGroupElement(newBases, inputExponents[i], this.crypto.Group);
                expected.Value = input[i].Value;
                Assert.AreEqual(expected, outputNT[i], "outputNT " + i);
            }

            FieldZqElement [] commitments = StaticHelperClass.GenerateRandomExponents(10, this.paramIndex);
            FieldZqElement [] openings = StaticHelperClass.GenerateRandomExponents(10, this.paramIndex);
            input = PedersenCommitment.GetCommitments(this.crypto, commitments, openings);

        }

        [TestMethod]
        public void CSDLRepArrayTestWithGroup()
        {
            DLRepOfGroupElement[] input = StaticHelperClass.GenerateRandomDLRepOfGroupElementArray(10, 7, this.paramIndex);
            FieldZqElement[][] inputExponents = new FieldZqElement[10][];
            for (int dlIndex = 0; dlIndex < 10; ++dlIndex)
            {
                inputExponents[dlIndex] = new FieldZqElement[7];
                for (int exponentIndex = 0; exponentIndex < 7; ++exponentIndex)
                {
                    inputExponents[dlIndex][exponentIndex] = input[dlIndex].ExponentAtIndex(exponentIndex);
                }
            }


            string[] serializedTT = CryptoSerializer.Serialize(input, true, true);
            DLRepOfGroupElement[] outputTT = CryptoSerializer.Deserialize<DLRepOfGroupElement>(serializedTT, null, null);
            StaticHelperClass.AssertArraysAreEqual(input, outputTT, "outputTT");

            string[] serializedNT = CryptoSerializer.Serialize(input, true, false);
            GroupElement[] newBases = StaticHelperClass.GenerateRandomBases(input[0].RepresentationLength, this.paramIndex);
            DLRepOfGroupElement[] outputNT = CryptoSerializer.Deserialize<DLRepOfGroupElement>(serializedNT, null, newBases);
            Assert.AreEqual(input.Length, outputNT.Length, "outputNT.Length");
            for (int i = 0; i < outputNT.Length; ++i)
            {
                DLRepOfGroupElement expected = new DLRepOfGroupElement(newBases, inputExponents[i], this.crypto.Group);
                expected.Value = input[i].Value;
                Assert.AreEqual(expected, outputNT[i], "outputNT " + i);
            }

            FieldZqElement[] commitments = StaticHelperClass.GenerateRandomExponents(10, this.paramIndex);
            FieldZqElement[] openings = StaticHelperClass.GenerateRandomExponents(10, this.paramIndex);
            input = PedersenCommitment.GetCommitments(this.crypto, commitments, openings);

        }

        [TestMethod]
        public void CSCheckDeserializationInputTest()
        {
            PrivateType serializer = new PrivateType(typeof(CryptoSerializer));

            object [] parameters = new object[]{new string[]{"b","a"}, 0, 0, "lalla", null};
            StaticHelperClass.AssertThrowsException(
                () => { serializer.InvokeStatic("CheckDeserializationInput", parameters); },
                typeof(SerializationException),
                "Group is null");
        }

        [TestMethod]
        public void CSGenericBadSerializationTest()
        {
            StaticHelperClass.AssertThrowsException(
                () => { CryptoSerializer.Deserialize<SetMembershipProof>("bad jsonString"); },
                typeof(SerializationException),
                "deserialization");

            ProverSetMembershipParameters prover = new ProverSetMembershipParameters(crypto);
            FieldZqElement [] memberSet = crypto.FieldZq.GetRandomElements(10,true);
            prover.setProverParameters(memberSet[0], memberSet);
            SetMembershipProof proof = new SetMembershipProof(prover);
            PrivateObject proofAccessor = new PrivateObject(proof);
            proofAccessor.SetProperty("c", null);

            StaticHelperClass.AssertThrowsException(
                () => { CryptoSerializer.Serialize<SetMembershipProof>(proof); },
                typeof(SerializationException),
                "serialization");
        }

        [TestMethod]
        public void CSChangeGroupTest()
        {
            CryptoParameters crypto1 = StaticHelperClass.ParameterArray[4];
            ProverSetMembershipParameters prover1 = new ProverSetMembershipParameters(crypto1);
            FieldZqElement[] memberSet1 = crypto1.FieldZq.GetRandomElements(10, true);
            prover1.setProverParameters(memberSet1[0], memberSet1);
            SetMembershipProof proof1 = new SetMembershipProof(prover1);
            
            string serialized1 = CryptoSerializer.Serialize<SetMembershipProof>(proof1);
            SetMembershipProof output1 = CryptoSerializer.Deserialize<SetMembershipProof>(serialized1);
            Assert.IsTrue(output1.Verify(prover1), "output1");

            CryptoParameters crypto2 = StaticHelperClass.ParameterArray[3];
            ProverSetMembershipParameters prover2 = new ProverSetMembershipParameters(crypto2);
            FieldZqElement[] memberSet2 = crypto2.FieldZq.GetRandomElements(10, true);
            prover2.setProverParameters(memberSet2[0], memberSet2);
            SetMembershipProof proof2 = new SetMembershipProof(prover2);

            string serialized2 = CryptoSerializer.Serialize<SetMembershipProof>(proof2);
            SetMembershipProof output2 = CryptoSerializer.Deserialize<SetMembershipProof>(serialized2);
            Assert.IsTrue(output2.Verify(prover2), "output2");


        }
    }


}
