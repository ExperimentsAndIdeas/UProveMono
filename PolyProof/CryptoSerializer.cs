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
using System.Runtime.Serialization;
using UProveCrypto.Math;
using UProveCrypto;

using System.IO;
using System.Runtime.Serialization.Json;
using System.Text;

namespace UProveCrypto.PolyProof
{
    public class CryptoSerializer
    {

        /// <summary>
        /// Serialize serializable types in namespace UProveCrypto.PolyProof.
        /// </summary>
        /// <typeparam name="T">input type</typeparam>
        /// <param name="obj">instance of serializable type</param>
        /// <returns>JSON string</returns>
        public static string Serialize<T>(T obj)
        {
            string result;

            try
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    DataContractJsonSerializer jsonSerializer =
                        new DataContractJsonSerializer(obj.GetType()); 

                    jsonSerializer.WriteObject(ms, obj);
                    ms.Position = 0;

                    StreamReader reader = new StreamReader(ms);
                    result = reader.ReadToEnd();
                }
            }
            catch (Exception e)
            {
                throw new SerializationException(obj.GetType().Name, e);
            }

            return result;
        }


        /// <summary>
        /// Serializes an array of IStatements.
        /// </summary>
        /// <param name="statements">statements</param>
        /// <param name="serializeGroup">If true, will serialize statements[0].Group.  If false, will  not serialize group.</param>
        /// <param name="serializeBases">If true, will serialize all bases.  If false, will not serialize bases.</param>
        /// <returns>Array of strings.  String[2i] is the serialized statement, String[2i+1] is the actual class name</returns>
        public static string[] Serialize(IStatement[] statements, bool serializeGroup=true, bool serializeBases=true)
        {
            string[] output = new string[statements.Length * 2];
            for (int i = 0; i < statements.Length; ++i)
            {
                if ((i == 0) && (serializeGroup))
                {
                    statements[i].IsGroupSerializable = true;
                }
                else
                {
                    statements[i].IsGroupSerializable = false;
                }

                if (serializeBases == true)
                {
                    statements[i].AreBasesSerializable = true;
                }
                else
                {
                    statements[i].AreBasesSerializable = false;
                }
                output[2*i] = CryptoSerializer.Serialize<IStatement>(statements[i]);
                output[2*i+1] = statements[i].GetType().FullName;
            }
            return output;
        }

        /// <summary>
        /// Deserializes serializable classes in namespace UProveCrypto.PolyProof.
        /// </summary>
        /// <typeparam name="T">Return type. Must be an object not an interface.</typeparam>
        /// <param name="jsonString">Input jsonString</param>
        /// <returns></returns>
        internal static T DeserializeInternal<T>(string jsonString) 
        {
            T result = default(T);

            UTF8Encoding encoding = new UTF8Encoding();
            byte[] bytes = encoding.GetBytes(jsonString);

            try
            {
                using (MemoryStream ms = new MemoryStream(bytes))
                {
                    DataContractJsonSerializer jsonSerializer =
                        new DataContractJsonSerializer(typeof(T));

                    result = (T)jsonSerializer.ReadObject(ms);
                }
            }
            catch (Exception exp)
            {
                throw new SerializationException(typeof(T).Name, exp);
            }

            return result;
        }


        /// <summary>
        /// Deserializes serializable classes in namespace UProveCrypto.PolyProof.
        /// </summary>
        /// <typeparam name="T">Return type.  Must be an object not an interface.</typeparam>
        /// <param name="jsonString">Input jsonString</param>
        /// <returns></returns>
        public static T Deserialize<T>(string jsonString)
        {
            T deserialized = DeserializeInternal<T>(jsonString);
            IGroupParameterizedSerialization igp = deserialized as IGroupParameterizedSerialization;
            if (igp != null)
            {
                try
                {
                    igp.FinishDeserializing();
                    deserialized = (T) igp;
                }
                catch (Exception e)
                {
                }
            }

            return deserialized;
        }

        /// <summary>
        /// Deserialize instance of a subclass of GroupParameterizedSerializer using a particular group is case
        /// the Group has not been serialized.
        /// </summary>
        /// <typeparam name="T">Subclass of GroupParameterizedSerializer. Fails on interfaces.</typeparam>
        /// <param name="jsonString">JSON string</param>
        /// <param name="group">Group. May be null.</param>
        /// <returns>Deserialized instance of subclass of GroupParameterizedSerializer </returns>
        public static T Deserialize<T>(string jsonString, Group group = null) where T : IGroupParameterizedSerialization
        {
            T result = DeserializeInternal<T>(jsonString);
            result.FinishDeserializing(group);
            return result;
        }


        /// <summary>
        /// Deserialize instance of a subclass of GroupParameterizedSerializer using a particular group is case
        /// the Group has not been serialized.
        /// </summary>
        /// <typeparam name="T">Subclass of EqualityProofWitnessStatement. Fails on interfaces.</typeparam>
        /// <param name="jsonString">JSON string</param>
        /// <param name="group">Group. May be null.</param>
        /// <returns>Deserialized instance of subclass of GroupParameterizedSerializer </returns>
        public static T Deserialize<T>(string jsonString, Group group = null, GroupElement[] bases = null) where T : EqualityProofWitnessStatement
        {
            T result = DeserializeInternal<T>(jsonString);
            result.FinishDeserializing(group, bases);
            return result;
        }

        /// <summary>
        /// Deserializes an array of jsonStrings representing an array of IStatements or an array of IWitnesses.
        /// The input to this method is the output of public static string[] Serialize(IStatement[] statements, bool serializeGroup=true, bool serializeBases=true).
        /// </summary>
        /// <typeparam name="T">class or interface that implements IStatement.  Usually IStatement or IWitness</typeparam>
        /// <param name="jsonStrings">jsonString[2i] is a serialized IStatement (or IWitness) while jsongString[2i+1] is the class name.</param>
        /// <param name="group">Group in case it was not serialized.  Default is null.</param>
        /// <param name="bases">Bases in case they were not serialized.  Default is null.</param>
        /// <returns></returns>
        public static T [] Deserialize<T>(string[] jsonStrings, Group group = null, GroupElement [] bases = null) where T:IStatement
        {
            if ((jsonStrings == null) || (jsonStrings.Length == 0))
            {
                return null;
            }

            T[] output = new T[jsonStrings.Length / 2];
            for (int i = 0; i < output.Length; ++i)
            {
                if (i > 0)
                {
                    group = output[0].Group;
                }

                output[i] = (T) DeserializeStatement(jsonStrings[i * 2 + 1], jsonStrings[i * 2]);
                output[i].FinishDeserializing(group, bases);
            }
            return output;
        }

        /// <summary>
        /// Names of classes that implement IStatement that can be deserialized by DeserializeStatement()
        /// </summary>
        private const string OpenUProveToken = "UProveCrypto.PolyProof.OpenUProveToken";
        private const string ClosedUProveToken = "UProveCrypto.PolyProof.ClosedUProveToken";
        private const string DLRepOfGroupElement = "UProveCrypto.PolyProof.DLRepOfGroupElement";
        private const string ClosedDLRepOfGroupElement = "UProveCrypto.PolyProof.ClosedDLRepOfGroupElement";
        private const string PedersenCommitment = "UProveCrypto.PolyProof.PedersenCommitment";
        private const string ClosedPedersenCommitment = "UProveCrypto.PolyProof.ClosedPedersenCommitment";

        /// <summary>
        /// Deserializes an IStatement.  
        /// </summary>
        /// <param name="typeFullName">Name of class that was serialized as jsonString.</param>
        /// <param name="jsonString">Serialized class.</param>
        /// <returns></returns>
        private static IStatement DeserializeStatement(string typeFullName, string jsonString) 
        {
            switch (typeFullName)
            {
                case OpenUProveToken: return  Deserialize<OpenUProveToken>(jsonString);
                case ClosedUProveToken: return  Deserialize<ClosedUProveToken>(jsonString);

                case DLRepOfGroupElement: return  Deserialize<DLRepOfGroupElement>(jsonString);
                case ClosedDLRepOfGroupElement: return  Deserialize<ClosedDLRepOfGroupElement>(jsonString);

                case PedersenCommitment: return  Deserialize<PedersenCommitment>(jsonString);
                case ClosedPedersenCommitment: return  Deserialize<ClosedPedersenCommitment>(jsonString);
            }
            throw new SerializationException("Could not deserialize unknown type: " + typeFullName);
        }

 
        #region Basic Serialize/Deserialize
        public static string Serialize(FieldZqElement value)
        {
            return value.ToBase64String();
        }

        public static string Serialize(GroupElement value)
        {
            return value.ToBase64String();
        }

        public static FieldZqElement DeserializeFieldZqElement(string json, Group group)
        {
            return json.ToFieldZqElement(group.FieldZq);
        }

        public static GroupElement DeserializeGroupElement(string json, Group group)
        {
            return json.ToGroupElement(group);
        }

        #endregion



        /// <summary>
        /// Checks whether the input to SerializeGroupElementArray/DeserializeGroupElementArray will throw an
        /// IndexOutOfRange exception.
        /// </summary>
        /// <param name="inputLength"></param>
        /// <param name="startIndex"></param>
        /// <param name="outputLength"></param>
        /// <param name="fieldName"></param>
        private static void CheckSerializationInput(int inputLength, int startIndex, int outputLength, string fieldName)
        {
            if (inputLength < startIndex + outputLength)
            {
                throw new SerializationException("Could not serialize " + fieldName + " because startIndex + outputLength exceeds length of array.");
            }
            if (startIndex < 0)
            {
                throw new SerializationException("Could not serialize " + fieldName + " because startIndex < 0.");
            }
        }

        /// <summary>
        /// Checks whether input to DeserializeFieldZqElementArray/DeserializeGroupElementArray will thorw
        /// an IndexOutOfRange exception.
        /// </summary>
        /// <param name="serializedGroupElements"></param>
        /// <param name="startIndex"></param>
        /// <param name="outputLength"></param>
        /// <param name="fieldName"></param>
        /// <param name="group"></param>
        private static void CheckDeserializationInput(string [] serializedGroupElements, int startIndex, int outputLength, string fieldName, Group group)
        {
            if (serializedGroupElements == null)
            {
                throw new SerializationException("Cannot deserialize " + fieldName + " because it is null.");
            }
            int inputLength = serializedGroupElements.Length;

            if (group == null)
            {
                throw new SerializationException("Cannot deserialize " + fieldName + ". Group must be deserialized first and not null.");
            }
            if (startIndex < 0)
            {
                throw new SerializationException("Cannot deserialize " + fieldName + ". StartIndex must be less than 0.");
            }
            if (outputLength - startIndex < inputLength)
            {
                throw new SerializationException("Cannot deserialize " + fieldName + ". Insufficient elements in array.");
            }
        }

        #region GroupElement


        /// <summary>
        /// Transforms subset an array of group elements into array of Base64 strings.
        /// </summary>
        /// <param name="groupElements">Input array.</param>
        /// <param name="startIndex">index in groupElements at which to start copying.</param>
        /// <param name="outputLength">number of GroupElements to copy.</param>
        /// <param name="fieldName">Added to exception messages.</param>
        /// <returns></returns>
        public static string[] SerializeGroupElementArray(GroupElement[] groupElements, int startIndex, int outputLength, string fieldName)
        {
            CheckSerializationInput(groupElements.Length, startIndex, outputLength, fieldName);
            string[] output = new string[outputLength];
            int copyLength = System.Math.Min(outputLength, groupElements.Length - startIndex);
            for (int i = 0; i < copyLength; ++i)
            {
                output[i] = groupElements[startIndex + i].ToBase64String();
            }
            return output;
        }
        /// <summary>
        /// Transforms entire GroupElement array into array of Base64 strings.
        /// </summary>
        /// <param name="groupElements">input array</param>
        /// <param name="fieldName">used in exception messages</param>
        /// <returns></returns>
        public static string[] SerializeGroupElementArray(GroupElement[] groupElements, string fieldName)
        {
            if (groupElements == null)
            {
                throw new SerializationException("Cannot serialize " + fieldName + " because it is null.");
            }
            return SerializeGroupElementArray(groupElements, 0, groupElements.Length, fieldName);
        }

        /// <summary>
        /// Deserializes array of serialized GroupElements. May add padding of null elements at
        /// the beginning and end of output array.
        /// </summary>
        /// <param name="serializedGroupElements">JSON strings.</param>
        /// <param name="startIndex">Index in output array into which to copy first element of serializedGroupElements.</param>
        /// <param name="outputLength">Length of output array.</param>
        /// <param name="fieldName">Added to Exception messages.</param>
        /// <param name="group">Needed for deserialization. May not be null.</param>
        /// <returns></returns>
        public static GroupElement[] DeserializeGroupElementArray(string[] serializedGroupElements, int startIndex, int outputLength, string fieldName, Group group)
        {
            CheckDeserializationInput(serializedGroupElements, startIndex, outputLength, fieldName, group);
            GroupElement[] output = new GroupElement[outputLength];
            int copyLength = System.Math.Min(outputLength, serializedGroupElements.Length);
            for (int i = 0; i < copyLength; ++i)
            {
                output[i + startIndex] = serializedGroupElements[i].ToGroupElement(group);
            }
            return output;
        }

        /// <summary>
        /// Deserializes entire array of group elements.
        /// </summary>
        /// <param name="serializedGroupElements">JSON strings</param>
        /// <param name="fieldName">Added to Exception messages.</param>
        /// <param name="group">May not be null.</param>
        /// <returns></returns>
        public static GroupElement[] DeserializeGroupElementArray(string[] serializedGroupElements, string fieldName, Group group)
        {
            if (serializedGroupElements == null)
            {
                throw new SerializationException("Cannot deserialize " + fieldName + " because it is null.");
            }

            return DeserializeGroupElementArray(serializedGroupElements, 0, serializedGroupElements.Length, fieldName, group);
        }

        #endregion

        #region FieldZqElement

        /// <summary>
        /// Serializes array of FieldZqElements.
        /// </summary>
        /// <param name="fieldZqElements">Input array.</param>
        /// <param name="startIndex">First fieldZqElement to serialize.</param>
        /// <param name="outputLength">Number of fieldZqElements to serialize.</param>
        /// <param name="fieldName">Name added to SerializationException message.</param>
        /// <returns></returns>
        public static string[] SerializeFieldZqElementArray(FieldZqElement[] fieldZqElements, int startIndex, int outputLength, string fieldName)
        {
            CheckSerializationInput(fieldZqElements.Length, startIndex, outputLength, fieldName);
            string[] output = new string[outputLength];
            int copyLength = System.Math.Min(outputLength, fieldZqElements.Length - startIndex);
            for (int i = 0; i < copyLength; ++i)
            {
                output[i] = fieldZqElements[startIndex + i].ToBase64String();
            }
            return output;
        }

        /// <summary>
        /// Serializes array of FieldZqElements.
        /// </summary>
        /// <param name="fieldZqElements">array.</param>
        /// <param name="fieldName">String added to SerializationException message.</param>
        /// <returns></returns>
        public static string[] SerializeFieldZqElementArray(FieldZqElement[] fieldZqElements, string fieldName)
        {
            return SerializeFieldZqElementArray(fieldZqElements, 0, fieldZqElements.Length, fieldName);
        }

        /// <summary>
        /// Deserializes array of JSON strings representing FieldZqElements.
        /// </summary>
        /// <param name="serializedFieldZqElements">JSON strings</param>
        /// <param name="startIndex">Index of first element in output array to put deserialized FieldZqElement.</param>
        /// <param name="outputLength">Length of output array.</param>
        /// <param name="fieldName">Name added to SerializationException message.</param>
        /// <param name="group">Groupic context, may not be null.</param>
        /// <returns></returns>
        public static FieldZqElement[] DeserializeFieldZqElementArray(string[] serializedFieldZqElements, int startIndex, int outputLength, string fieldName, Group group)
        {
            if (group == null)
            {
                throw new SerializationException("Cannot deserialize " + fieldName + " because group is null.");
            }

            CheckDeserializationInput(serializedFieldZqElements, startIndex, outputLength, fieldName, group);
            FieldZqElement[] output = new FieldZqElement[outputLength];
            int copyLength = System.Math.Min(output.Length - startIndex, serializedFieldZqElements.Length);
            for (int i = 0; i < copyLength; ++i)
            {
                output[i + startIndex] = serializedFieldZqElements[i].ToFieldZqElement(group.FieldZq);
            }
            return output;
        }

        /// <summary>
        /// Deserializes array of JSON strings into FieldZqElements.
        /// </summary>
        /// <param name="serializedFieldZqElements">input JSON strings.</param>
        /// <param name="fieldName">Name added to SerializationException message.</param>
        /// <param name="group">Groupic context, may not be null.</param>
        /// <returns></returns>
        public static FieldZqElement[] DeserializeFieldZqElementArray(string[] serializedFieldZqElements, string fieldName, Group group)
        {
            return DeserializeFieldZqElementArray(serializedFieldZqElements, 0, serializedFieldZqElements.Length, fieldName, group);
        }


        #endregion
    }
}
