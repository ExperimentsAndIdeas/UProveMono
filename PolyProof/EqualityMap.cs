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
using UProveCrypto;
using UProveCrypto.Math;
using System.Runtime.Serialization;

namespace UProveCrypto.PolyProof
{
    [DataContract]
    public class EqualityMap
    {
        [DataMember]
        private SortedDictionary<PrettyName, List<DoubleIndex>> PrettyNameToDoubleIndexList;
        private Dictionary<DoubleIndex, PrettyName> DoubleIndextToPrettyName;

        /// <summary>
        /// Creates an empty equality map object.  Use Add() method
        /// to create equality relations.
        /// </summary>
        public EqualityMap()
        {
            PrettyNameToDoubleIndexList = new SortedDictionary<PrettyName, List<DoubleIndex>>();
            DoubleIndextToPrettyName = new Dictionary<DoubleIndex, PrettyName>();
        }

        /// <summary>
        /// Creates an equality map object for two simple discrete log equations:
        /// A = g[0]^x[0] * .... * g[n-1]^x[n-1]
        /// B = h[0]^y[0] * .... * h[m-1]^y[m-1]
        /// Proof will show that x[exponentIndexForEquation0] = y[exponentIndexForEquation1]
        /// </summary>
        /// <param name="exponentIndexForEquation0">Index for exponent in equation 0</param>
        /// <param name="exponentIndexForEquation1">Index for exponent in equation 1</param>
        public EqualityMap(int exponentIndexForEquation0, int exponentIndexForEquation1)
        {
            // create equality map
            PrettyNameToDoubleIndexList = new SortedDictionary<PrettyName, List<DoubleIndex>>();
            DoubleIndextToPrettyName = new Dictionary<DoubleIndex, PrettyName>();
            //PrettyNameToIntMap = new Dictionary<PrettyName, int>();

            // add indices
            PrettyName alpha = new PrettyName("alpha", 0);
            DoubleIndex di0 = new DoubleIndex(0, exponentIndexForEquation0);
            DoubleIndex di1 = new DoubleIndex(1, exponentIndexForEquation1);
            this.Add(alpha, di0);
            this.Add(alpha, di1);
        }

        /// <summary>
        /// Adds an entry into the equality  map object.  Let
        /// A[i] = product(g[j] ^ x[j])
        /// be the list of of DL equations.
        /// Associates the indicated exponent x[j] from equation i with
        /// prettyName.  EqualityProof will show that all exponents
        /// with the same prettyName are equal.
        /// </summary>
        /// <param name="prettyName">Pretty name.</param>
        /// <param name="equationAndExponentIndex">Indicates equation i, exponent j.</param>
        public void Add(PrettyName prettyName, DoubleIndex equationAndExponentIndex)
        {
            List<DoubleIndex> diList;
            if (PrettyNameToDoubleIndexList.TryGetValue(prettyName, out diList))
            {
                if (! diList.Contains(equationAndExponentIndex))
                {
                    diList.Add(equationAndExponentIndex);
                }
            }
            else
            {
                diList = new List<DoubleIndex>();
                diList.Add(equationAndExponentIndex);
                PrettyNameToDoubleIndexList.Add(prettyName, diList);
            }

            if (!DoubleIndextToPrettyName.ContainsKey(equationAndExponentIndex))
            {
                DoubleIndextToPrettyName.Add(equationAndExponentIndex, prettyName);
            }
        }

        /// <summary>
        /// Tries to retrieve the pretty name associated with equationAndExponentIndex
        /// </summary>
        /// <param name="equationAndExponentIndex"></param>
        /// <param name="name">Output parameter.</param>
        /// <returns>True on success, false if equationAndExponentIndex has no associated pretty name.</returns>
        public bool TryGetPrettyName(DoubleIndex equationAndExponentIndex, out PrettyName name)
        {
            bool success = DoubleIndextToPrettyName.TryGetValue(equationAndExponentIndex, out name);
            return success;
        }

        /// <summary>
        /// Retrieves the pretty name associated with the equationAndExponentIndex, 
        /// and returns the index of the pretty name.  (Pretty names are numbered
        /// consecutively, from 0; this numbering is unique to each EqualityMap object,
        /// based on the order in which the pretty names were added).
        /// </summary>
        /// <param name="equationAndExponentIndex"></param>
        /// <param name="index"></param>
        /// <returns></returns>
        public bool TryRetrieveIntIndex(DoubleIndex equationAndExponentIndex, out int index)
        {
            PrettyName pretty;
            bool success =DoubleIndextToPrettyName.TryGetValue(equationAndExponentIndex, out pretty);
            if (success)
            {
                index = 0;
                foreach (PrettyName key in PrettyNameToDoubleIndexList.Keys)
                {
                    if (pretty.Equals(key))
                    {
                        return true;
                    }
                    ++index;
                }
            }
            index = 0;
            return false;
        }

        /// <summary>
        /// Total number of unique entries for ExquationAndExponentIndex.
        /// </summary>
        public int CountEquationAndExponentIndices
        {
            get
            {
                return this.DoubleIndextToPrettyName.Count;
            }
        }

        /// <summary>
        /// Total number of unique pretty name objects.
        /// </summary>
        public int CountPrettyName
        {
            get
            {
                return this.PrettyNameToDoubleIndexList.Count;
            }
        }

        /// <summary>
        /// Returns a hash of this EqualityMap. Sorts all
        /// entries in the map into canonical order, so output is
        /// identical regardless of what order entries were added to EqualityMap.
        /// </summary>
        /// <param name="hashFunctionName">Name of hash function to use.  See CryptoParameters for details.</param>
        /// <returns>Hash of this EqualityMap.</returns>
        public byte[] Hash(string hashFunctionName)
        {
            System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();

            HashFunction hash = new HashFunction(hashFunctionName);
            foreach (KeyValuePair<PrettyName, List<DoubleIndex>> entry in PrettyNameToDoubleIndexList)
            {
                PrettyName prettyName = entry.Key;
                hash.Hash(encoding.GetBytes(prettyName.Name));
                hash.Hash(prettyName.Subscript);
                List<DoubleIndex> sortedDoubleIndices = entry.Value;
                sortedDoubleIndices.Sort();
                foreach (DoubleIndex doubleIndex in sortedDoubleIndices)
                {
                    hash.Hash(doubleIndex.EquationIndex);
                    hash.Hash(doubleIndex.ExponentIndex);
                }
            }
            return hash.Digest;
        }

        /// <summary>
        /// Checks if this EqualityMap is valid with respect to the given list of
        /// open equations.  Checks that all DoubleIndex entries are within range
        /// (EquationIndex and ExponentIndex).  Also checks that the exponents this
        /// EqualityMap says are equal are identical in openEquations.
        /// </summary>
        /// <param name="witnesses"></param>
        /// <returns>True or false.</returns>
        public bool Verify(IWitness[] witnesses)
        {
            if (!Verify((IStatement[])witnesses))
            {
                return false;
            }

            if ((witnesses == null) || (witnesses.Length == 0))
            {
                return true;
            }

            Dictionary<PrettyName, FieldZqElement> exponentMap = new Dictionary<PrettyName, FieldZqElement>();

            foreach (KeyValuePair<PrettyName, List<DoubleIndex>> entry in PrettyNameToDoubleIndexList)
            {
                PrettyName prettyName = entry.Key;
                List<DoubleIndex> doubleIndexList = entry.Value;
                foreach (DoubleIndex doubleIndex in doubleIndexList)
                {
                    FieldZqElement exponent;
                    if (exponentMap.TryGetValue(prettyName, out exponent))
                    {
                        if (exponent != witnesses[doubleIndex.EquationIndex].ExponentAtIndex(doubleIndex.ExponentIndex))
                        {
                            return false;
                        }
                    }
                    else
                    {
                        exponentMap.Add(prettyName, witnesses[doubleIndex.EquationIndex].ExponentAtIndex(doubleIndex.ExponentIndex));
                    }
                }
            }
            return true;
        }

        /// <summary>
        /// Checks that this EqualityMap is valid for the given list of
        /// closed equations.  Returns false if any of the DoubleIndex entries
        /// in the map are out of range in terms of EquationIndex or ExponentIndex.
        /// </summary>
        /// <param name="statements">array of closed equations.</param>
        /// <returns>True if this EqualityMap is valid with respect to the array of closed equations.</returns>
        public bool Verify(IStatement[] statements)
        {
            foreach(List<DoubleIndex> diList in PrettyNameToDoubleIndexList.Values)
            {
                foreach(DoubleIndex doubleIndex in diList)
                {
                    if (doubleIndex.EquationIndex >= statements.Length)
                    {
                        return false;
                    }
                    if (doubleIndex.ExponentIndex >= statements[doubleIndex.EquationIndex].RepresentationLength)
                    {
                        return false;
                    }
                }
            }
            return true;
        }


        #region Serialization


        [OnDeserialized]
        public void OnDeserialized(StreamingContext context)
        {
            SortedDictionary<PrettyName, List<DoubleIndex>> savedMap = this.PrettyNameToDoubleIndexList;

            PrettyNameToDoubleIndexList = new SortedDictionary<PrettyName, List<DoubleIndex>>();
            DoubleIndextToPrettyName = new Dictionary<DoubleIndex, PrettyName>();

            foreach (KeyValuePair<PrettyName, List<DoubleIndex>> entry in savedMap)
            {
                PrettyName name = entry.Key;
                foreach (DoubleIndex doubleIndex in entry.Value)
                {
                    this.Add(name, doubleIndex);
                }
            }
        }

        #endregion


    }

    [DataContract]
    public class DoubleIndex : IComparable
    {
        [DataMember(Name="EqIndex")]
        public int EquationIndex { get; set; }

        [DataMember(Name="ExpIndex")]
        public int ExponentIndex { get; set; }

        public DoubleIndex(int equationIndex, int exponentIndex)
        {
            this.EquationIndex = equationIndex;
            this.ExponentIndex = exponentIndex;
        }

        public override bool Equals(object obj)
        {
            if(obj.GetType() != this.GetType())
            {
                return false;
            }

            DoubleIndex di = (DoubleIndex) obj;
            if((this.EquationIndex != di.EquationIndex)
                || (this.ExponentIndex != di.ExponentIndex))
            {
                return false;
            }
            return true;
        }

        public override int GetHashCode()
        {
            return this.ExponentIndex * 1000 + this.EquationIndex;
        }

        int IComparable.CompareTo(object obj)
        {
            if (obj.GetType() != typeof(DoubleIndex))
            {
                return 1;
            }


            DoubleIndex thing = (DoubleIndex)obj;
            if (this.EquationIndex < thing.EquationIndex)
            {
                return -1;
            }
            else if (this.EquationIndex > thing.EquationIndex)
            {
                return 1;
            }
            else
            {
                if(this.ExponentIndex > thing.EquationIndex)
                {
                    return 1;
                }
                if( this.ExponentIndex < thing.ExponentIndex)
                {
                    return -1;
                }
            }
            return 0;
        }
    }



    [DataContract]
    public class PrettyName : IComparable 
    {
        [DataMember(Name="Name")]
        public String Name { get; set; }

        [DataMember(Name="Subscript")]
        public int Subscript { get; set; }

        public PrettyName(String name, int subscript)
        {
            this.Name = name;
            this.Subscript = subscript;
        }

        public override bool Equals(object obj)
        {
            if (obj.GetType() != this.GetType())
            {
                return false;
            }

            PrettyName gi = (PrettyName) obj;
            if (this.Subscript != gi.Subscript)
            {
                return false;
            }
            return this.Name.Equals(gi.Name);
        }

        public override int GetHashCode()
        {
            return this.Name.GetHashCode() + this.Subscript;
        }

        int IComparable.CompareTo(object obj)
        {
            if (obj.GetType() != typeof(PrettyName))
            {
                return 1;
            }

            PrettyName thing = (PrettyName) obj;
            int comparison = this.Name.CompareTo(thing.Name);
            if (comparison == 0)
            {
                if (this.Subscript < thing.Subscript)
                {
                    return -1;
                }
                else if(this.Subscript > thing.Subscript)
                {
                    return 1;
                }
                return 0;

            }
            return comparison;
        }
    }
}
