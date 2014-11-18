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
using System.Runtime.Serialization;

namespace UProveCrypto.PolyProof
{
    /// <summary>
    /// Represents a GroupElement whose discrete log representation
    /// in terms of a series of bases is unknown.
    /// </summary>
    [DataContract]
    public class ClosedDLRepOfGroupElement : EqualityProofWitnessStatement, IStatement
    {
        /// <summary>
        /// ClosedDLRepOfGroupElement is never a witness.
        /// </summary>
        public override bool IsWitness 
        { 
            get 
            { 
                return false; 
            } 
        }

        /// <summary>
        /// Create null instance of class
        /// </summary>
        public ClosedDLRepOfGroupElement()
        {
            this.Group = null;
            this.Bases = null;
            this.Value = null;
            this.Exponents = null;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="bases"></param>
        /// <param name="value"></param>
        /// <param name="group"></param>
        public ClosedDLRepOfGroupElement(GroupElement[] bases, GroupElement value, Group group)
        {
            this.Bases = bases;
            this.Value = value;
            this.Group = group;
            this.Exponents = null;
        }

        /// <summary>
        /// Returns true if all objects in the input array contain the same
        /// bases, in the same order.
        /// </summary>
        /// <param name="udl"></param>
        /// <returns></returns>
        public static bool AreBasesEqual(ClosedDLRepOfGroupElement[] udl)
        {
            if((udl == null) || (udl.Length < 1))
            {
                return false;
            }
            for (int index = 1; index < udl.Length; ++index)
            {
                if (!udl[0].AreBasesEqual(udl[index]))
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Creates a new ClosedDLRepOfGroupElement object whose value is the product of all
        /// the values in the input array. Fails if any of the objects in dlarray have
        /// different bases.
        /// </summary>
        /// <param name="dlarray">Array of objects to multiply</param>
        /// <param name="product">Outputs product of dlarray</param>
        /// <returns>true on success, false on failure.</returns>
        public static bool TryStrictMultiply(ClosedDLRepOfGroupElement [] dlarray, out ClosedDLRepOfGroupElement product)
        {
            // make sure there is at least one element in the array
            if ((dlarray == null) || (dlarray.Length < 1))
            {
                product = null;
                return false;
            }

            //copy bases
            GroupElement [] newBases = new GroupElement[dlarray[0].RepresentationLength];
            for (int baseIndex = 0; baseIndex < dlarray[0].RepresentationLength; ++baseIndex)
            {
                newBases[baseIndex] = dlarray[0].BaseAtIndex(baseIndex);
                for (int dlIndex = 1; dlIndex < dlarray.Length; ++dlIndex)
                {
                    if(dlarray[dlIndex].BaseAtIndex(baseIndex) != dlarray[0].BaseAtIndex(baseIndex))
                    {
                        product = null;
                        return false;
                    }
                }
            }

            // compute product
            GroupElement value = dlarray[0].Group.Identity;
            for (int dlIndex = 0; dlIndex < dlarray.Length; ++dlIndex)
            {
                value *= dlarray[dlIndex].Value;
            }

            product= new ClosedDLRepOfGroupElement(newBases, value, dlarray[0].Group);
            return true;
        }

        /// <summary>
        /// Raises the Value of this object by scalar.
        /// </summary>
        /// <param name="scalar"></param>
        /// <returns></returns>
        public ClosedDLRepOfGroupElement Exponentiate(FieldZqElement scalar)
        {
            GroupElement[] newBases = new GroupElement[this.RepresentationLength];

            for (int baseIndex = 0; baseIndex < this.RepresentationLength; ++baseIndex)
            {
                newBases[baseIndex] = this.Bases[baseIndex];
            }
            return new ClosedDLRepOfGroupElement(Bases, this.Value.Exponentiate(scalar), this.Group);
        }



        /// <summary>
        /// Returns a hash code computed using the first base. If the representation
        /// length is 0, returns 0;
        /// </summary>
        /// <returns>Hashcode</returns>
        public override int GetHashCode()
        {
            if (this.RepresentationLength == 0)
            {
                return 0;
            }
            return this.Bases[0].GetHashCode();
        }

        /// <summary>
        /// Verifies that the response to the Sigma protocol, given the commitment and challenge.
        /// </summary>
        /// <param name="commitment">Commitment generated during ComputeCommitment</param>
        /// <param name="challenge">Random challenge</param>
        /// <param name="response">Response generated by ComputeResponse</param>
        /// <returns></returns>
        public override bool Verify(GroupElement commitment, FieldZqElement challenge, FieldZqElement[] response)
        {
            GroupElement[] vBases = new GroupElement[this.RepresentationLength + 1];
            FieldZqElement[] vExponents = new FieldZqElement[this.RepresentationLength + 1];
            for (int i = 0; i < this.RepresentationLength; ++i)
            {
                vBases[i] = this.Bases[i];
                vExponents[i] = response[i];
            }
            vBases[this.RepresentationLength] = this.Value;
            vExponents[this.RepresentationLength] = challenge;

            GroupElement rightSide = this.Group.MultiExponentiate(vBases, vExponents);
            return (commitment == rightSide);
        }

        /// <summary>
        /// Returns the bases raised to randomData.
        /// </summary>
        /// <param name="randomData"></param>
        /// <returns></returns>
        public override GroupElement ComputeCommitment(FieldZqElement[] randomData)
        {
            return this.Group.MultiExponentiate(this.Bases, randomData);
        }

        /// <summary>
        /// Computes the response for the equality proof for the specified exponent, given the challenge and random data.
        /// </summary>
        /// <param name="challenge">Challange</param>
        /// <param name="randomData">Random data used during ComputeCommitment</param>
        /// <param name="exponentIndex">Specifies an exponent</param>
        /// <returns></returns>
        public override FieldZqElement ComputeResponse(FieldZqElement challenge, FieldZqElement randomData, int exponentIndex)
        {
            FieldZqElement response = randomData - (challenge * this.ExponentAtIndex(exponentIndex));
            return response;
        }

        /// <summary>
        /// Returns a ClosedDLRepOfGroupElement.
        /// </summary>
        /// <returns></returns>
        public override IStatement GetStatement()
        {
            return new ClosedDLRepOfGroupElement(this.Bases, this.Value, this.Group);
        }

    }

    /// <summary>
    /// Represents a GroupElement whose discrete logarithmn representation
    /// in terms of a sequence of bases is known.
    /// 
    /// Contains an array of bases, an array of exponents, and Value such that
    /// Value = this.Group.MultiExponentiate(bases, exponents)
    /// </summary>
    [DataContract]
    public class DLRepOfGroupElement : ClosedDLRepOfGroupElement, IWitness
    {
        /// <summary>
        /// DLRepOfGroupElement is always a witness.
        /// </summary>
        public override bool IsWitness
        {
            get
            {
                return true;
            }
        }
        #region Constructors

        /// <summary>
        /// Creates an empty object where bases, exponents, value and group
        /// are null.  If this constructor is used, it should be immediately
        /// followed by a call to ComputeValue().
        /// </summary>
        public DLRepOfGroupElement()
            : base()
        {
            this.Exponents = null;
        }


        /// <summary>
        /// Constructs an instance of DLRepOfGroupElement.  Throws exception on null arguments or
        /// if bases and exponents are of different lengths.
        /// </summary>
        /// <param name="bases">Array of bases.</param>
        /// <param name="exponents">Array of exponents.</param>
        /// <param name="group">All bases should be members of this group.</param>
        public DLRepOfGroupElement(GroupElement[] bases, FieldZqElement[] exponents, Group group)
        {
            this.Group = group;
            this.ComputeValue(bases, exponents);
        }

        /// <summary>
        /// Constructs an instance of DLRepOfGroupElement. Throws an exception on null argument.
        /// Uses parameters.Generators to choose bases. If there are not enough bases in parameters,
        /// or on null input, throws exception.
        /// </summary>
        /// <param name="exponents">Array of exponents.</param>
        /// <param name="parameterSet">Parameter set to choose bases.</param>
        public DLRepOfGroupElement(FieldZqElement[] exponents, CryptoParameters parameters)
        {
            this.Group = parameters.Group;
            GroupElement[] bases = new GroupElement[exponents.Length];
            for (int i = 0; i < bases.Length; ++i)
            {
                bases[i] = parameters.Generators[i];
            }
            this.ComputeValue(bases,exponents);
        }

        #endregion


        /// <summary>
        /// Takes an array of bases and exponents and computes the multi-exponentiation:
        /// value = product_{i in 0...bases.Length-1} bases[i]^exponents[i].
        /// Throws exception on invalid inpute: null input, zero length array, different length arrays.
        /// </summary>
        /// <param name="bases">Array of bases</param>
        /// <param name="exponents">Array of exponents.</param>
        internal void ComputeValue(GroupElement[] bases, FieldZqElement[] exponents)
        {
            //Validate input
            if ((bases == null) || (exponents == null))
            {
                throw new ArgumentNullException("Constructor expects arguments to not be null");
            }
            if (bases.Length != exponents.Length)
            {
                throw new Exception("Constructor expects two arrays of equal length");
            }
            if ((bases.Length == 0) || (exponents.Length == 0))
            {
                throw new Exception("Constructor expects arrays to have at least one element");
            }

            // copy bases, exponents
            this.Bases = bases;
            this.Exponents = exponents;

            // computes value
            this.Value = this.Group.MultiExponentiate(bases, exponents);

        }

        /// <summary>
        /// Compares openDL and closedDL.  Returns true if they have the same bases and value.
        /// </summary>
        /// <param name="openDL"></param>
        /// <param name="closedDL"></param>
        /// <returns></returns>
        public static bool IsValidOpenClosedPair(IWitness openDL, IStatement closedDL)
        {
            if ((openDL == null)
                || (closedDL == null))
            {
                return false;
            }
            if ((!openDL.IsWitness) || (closedDL.IsWitness))
            {
                return false;
            }

            IStatement expectedClosedDL = openDL.GetStatement();
            return expectedClosedDL.Equals(closedDL);
        }

 
        /// <summary>
        /// Returns a hash code computed using the first base. If the representation
        /// length is 0, returns 0;
        /// </summary>
        /// <returns>Hashcode</returns>
        public override int GetHashCode()
        {
            if (this.RepresentationLength == 0)
            {
                return 0;
            }
            return this.Bases[0].GetHashCode();
        }

        /// <summary>
        /// Multiplies all objects in dlarray.  Adds all the exponents and multiplies the values.
        /// Fails if objects in dlarray don't have the same bases in the same order. 
        /// </summary>
        /// <param name="dlarray"></param>
        /// <param name="product"></param>
        /// <returns></returns>
        public static bool TryStrictMultiply(DLRepOfGroupElement [] dlarray, out DLRepOfGroupElement product)
        {
            product = null;

            // make sure there is at least one element in the array
            if ((dlarray == null) || (dlarray.Length < 1))
            {
                return false;
            }

            // compare bases
            for (int i = 1; i < dlarray.Length; ++i)
            {
                if (! dlarray[0].AreBasesEqual(dlarray[i]))
                {
                    return false;
                }
            }


            GroupElement [] newBases = new GroupElement[dlarray[0].RepresentationLength];
            FieldZqElement [] newExponents = new FieldZqElement[dlarray[0].RepresentationLength];

            for (int baseIndex = 0; baseIndex < dlarray[0].RepresentationLength; ++baseIndex)
            {
                newBases[baseIndex] = dlarray[0].BaseAtIndex(baseIndex);
                newExponents[baseIndex] = dlarray[0].ExponentAtIndex(baseIndex);
                for (int dlIndex = 1; dlIndex < dlarray.Length; ++dlIndex)
                {
                    newExponents[baseIndex] += dlarray[dlIndex].ExponentAtIndex(baseIndex);
                }
            }

            product= new DLRepOfGroupElement(newBases, newExponents, dlarray[0].Group);
            return true;
        }

        /// <summary>
        /// Returns a new DLRepOfGroupElement object that has all the exponents
        /// in the current object multiplied by the scalar.
        /// </summary>
        /// <param name="scalar"></param>
        /// <returns></returns>
        public DLRepOfGroupElement Exponentiate(FieldZqElement scalar)
        {
            GroupElement[] newBases = new GroupElement[this.RepresentationLength];
            FieldZqElement[] newExponents = new FieldZqElement[this.RepresentationLength];

            for (int baseIndex = 0; baseIndex < this.RepresentationLength; ++baseIndex)
            {
                newBases[baseIndex] = this.Bases[baseIndex];
                newExponents[baseIndex] = scalar * this.Exponents[baseIndex];
            }
            return new DLRepOfGroupElement(newBases, newExponents, this.Group);
        }
    }

}
