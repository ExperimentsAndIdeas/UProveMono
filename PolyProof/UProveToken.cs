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
using System.Runtime.Serialization;
using UProveCrypto.Math;

namespace UProveCrypto.PolyProof
{
    /// <summary>
    /// Closed UProve token for verifier to check proofs about hidden attributes.
    /// </summary>
    [DataContract]
    public class ClosedUProveToken : EqualityProofWitnessStatement, IStatement
    {
        public override bool IsWitness
        {
            get
            {
                return false;
            }
        }

        /// <summary>
        /// The generators used to compute this token. The generators G[0],...,G[n] correspond to
        /// generators g_0,...,g_n. The last element in the array
        /// corresponds to special generator g_t.
        /// </summary>
        public GroupElement[] G
        {
            get
            {
                return this.Bases;
            }
        }

        /// <summary>
        /// The special generator g_t.
        /// </summary>
        public GroupElement GT
        {
            get
            {
                return G[G.Length - 1];
            }
            internal set
            {
                G[G.Length - 1] = value;
            }
        }

        /// <summary>
        /// Special attribute x_t.
        /// </summary>
        public FieldZqElement AttributeXT
        {
            get
            {
                return this.Exponents[this.RepresentationLength - 1];
            }
            set
            {
                this.Exponents[this.RepresentationLength - 1] = value;
            }
        }

        /// <summary>
        /// Then token public key h.
        /// </summary>
        public GroupElement PublicKey
        {
            get
            {
                return this.Value;
            }
        }

 
        /// <summary>
        /// Returns the number of attributes XI.
        /// </summary>
        public int NumberOfAttributesXI
        {
            get
            {
                return this.RepresentationLength - 2;
            }
        }


        /// <summary>
        /// Token private key alpha^{-1}.
        /// </summary>
        public FieldZqElement PrivateKey
        {
            get
            {
                return this.Alpha.Invert();
            }
        }

        /// <summary>
        /// Returns PrivateKey.Invert().
        /// </summary>
        public FieldZqElement Alpha
        {
            get
            {
                if (this.RepresentationLength == 0)
                {
                    return null;
                }
                else
                {
                    return this.Exponents[0];
                }
            }
            internal set
            {
                if (this.RepresentationLength > 0)
                {
                    this.Exponents[0] = value;
                }
            }
        }


        /// <summary>
        /// Creates a closed UProve token for proof verification.
        /// </summary>
        /// <param name="vppp">Verifier parameters</param>
        /// <param name="device">Required for device protected tokens.</param>
        public ClosedUProveToken(VerifierPresentationProtocolParameters vppp )
        {
            this.Bases = new GroupElement[vppp.IP.E.Length + 2];
            for (int i = 0; i < this.G.Length; ++i)
            {
                this.Bases[i] = vppp.IP.G[i];
            }
            this.Value = vppp.Token.H;
            this.Group = vppp.IP.Gq;
            this.Exponents = null; 
        }


        public ClosedUProveToken(GroupElement[] bases, GroupElement publicKey, Group group)
        {
            this.Bases = bases;
            this.Value = publicKey;
            this.Group = group;
            this.Exponents = null;
        }

        /// <summary>
        /// Returns attribute.
        /// </summary>
        /// <param name="index">Integer 1...n</param>
        /// <returns></returns>
        public FieldZqElement AttributeXI(int index)
        {
            if ((index < 1) || (index >= RepresentationLength - 1))
            {
                throw new IndexOutOfRangeException("Index must be an integer 1...n where n is the number of attributes x_i");
            }
            return this.ExponentAtIndex(index);
        }

        internal void SetAttributeXI(FieldZqElement [] attributeValues)
        {
            if (attributeValues == null)
            {
                return;
            }

            if (attributeValues.Length != RepresentationLength - 2)
            {
                throw new ArgumentException("Token must have exactly " + (this.RepresentationLength - 2) + " attributex x_i");
            }
            for (int i = 0; i < attributeValues.Length; ++i)
            {
                this.Exponents[i + 1] = attributeValues[i];
            }
        }

 
        /// <summary>
        /// Verifies that the given (commitment, challenge, response) values are a
        /// valid proof for this object.  See IOpenEquation for how commitment and response are generated.
        /// </summary>
        /// <param name="challenge">The challenge for this proof (second step in Sigma protocol).</param>
        /// <param name="responseValues">The response (third step in Sigma protocol).</param>
        /// <param name="commitment">The commitment (first step in Sigma protocol).</param>
        /// <returns></returns>
        public override bool Verify(GroupElement commitment, FieldZqElement challenge, FieldZqElement[] response)
        {
            if ((response == null) || (response.Length != this.RepresentationLength))
            {
                return false;
            }

            GroupElement[] bases = new GroupElement[ this.RepresentationLength + 1];
            FieldZqElement[] exponents = new FieldZqElement[this.RepresentationLength + 1];
            for (int i = 0; i < response.Length; ++i)
            {
                bases[i] = this.BaseAtIndex(i);
                exponents[i] = response[i];
            }
            exponents[0] = challenge.Negate();
            bases[this.RepresentationLength] = this.PublicKey;
            exponents[this.RepresentationLength] = response[0];

            GroupElement verifier = this.Group.MultiExponentiate(bases, exponents);
            if (commitment != verifier)
            {
                return false;
            }
            return true;
        }

        /// <summary>
        /// Computes a commitment to this object - first element in EqualityProof Sigma protocol.
        /// </summary>
        /// <param name="randomData">Randomness for creating commitment.  Length of array should be equal to the RepresentationLength</param>
        /// <returns></returns>
        public override GroupElement ComputeCommitment(FieldZqElement[] randomData)
        {
            if ((randomData == null) || (randomData.Length != this.RepresentationLength))
            {
                throw new ArgumentException("First argument to ComputeCommitment should be an array of length " + this.RepresentationLength + ".");
            }

            GroupElement[] bases = new GroupElement[this.RepresentationLength];
            bases[0] = this.PublicKey;
            for (int i = 1; i < bases.Length; ++i)
            {
                bases[i] = this.G[i];
            }
            return this.Group.MultiExponentiate(bases, randomData);
        }

        /// <summary>
        /// Computes an array of responses given the challenge and randomData.
        /// </summary>
        /// <param name="challenge">Challenge (second element in Sigma protocol)</param>
        /// <param name="randomData">Same random data as used to ComputeCommitment.</param>
        /// <param name="exponentIndex">Index of exponent.  Exponent 0 corresponds to G[0], 
        /// exponent 1...n corresponds to attributes AttributeXI[0]....AttributeXI[n-1], and exponent n+1 corresponds to AttributeXT</param>
        /// <returns>FieldZq element.</returns>
        public override FieldZqElement ComputeResponse(FieldZqElement challenge, FieldZqElement randomData, int exponentIndex)
        {
            if (exponentIndex == 0)
            {
                return challenge * this.PrivateKey + randomData;
            }
            else
            {
                return randomData - challenge * this.ExponentAtIndex(exponentIndex);
            }
        }

        /// <summary>
        /// Returns a ClosedUProveToken.
        /// </summary>
        /// <returns></returns>
        public override IStatement GetStatement()
        {
            return new ClosedUProveToken(this.Bases, this.PublicKey, this.Group);
        }

    }

    /// <summary>
    /// Open UProve token used by Prover to generate proofs about token attributes.
    /// </summary>
    [DataContract]
    public class OpenUProveToken : ClosedUProveToken, IWitness
    {
        public override bool IsWitness
        {
            get
            {
                return true;
            }
        }



        /// <summary>
        /// Creates a UProve token for non-device protected tokens.
        /// </summary>
        /// <param name="pppp">Prover presentation protocol parameters for non-device protected token.</param>
        /// <param name="device">Device information. Required for device protected tokens.</param>
        public OpenUProveToken(ProverPresentationProtocolParameters pppp) : base(null, null,null)
        {
            if (pppp == null)
            {
                throw new ArgumentNullException("UProveToken constructor expects non-null input.");
            }

            this.Group = pppp.IP.Gq;
            this.Bases = new GroupElement[pppp.Attributes.Length + 2];
            for (int i = 0; i < this.G.Length; ++i)
            {
                this.G[i] = pppp.IP.G[i];
            }
            this.Value = pppp.KeyAndToken.Token.H;

            this.Exponents = new FieldZqElement[this.RepresentationLength];
            this.Alpha = pppp.KeyAndToken.PrivateKey.Invert();

            FieldZqElement [] attributes = new FieldZqElement[pppp.Attributes.Length];
            for (int i = 0; i < attributes.Length; ++i)
            {
                attributes[i] = ProtocolHelper.ComputeXi(pppp.IP, i, pppp.Attributes[i]);
            }
            this.SetAttributeXI(attributes);
            this.AttributeXT = ProtocolHelper.ComputeXt(pppp.IP, pppp.KeyAndToken.Token.TI, pppp.KeyAndToken.Token.IsDeviceProtected);
        }

        /// <summary>
        /// Checks that the token public key is consistent with the other token values.
        /// </summary>
        /// <returns></returns>
        public bool Validate(GroupElement devicePublicKey)
        {
            // compute H from token manually
            FieldZqElement[] exponents = new FieldZqElement[this.G.Length];
            exponents[0] = this.Alpha;
            for (int i = 0; i < this.NumberOfAttributesXI; ++i)
            {
                exponents[i + 1] = this.AttributeXI(i+1) * this.Alpha;
            }
            exponents[exponents.Length - 1] = this.AttributeXT * this.Alpha;
            GroupElement expectedPublicKey = this.Group.MultiExponentiate(this.G, exponents);

            // factor in device public key
            if (devicePublicKey != null)
            {
                expectedPublicKey *= devicePublicKey;
            }


            // check public key (this also validates all other elements in token).
            if (this.PublicKey != expectedPublicKey)
            {
                return false;
            }
            return true;
        }

    }
}
