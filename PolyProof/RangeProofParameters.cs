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
using System.Collections;

namespace UProveCrypto.PolyProof
{
    /// <summary>
    /// Verifier parameters for range proofs comparing integerA to integerB.
    /// IntegerA is known only to the prover, while integerB may be known to the verifier.
    /// </summary>
    [DataContract]
    public class VerifierRangeProofParameters : ProofParameters
    {
        /// <summary>
        /// Pedersen Commitment to integerA
        /// </summary>
       public GroupElement ClosedIntegerA
        {
            get
            {
                if ((this.PublicValues == null)
                    || (this.PublicValues.Length != 2))
                {
                    return null;
                }
                return this.PublicValues[0];
            }
            set
            {
                if ((this.PublicValues == null)
                    || (this.PublicValues.Length != 2))
                {
                    this.PublicValues = new GroupElement[2] { null, null };
                }
                this.PublicValues[0] = value;
            }
        }

       public GroupElement RangeNormalizedClosedIntegerA
       {
           get
           {
               if (this.ClosedIntegerA == null)
               {
                   return null;
               }
               return this.ClosedIntegerA * this.G.Exponentiate(this.RangeNormalizationFactor);
           }
       }

        /// <summary>
        /// Pedersen Commitment to IntegerB
        /// </summary>
        public GroupElement ClosedIntegerB
        {
            get
            {
                if ((this.PublicValues == null)
                    || (this.PublicValues.Length !=2))
                {
                    return null;
                }
                return this.PublicValues[1];
            }
            set
            {
                if ((this.PublicValues == null)
                    || (this.PublicValues.Length !=2))
                {
                    this.PublicValues = new GroupElement[2] { null, null };
                }
                this.PublicValues[1] = value;
            }
        }

        public GroupElement RangeNormalizedClosedIntegerB
        {
            get
            {
                if (this.ClosedIntegerB == null)
                {
                    return null;
                }
                return this.ClosedIntegerB * this.G.Exponentiate(this.RangeNormalizationFactor);
            }
        }

        /// <summary>
        /// Range Proof Type: proof can show whether the relation of integerA to integerB is
        /// LESS_THAN, LESS_THAN_OR_EQUAL_TO, GREATER_THAN, GREATER_THAN_OR_EQUAL_TO
        /// </summary>
        [DataMember (Name="RangeProofType", EmitDefaultValue=false)]
        public ProofType RangeProofType;

        /// <summary>
        /// Minimum value of integerA and integerB.  MaxValue-MinValue should be as small as possible
        /// to minimize range proof size.
        /// </summary>
        [DataMember (Name="MinValue", EmitDefaultValue=false)]
        public int MinValue;


        /// <summary>
        /// Maximum value of integerA and integerB. MaxValue-MinValue should be as small as possible
        /// to minimize range proof size.
        /// </summary>
        [DataMember(Name = "MaxValue", EmitDefaultValue = false)]
        public int MaxValue;

        /// <summary>
        /// Returns -MinValue.
        /// </summary>
        public FieldZqElement RangeNormalizationFactor
        {
            get
            {
                return this.FieldZq.GetElement(0-MinValue);
            }
        }

        

        /// <summary>
        /// Whether verifier knows integerB.
        /// </summary>
        [DataMember (Name="IntegerBIsKnown", EmitDefaultValue=false)]
        public bool IntegerBIsKnown=true;

        /// <summary>
        /// Value of integer B.  Ignore if this.IntegerBIsKnown=false.
        /// </summary>
        [DataMember(Name = "IntegerB", EmitDefaultValue = false)]
        public int IntegerB;

        /// <summary>
        /// Guaranteed to be >= 0.
        /// </summary>
        public int RangeNormalizedIntegerB
        {
            get
            {
                return this.IntegerB - this.MinValue;
            }
        }

#region Defaults and Convenience Members 
        


        // Range proof types
        public enum ProofType
        {
            LESS_THAN,
            GREATER_THAN,
            LESS_THAN_OR_EQUAL_TO,
            GREATER_THAN_OR_EQUAL_TO
        };

        /// <summary>
        /// Maximum supported value for MaxValue - MinValue.
        /// </summary>
        public const int MAX_RANGE = (int)(Int32.MaxValue / 2);



#endregion

        /// <summary>
        /// Constructor. Use this constructor when the Verifier knows the value of integerB.
        /// </summary>
        /// <param name="crypto">Crypto parameters</param>
        /// <param name="closedIntegerA">Committed value being compared.</param>
        /// <param name="integerB">Verifier known constant being compared</param>
        /// <param name="maxRange">Maximum value of committed value in closedCommitment. Used to determine length of bit decomposition.</param>
        /// <param name="minRange">Minimum value of committed value in closedCommitment. Used to determine length of bit decomposition.</param>
        /// <param name="proofType">Relatation between committed value in closedCommitment and integer ( less than, greater than, etc).</param>
        public VerifierRangeProofParameters(CryptoParameters crypto, GroupElement closedIntegerA, ProofType rangeProofType, int integerB, int minRange, int maxRange)
            : base(crypto)
        {
            GroupElement closedIntegerB = this.G.Exponentiate(this.FieldZq.GetElement(integerB));
            this.setVerifierParameters(new GroupElement[] { closedIntegerA, closedIntegerB});

            this.RangeProofType = rangeProofType;
            this.IntegerBIsKnown = true;
            this.IntegerB = integerB;
            this.MinValue = minRange;
            this.MaxValue = maxRange;
       }

        /// <summary>
        /// Constructor.  Use this constructor when the verifier does not known integerB.
        /// </summary>
        /// <param name="crypto">Crypto parameters</param>
        /// <param name="closedIntegerA">Value of pedersen commitment to integer A</param>
        /// <param name="rangeProofType">relation between integerA and integerB</param>
        /// <param name="closedIntegerB">Value of pedersen commitment to integer B</param>
        /// <param name="minRange">Minimum value of integerA and integerB</param>
        /// <param name="maxRange">Maximum value of integerA and integerB</param>
        public VerifierRangeProofParameters(CryptoParameters crypto, GroupElement closedIntegerA, ProofType rangeProofType, GroupElement closedIntegerB, int minRange, int maxRange)
            : base(crypto)
        {
            this.setVerifierParameters(new GroupElement[] { closedIntegerA, closedIntegerB });

            this.RangeProofType = rangeProofType;
            this.IntegerBIsKnown = false;
            this.MinValue = minRange;
            this.MaxValue = maxRange;
       }

        /// <summary>
        /// Do not use this constructor for VerifyRangeProofParameters.
        /// </summary>
        /// <param name="crypto"></param>
        internal VerifierRangeProofParameters(CryptoParameters crypto) : base(crypto)
        {
            this.setVerifierParameters(null);
        }

        /// <summary>
        /// Verify that parameters are valid..
        /// </summary>
        /// <returns>True if parameters are valid, false otherwise.</returns>
        new public bool Verify()
        {
            if (!base.Verify())
            {
                return false;
            }

            // check range
            if ((this.MinValue > this.MaxValue)
                || (this.MaxValue - this.MinValue > MAX_RANGE))
            {
                return false;
            }

            // check integer A and integer B
            if(this.ClosedIntegerA == null)
            {
                return false;
            }
            if (this.IntegerBIsKnown)
            {
                if ((this.IntegerB < this.MinValue || this.IntegerB > this.MaxValue))
                {
                    return false;
                }
            }
            else
            {
                if (this.ClosedIntegerB == null)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Compares integer represented by bitA to integer represented by bitB.
        /// </summary>
        /// <param name="bitA">Binary representation of an integer.  LSB first.</param>
        /// <param name="bitB">Binary representation of an integer.  LSB first.</param>
        /// <returns>Returns 0 if bitA==bitB, 1 if bitA>bitB, and -1 otherwise. </returns>
        public static int Compare(BitArray bitA, BitArray bitB)
        {
            if (bitA.Length > bitB.Length)
            {
                return 1;
            }

            if (bitA.Length < bitB.Length)
            {
                return -1;
            }

            for (int i = bitA.Length - 1; i >= 0; --i)
            {
                if (bitA.Get(i) && (! bitB.Get(i)))
                {
                    return 1;
                }
                if ((! bitA.Get(i)) && bitB.Get(i))
                {
                    return -1;
                }
            }
            return 0;
        }

    }

    [DataContract]
    public class ProverRangeProofParameters : VerifierRangeProofParameters
    {
        /// <summary>
        /// PedersenCommitment to integerA.
        /// </summary>
        public PedersenCommitment OpenIntegerA
        {
            get
            {
                if ((this.Witnesses == null)
                    || (this.Witnesses.Length != 2))
                {
                    return null;
                }
                return (PedersenCommitment) this.Witnesses[0];
            }
            private set
            {
                if ((this.Witnesses == null)
                   || (this.Witnesses.Length != 2))
                {
                    this.Witnesses = new PedersenCommitment[2] { value, null };
                }
                this.Witnesses[0] = value;
                if (value != null)
                {
                    this.ClosedIntegerA = value.Value;
                }
            }
        }

        /// <summary>
        /// PedersenCommitment to integerB.
        /// </summary>
        public PedersenCommitment OpenIntegerB
        {
            get
            {
                if ((this.Witnesses == null)
                    || (this.Witnesses.Length != 2))
                {
                    return null;
                }
                return  (PedersenCommitment) this.Witnesses[1];
            }
            private set
            {
                if ((this.Witnesses == null)
                  || (this.Witnesses.Length != 2))
                {
                    this.Witnesses = new PedersenCommitment[2] { value, null };
                }

                this.Witnesses[1] = value;
                if (value != null)
                {
                    this.ClosedIntegerB= value.Value;
                }
            }
        }

        /// <summary>
        /// Returns OpenIntegerA multiplied by by G^{RangeNormalizationFactor}.
        /// Used by RangeProof to construct the actual proof.
        /// </summary>
        public PedersenCommitment RangeNormalizedOpenIntegerA
        {
            get
            {
                if (this.OpenIntegerA == null)
                {
                    return null;
                }
                return new PedersenCommitment(
                    this.G,
                    this.H,
                    this.OpenIntegerA.ExponentAtIndex(0) + this.RangeNormalizationFactor,
                    this.OpenIntegerA.ExponentAtIndex(1),
                    this.Group);
            }
        }

        /// <summary>
        /// Returns OpenIntegerB multiplied by by G^{RangeNormalizationFactor}.
        /// Used by RangeProof to construct the actual proof. 
        /// </summary>
        public PedersenCommitment RangeNormalizedOpenIntegerB
        {
            get
            {
                if (this.OpenIntegerB == null)
                {
                    return null;
                }
                return new PedersenCommitment(
                    this.G,
                    this.H,
                    this.OpenIntegerB.ExponentAtIndex(0) + this.RangeNormalizationFactor,
                    this.OpenIntegerB.ExponentAtIndex(1),
                    this.Group);
            }
        }


        
        /// <summary>
        /// Constructor. Use this constructor when the verifier DOES NOT know the value
        /// of IntegerB.
        /// </summary>
        /// <param name="crypto">Crypto parameters.</param>
        /// <param name="openIntegerA">Pedersen Commitment to integerA.</param>
        /// <param name="rangeProofType">Type of range proof.</param>
        /// <param name="openIntegerB">Pedersen Commitment to integerB.</param>
        /// <param name="minRange">Minimum value for integerA and integerB.</param>
        /// <param name="maxRange">Maximum value for integerA and integerB.</param>
        public ProverRangeProofParameters(
            CryptoParameters crypto,
            PedersenCommitment openIntegerA,
            ProofType rangeProofType,
            PedersenCommitment openIntegerB,
            int minRange,
            int maxRange) : base(crypto)
        {
            this.setProverParameters(new PedersenCommitment[] { openIntegerA, openIntegerB });
            this.IntegerBIsKnown = false;
            this.RangeProofType = rangeProofType;
            this.MinValue = minRange;
            this.MaxValue = maxRange;
        }

        /// <summary>
        /// Constructor. Use this constructor when the verifier knows the value
        /// of IntegerB.
        /// </summary>
        /// <param name="crypto">Crypto parameters.</param>
        /// <param name="openIntegerA">Pedersen Commitment to integerA.</param>
        /// <param name="rangeProofType">Type of range proof.</param>
        /// <param name="integerB">integerB.</param>
        /// <param name="minRange">Minimum value for integerA and integerB.</param>
        /// <param name="maxRange">Maximum value for integerA and integerB.</param>
 
        public ProverRangeProofParameters(
            CryptoParameters crypto,
            PedersenCommitment openIntegerA,
            ProofType rangeProofType,
            int integerB,
            int minRange,
            int maxRange) : base(crypto)
        {
            PedersenCommitment openIntegerB = new PedersenCommitment(this.G, this.H, this.FieldZq.GetElement((uint)integerB), this.FieldZq.Zero, this.Group);
            this.setProverParameters(new PedersenCommitment[] { openIntegerA, openIntegerB });

            this.IntegerBIsKnown = true;
            this.IntegerB = integerB;
            this.RangeProofType = rangeProofType;
            this.MinValue = minRange;
            this.MaxValue = maxRange;
        }

        /// <summary>
        /// Verifies that the ProverRangeProofParameters are valid.
        /// </summary>
        /// <returns>True if parameters are valid.</returns>
        new public bool Verify()
        {
            if (!base.Verify())
            {
                return false;
            }

            // check that they're in range
            BitArray maxValueBits = VerifierBitDecompositionParameters.GetBitDecomposition(this.GetRangeNormalizedFieldZqElement(this.MaxValue), 0, this.FieldZq);
            int decompositionLength = maxValueBits.Length;
            BitArray minValueBits = VerifierBitDecompositionParameters.GetBitDecomposition(this.GetRangeNormalizedFieldZqElement(this.MinValue), decompositionLength, this.FieldZq);


            // check integer A and integer B exist
            if (this.OpenIntegerA == null)
            {
                return false;
            }
            BitArray bitA = VerifierBitDecompositionParameters.GetBitDecomposition(this.RangeNormalizedOpenIntegerA.ExponentAtIndex(0), decompositionLength, this.FieldZq);
            BitArray bitB;
            if (this.IntegerBIsKnown)
            {
                bitB = VerifierBitDecompositionParameters.GetBitDecomposition(this.GetRangeNormalizedFieldZqElement(this.IntegerB), decompositionLength, this.FieldZq);
            }
            else
            {
                if (this.OpenIntegerB == null)
                {
                    return false;
                }
                bitB = VerifierBitDecompositionParameters.GetBitDecomposition(this.RangeNormalizedOpenIntegerB.ExponentAtIndex(0), decompositionLength, this.FieldZq);
            }

            // make sure integerA and integerB are in range.
            if((Compare(bitA,minValueBits)<0)
                || (Compare(bitA, maxValueBits) >0)
                || (Compare(bitB, minValueBits)<0)
                || (Compare(bitB, maxValueBits) > 0))
            {
                return false;
            }

            // now compare integerA and integerB based on range proof type.
            switch(this.RangeProofType)
            {
                case VerifierRangeProofParameters.ProofType.GREATER_THAN:
                    if(Compare(bitA,bitB) <= 0)
                    {
                        return false;
                    }
                    break;
                case VerifierRangeProofParameters.ProofType.GREATER_THAN_OR_EQUAL_TO:
                    if(Compare(bitA,bitB) < 0)
                    {
                        return false;
                    }
                    break;
                case VerifierRangeProofParameters.ProofType.LESS_THAN:
                    if(Compare(bitA,bitB) >= 0)
                    {
                        return false;
                    }
                    break;
                case VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO:
                    if(Compare(bitA,bitB) > 0)
                    {
                        return false;
                    }
                    break;
            }

            return true;
        }

        /// <summary>
        /// Returns FieldZqElement representing integer + this.RangeNormalizationFactor.
        /// </summary>
        /// <param name="integer"></param>
        /// <returns></returns>
        private FieldZqElement GetRangeNormalizedFieldZqElement(int integer)
        {
            return this.FieldZq.GetElement(integer) + this.RangeNormalizationFactor;
        }
    }

    public class RangeProofParameterFactory
    {
        /// <summary>
        /// Returns prover parameters for comparing actual age to verfierTargetAge.
        /// </summary>
        /// <param name="crypto">Crypto parameters</param>
        /// <param name="actualAge">Actual age of prover in years [0,127].</param>
        /// <param name="rangeProofType">Range proof type.</param>
        /// <param name="verifierTargetAge">Verifier target age in years [0,127].</param>
        /// <returns></returns>
        public static ProverRangeProofParameters GetAgeProverParameters(CryptoParameters crypto, int actualAge, VerifierRangeProofParameters.ProofType rangeProofType, int verifierTargetAge)
        {
            return new ProverRangeProofParameters(
                crypto,
                new PedersenCommitment(crypto.FieldZq.GetElement(actualAge), crypto),
                rangeProofType,
                verifierTargetAge,
                0,
                127);
        }

        /// <summary>
        /// Returns prover parameters for comparing prover age to verifier target age.
        /// </summary>
        /// <param name="crypto">Cryptographic parameters</param>
        /// <param name="commitmentToActualAge">Commitment to age in years [0,127].</param>
        /// <param name="rangeProofType">Range proof type.</param>
        /// <param name="verifierTargetAge">Verifier target age in years [0,127].</param>
        /// <returns></returns>
        public static ProverRangeProofParameters GetAgeProverParameters(CryptoParameters crypto, PedersenCommitment commitmentToActualAge, VerifierRangeProofParameters.ProofType rangeProofType, int verifierTargetAge)
        {
            return new ProverRangeProofParameters(
                crypto,
                commitmentToActualAge,
                rangeProofType,
                verifierTargetAge,
                0,
                127);
        }

        /// <summary>
        /// Returns verifier parameters for an age range proof.
        /// </summary>
        /// <param name="crypto">Cryptographic parameters.</param>
        /// <param name="commitmentToActualAge">Commitment to age in years provided by prover.</param>
        /// <param name="rangeProofType">Range proof type.</param>
        /// <param name="verifierTargetAge">Verifier target age in years [0,127].</param>
        /// <returns></returns>
        public static VerifierRangeProofParameters GetAgeVerifierParameters(CryptoParameters crypto, GroupElement commitmentToActualAge, VerifierRangeProofParameters.ProofType rangeProofType, int verifierTargetAge)
        {
            if ((verifierTargetAge < 0) || (verifierTargetAge > 127))
            {
                throw new ArgumentOutOfRangeException("VerifierTargetAge should be an integer in [0,127]");
            }
            return new VerifierRangeProofParameters(
                crypto,
                commitmentToActualAge,
                rangeProofType,
                verifierTargetAge,
                0,
                127);
        }

        /// <summary>
        /// Returns ProverRangeProofParameters that the committed date to the
        /// the verifier target date.  Range proof will require bit decomposition of  approximately  9 + log_2 (maxYear - minYear) bits.
        /// </summary>
        /// <param name="crypto">Crypto parameters</param>
        /// <param name="commitmentToDayOfYear">Commitment value in [0,365]</param>
        /// <param name="commitmentToYear">Commitment to a year in [minYear, maxYear].</param>
        /// <param name="rangeProofType">Range proof type.</param>
        /// <param name="verifierTargetDate">Commitment to a date in [minYear, maxYear +1).</param>
        /// <param name="minYear">Limits range of proof. </param>
        /// <param name="maxYear">Limits range of proof.</param>
        /// <returns></returns>
        public static ProverRangeProofParameters GetDateTimeProverParameters(CryptoParameters crypto, PedersenCommitment commitmentToYear, PedersenCommitment commitmentToDayOfYear, VerifierRangeProofParameters.ProofType rangeProofType, DateTime verifierTargetDate, int minYear, int maxYear)
        {

            //Check crypto parameters and pedersen commitment generators G and H
            if(! commitmentToYear.AreBasesEqual(commitmentToDayOfYear))
            {
                throw new ArgumentException("PedersenCommitments commitmentToYear and commitmentToDayOfYear have different bases.");
            }
            if(( crypto.G != commitmentToYear.BaseAtIndex(0))
                || (crypto.H != commitmentToYear.BaseAtIndex(1)))
            {
                throw new ArgumentException("PedersenCommitments commitmentToYear and commitmentToDayOfYear should use bases crypto.G and crypto.H.");
            }

            FieldZqElement minYearElement = crypto.FieldZq.GetElement((uint)minYear);
            FieldZqElement daysInOneYear = crypto.FieldZq.GetElement(366);
            FieldZqElement committedYear = commitmentToYear.ExponentAtIndex(0);
            FieldZqElement committedDay = commitmentToDayOfYear.ExponentAtIndex(0);
            FieldZqElement openingYear = commitmentToYear.ExponentAtIndex(1);
            FieldZqElement openingDay = commitmentToDayOfYear.ExponentAtIndex(1);
            
            PedersenCommitment commitmentToYearAndDay = new PedersenCommitment(
                crypto.G,
                crypto.H,
                (committedYear + minYearElement.Negate()) * daysInOneYear + committedDay,
                openingYear * daysInOneYear + openingDay,
                crypto.Group);



            int maxValue = (maxYear-minYear) * 366 + 365;
            int verifierYearAndDay = EncodeYearAndDay(verifierTargetDate, minYear);

            return new ProverRangeProofParameters(
                crypto,
                commitmentToYearAndDay,
                rangeProofType,
                verifierYearAndDay,
                0,
                maxValue);       
        }

        /// <summary>
        /// Returns verifier parameters corresponding to prover parameters generated by
        /// GetDateTimeProverParameters.
        /// </summary>
        /// <param name="crypto">Cryptographic parameters.</param>
        /// <param name="commitmentToDayOfYear">Prover supplied commitment to day of year in [0,365].</param>
        /// <param name="commitmentToYear">Prover supplied commitment to year in [minYear, maxYear].</param>
        /// <param name="rangeProofType">Range proof type.</param>
        /// <param name="verifierTargetDate">verifier target date in [minYear, maxYear+1).</param>
        /// <param name="minYear">Used to determine range.  Must be same as used by prover.</param>
        /// <param name="maxYear">Used to determine range.  Must be same as used by prover.</param>
        /// <returns></returns>
        public static VerifierRangeProofParameters GetDateTimeVerifierParameters(CryptoParameters crypto, GroupElement commitmentToYear, GroupElement commitmentToDayOfYear, VerifierRangeProofParameters.ProofType rangeProofType, DateTime verifierTargetDate, int minYear, int maxYear)
        {
            // Compute (commitmentToYear / G^minYear)^366  * commitmentToDayOfYear
            GroupElement[] bases = new GroupElement[]
            {
                commitmentToYear,
                crypto.G
            };
            FieldZqElement[] exponents = new FieldZqElement[]
            {
                crypto.FieldZq.GetElement(366),
                crypto.FieldZq.GetElement((uint)(minYear * 366)).Negate()
            };
            GroupElement commitmentToYearAndDay = crypto.Group.MultiExponentiate(bases, exponents) * commitmentToDayOfYear;


            int maxValue = (maxYear - minYear) * 366 + 365;
            int verifierYearAndDay = EncodeYearAndDay(verifierTargetDate, minYear);

            return new VerifierRangeProofParameters(
                crypto,
                commitmentToYearAndDay,
                rangeProofType,
                verifierYearAndDay,
                0,
                maxValue);
        }


        /// <summary>
        /// Creates prover parameters for comparing committed year and day to verifier target date.
        /// Size of proof is approximately log_2 (maxYear - minYear)*366.
        /// </summary>
        /// <param name="crypto">Cryptographic parameters.</param>
        /// <param name="commitmentToYearAndDay">See EncodeYearAndDay() for encoding format.</param>
        /// <param name="rangeProofType">Range proof type.</param>
        /// <param name="verifierTargetDate">Verifier target date.  Must be in [minYear, maxYear+1).</param>
        /// <param name="minYear">Used to specify range.</param>
        /// <param name="maxYear">Used to specify range.</param>
        /// <returns></returns>
        public static ProverRangeProofParameters GetDateTimeProverParameters(CryptoParameters crypto, PedersenCommitment commitmentToYearAndDay, VerifierRangeProofParameters.ProofType rangeProofType, DateTime verifierTargetDate, int minYear, int maxYear)
        {
            int maxValue = (maxYear - minYear) * 366 + 365;
            int verifierYearAndDay = EncodeYearAndDay(verifierTargetDate, minYear);

            return new ProverRangeProofParameters(
                crypto,
                commitmentToYearAndDay,
                rangeProofType,
                verifierYearAndDay,
                0,
                maxValue);     
        }

        /// <summary>
        /// Create verifier parameter for comparing committed date to verifier target date.
        /// </summary>
        /// <param name="crypto">Cryptographic parameters.</param>
        /// <param name="commitmentToYearAndDay">Prover supplied committed value.</param>
        /// <param name="rangeProofType">Range proof type.</param>
        /// <param name="verifierTargetDate">Verifier target date.  Must be in [minYear, maxYear+1).</param>
        /// <param name="minYear">Used to specify range, must be same as in prover parameters.</param>
        /// <param name="maxYear">Used to specify range, must be same as in prover parameters.</param>
        /// <returns></returns>
        public static VerifierRangeProofParameters GetDateTimeVerifierParameters(CryptoParameters crypto, GroupElement commitmentToYearAndDay, VerifierRangeProofParameters.ProofType rangeProofType, DateTime verifierTargetDate, int minYear, int maxYear)
        {
            int maxValue = (maxYear - minYear) * 366 + 365;
            int verifierYearAndDay = EncodeYearAndDay(verifierTargetDate, minYear);

            return new VerifierRangeProofParameters(
                crypto,
                commitmentToYearAndDay,
                rangeProofType,
                verifierYearAndDay,
                0,
                maxValue);     
        }


        /// <summary>
        /// Returns integer representation of date.  Use the following formula:
        /// output = (date.Year - minYear) * 366 + date.DayOfYear.
        /// Range proofs require approximately 9 + log_2 (maxYear - minYear)  bit decomposition.
        /// </summary>
        /// <param name="date">Must be in range [minYear, maxYear+1).</param>
        /// <param name="minYear"></param>
        /// <param name="maxYear"></param>
        /// <returns></returns>
        public static int EncodeYearAndDay(DateTime date, int minYear)
        {
            if (date.Year < minYear)
            {
                throw new ArgumentOutOfRangeException("Argument date is not within the range [minYear, maxYear].");
            }

            return (date.Year - minYear) * 366 + date.DayOfYear;
        }

        /// <summary>
        /// Returns integer representing day of year and hour.  Uses the following formula:
        /// output = (date.DayOfYear * 24) + date.Hour. 
        /// For full year, range proofs will require 14-bit decomposition.
        /// </summary>
        /// <param name="date"></param>
        /// <returns></returns>
        public static int EncodeDayAndHour(DateTime date, int minDayOfYear)
        {
            if (date.Year < minDayOfYear)
            {
                throw new ArgumentOutOfRangeException("Argument date is not within the range [minYear, maxYear].");
            }
            return (date.DayOfYear - minDayOfYear) * 24 + date.Hour;
        }

        /// <summary>
        /// Create prover parameters for comparing committed day and hour to verifier target day and hour.
        /// </summary>
        /// <param name="crypto">Cryptographic parameters.</param>
        /// <param name="commitmentToDayAndHour">See method EncodeDayAndHour() for encoding specification.</param>
        /// <param name="rangeProofType">Range proof type.</param>
        /// <param name="verifierTargetDayHour">Verifier target day of year and hour. Year is ignored.</param>
        /// <param name="minDayOfYear">Establishes range.</param>
        /// <param name="maxDayOfYear">Establishes range.</param>
        /// <returns></returns>
        public static ProverRangeProofParameters GetDayAndHourProverParameters(CryptoParameters crypto, PedersenCommitment commitmentToDayAndHour, VerifierRangeProofParameters.ProofType rangeProofType, DateTime verifierTargetDayHour, int minDayOfYear, int maxDayOfYear)
        {
            if(minDayOfYear > maxDayOfYear)
            {
                throw new ArgumentException("Argument minDayOfYear must be less than or equal to maxDayOfYear.");
            }
            if ((minDayOfYear < 0) || (maxDayOfYear > 366))
            {
                throw new ArgumentOutOfRangeException("Arguments minDayOfYear and maxDayOfYear must be in [0,365]");
            }

            return new ProverRangeProofParameters(
                crypto,
                commitmentToDayAndHour,
                rangeProofType,
                EncodeDayAndHour(verifierTargetDayHour, minDayOfYear),
                minDayOfYear * 24,
                maxDayOfYear * 24 + 23);
        }

        /// <summary>
        /// Create prover parameters for comparing committed day and hour to verifier target day and hour.
        /// </summary>
        /// <param name="crypto">Cryptographic parameters.</param>
        /// <param name="commitmentToDayAndHour">Prover supplied commitment.</param>
        /// <param name="rangeProofType">Range proof type.</param>
        /// <param name="verifierTargetDayHour">Verifier target day of year and hour. Year is ignored.</param>
        /// <param name="minDayOfYear">Establishes range. Must be same as used by prover.</param>
        /// <param name="maxDayOfYear">Establishes range. Must be same as used by prover.</param>
        /// <returns></returns>
        public static VerifierRangeProofParameters GetDayAndHourVerifierParameters(CryptoParameters crypto, GroupElement commitmentToDayAndHour, VerifierRangeProofParameters.ProofType rangeProofType, DateTime verifierTargetDayHour, int minDayOfYear, int maxDayOfYear)
        {
            if (minDayOfYear > maxDayOfYear)
            {
                throw new ArgumentException("Argument minDayOfYear must be less than or equal to maxDayOfYear.");
            }
            if ((minDayOfYear < 0) || (maxDayOfYear > 366))
            {
                throw new ArgumentOutOfRangeException("Arguments minDayOfYear and maxDayOfYear must be in [0,365]");
            }
            return new VerifierRangeProofParameters(
                crypto,
                commitmentToDayAndHour,
                rangeProofType,
                EncodeDayAndHour(verifierTargetDayHour, minDayOfYear),
                minDayOfYear * 24,
                maxDayOfYear * 24 + 23);
        }

        public static byte[] EncodeYearAndDayAsUProveAttribute(DateTime date, int minYear)
        {
            int encodedDate = RangeProofParameterFactory.EncodeYearAndDay(date, minYear);
            return RangeProofParameterFactory.EncodeIntAsUProveAttribute(encodedDate);
        }

        public static byte[] EncodeIntAsUProveAttribute(int integer)
        {
            byte[] bigEndian = BitConverter.GetBytes(integer);
            if (BitConverter.IsLittleEndian)
            {
                byte[] reverse = new byte[bigEndian.Length];
                for (int i = 0; i < reverse.Length; ++i)
                {
                    reverse[i] = bigEndian[bigEndian.Length - i -1];
                }
                bigEndian = reverse;
            }
            return bigEndian;

        }
    }
}
