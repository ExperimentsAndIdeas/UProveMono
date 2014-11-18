﻿//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//    This code is licensed under the Apache License
//    Version 2.0.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

using System;
using UProveCrypto.Math;
using System.Runtime.Serialization;
using System.ComponentModel;

namespace UProveCrypto
{
    /// <summary>
    /// Specifies the Prover random data for the issuance protocol, if provided externally.
    /// </summary>
    public class ProverRandomData
    {

        FieldZqElement beta0;
        FieldZqElement[] alpha;
        FieldZqElement[] beta1;
        FieldZqElement[] beta2;

        /// <summary>
        /// Constructs a new <code>ProverRandomData</code> instance.
        /// </summary>
        public ProverRandomData()
        {
        }

        /// <summary>
        /// Constructs a new <code>ProverRandomData</code> instance.
        /// </summary>
        /// <param name="alpha">An array of alpha values.</param>
        /// <param name="beta1">An array of beta1 values.</param>
        /// <param name="beta2">An array of beta2 values.</param>
        /// <param name="beta0">A beta0 value. Defaults to <code>null</code>.</param>
        public ProverRandomData(FieldZqElement[] alpha, FieldZqElement[] beta1, FieldZqElement[] beta2, FieldZqElement beta0 = null)
        {
            this.beta0 = beta0;
            this.alpha = alpha;
            this.beta1 = beta1;
            this.beta2 = beta2;
        }

        /// <summary>
        /// Gets or sets the alpha array.
        /// </summary>
        public FieldZqElement[] Alpha
        {
            get { return alpha; }
            set { alpha = value; }
        }


        /// <summary>
        /// Gets or sets the beta0 value.
        /// </summary>
        public FieldZqElement Beta0
        {
            get { return beta0; }
            set { beta0 = value; }
        }

        /// <summary>
        /// Gets or sets the beta1 array.
        /// </summary>
        public FieldZqElement[] Beta1
        {
            get { return beta1; }
            set { beta1 = value; }
        }

        /// <summary>
        /// Gets or sets the beta2 array.
        /// </summary>
        public FieldZqElement[] Beta2
        {
            get { return beta2; }
            set { beta2 = value; }
        }

        /// <summary>
        /// Validates the consistency of the object.
        /// </summary>
        public void Validate()
        {
            if (alpha == null || beta1 == null || beta2 == null) // beta0 can be null
            {
                throw new ArgumentNullException();
            }
            if (alpha.Length != beta1.Length || alpha.Length != beta2.Length)
            {
                throw new ArgumentException("arrays must be of same length");
            }
        }
    }

    /// <summary>
    /// Issuance protocol parameters for the Prover.
    /// </summary>
    public class ProverProtocolParameters : IssuanceProtocolParameters
    {

        /// <summary>
        /// Blinding value used to hide gamma, i.e., compute h_0 = gamma^beta0.
        /// </summary>
        public FieldZqElement Beta0 { get; set; }

        /// <summary>
        /// Constructs new issuance protocol parameters for the Prover.
        /// </summary>
        /// <param name="ip">The Issuer parameters.</param>
        public ProverProtocolParameters(IssuerParameters ip)
        {
            if (ip == null)
            {
                throw new ArgumentNullException("ip");
            }
            IssuerParameters = ip;
            BatchValidationSecurityLevel = 0; // defaults to normal validation
            BlindGamma = false;
        }

        /// <summary>
        /// The Issuer parameters.
        /// </summary>
        public IssuerParameters IssuerParameters { get; private set; }

        /// <summary>
        /// The Prover information field value. Can be <code>null</code>.
        /// </summary>
        public byte[] ProverInformation { get; set; }

        /// <summary>
        /// The pregenerated Prover randomizers. Can be <code>null</code>.
        /// </summary>
        public ProverRandomData ProverRandomData { get; set; }

        /// <summary>
        /// <code>True</code> to blind the gamma value, to send to the issuer in the collaborative
        /// issuance setting; false otherwise (default). If <code>true</code>, the blinded gamma
        /// value can be retrieved from the <code>Prover.BlindedGamma</code> property.
        /// </summary>
        public bool BlindGamma { get; set; }

        /// <summary>
        /// The security level of the batch token signature validation. Given a security level <code>l</code>,
        /// the probability for the Prover to accept an invalid token is <code>2^-l</code>. If set to 0, than
        /// regular validation is used. A minimum value of 20 is recommended.
        /// </summary>
        public ushort BatchValidationSecurityLevel
        { get; set; }

        /// <summary>
        /// Validates the issuance parameters.
        /// </summary>
        public override void Validate()
        {
            if (ProverRandomData != null && ProverRandomData.Alpha.Length != NumberOfTokens)
            {
                throw new ArgumentException("invalid ProverRandomData length");
            }
        }

        /// <summary>
        /// Creates an Prover instance.
        /// </summary>
        /// <returns>A Prover instance.</returns>
        public Prover CreateProver()
        {
            Validate();
            if (Gamma == null)
            {
                Gamma = ProtocolHelper.ComputeIssuanceInput(IssuerParameters, Attributes, TokenInformation, DevicePublicKey);
            }


            return new Prover(IssuerParameters, NumberOfTokens, Gamma, TokenInformation, ProverInformation, ProverRandomData,
                DevicePublicKey != null, BatchValidationSecurityLevel, Beta0);
        }

        public void SetBlindedGamma(GroupElement gamma, FieldZqElement beta0)
        {
            this.BlindGamma = true;
            this.Gamma = gamma;
            this.Beta0 = beta0;
        }
    }

    /// <summary>
    /// Issuance state after the second message generation. This
    /// object can be used to re-instanciate a <code>Prover</code> instance
    /// that can complete the token issuance.
    /// </summary>
    [DataContract]
    public class PostSecondMessageState : IParametrizedDeserialization
    {
        /// <summary>
        /// Constructs a <code>PostSecondMessageState</code> instance.
        /// </summary>
        public PostSecondMessageState()
        {
        }

        /// <summary>
        /// Gets or sets the token information field value.
        /// </summary>
        public byte[] TI { get; set; }

        /// <summary>
        /// Gets or sets the prover information field value.
        /// </summary>
        public byte[] PI { get; set; }

        /// <summary>
        /// Gets or sets the private key value alpha inverse.
        /// </summary>
        public FieldZqElement[] AlphaInverse { get; set; }

        /// <summary>
        /// Gets or sets the beta2 value.
        /// </summary>
        public FieldZqElement[] Beta2 { get; set; }

        /// <summary>
        /// Gets or sets the public key value h.
        /// </summary>
        public GroupElement[] H { get; set; }

        /// <summary>
        /// Gets or sets the sigmaZPrime value.
        /// </summary>
        public GroupElement[] SigmaZPrime { get; set; }

        /// <summary>
        /// Gets or sets the sigmaAPrime value.
        /// </summary>
        public GroupElement[] SigmaAPrime { get; set; }

        /// <summary>
        /// Gets or sets the sigmaBPrime value.
        /// </summary>
        public GroupElement[] SigmaBPrime { get; set; }

        /// <summary>
        /// Gets or sets the sigmaCPrime value.
        /// </summary>
        public FieldZqElement[] SigmaCPrime { get; set; }

        /// <summary>
        /// Gets or sets the boolean indicating if the token is Device-protected.
        /// </summary>
        public bool IsDeviceProtected { get; set; }

        /// <summary>
        /// Validates that the fields are consistent.
        /// </summary>
        public void Validate()
        {
            if (AlphaInverse == null)
                throw new UProveSerializationException("AlphaInverse ");
            if (Beta2 == null)
                throw new UProveSerializationException("Beta2");
            if (H == null)
                throw new UProveSerializationException("H");
            if (SigmaZPrime == null)
                throw new UProveSerializationException("SigmaZPrime");
            if (SigmaAPrime == null)
                throw new UProveSerializationException("SigmaAPrime");
            if (SigmaBPrime == null)
                throw new UProveSerializationException("SigmaBPrime");
            if (SigmaCPrime == null)
                throw new UProveSerializationException("SigmaCPrime");

            int count = AlphaInverse.Length;
            if (Beta2.Length != count || H.Length != count || SigmaZPrime.Length != count || SigmaAPrime.Length != count || SigmaBPrime.Length != count || SigmaCPrime.Length != count)
            {
                throw new UProveSerializationException("all arrays must have the same length");
            }
        }

        #region Serialization

        [DataMember(Name = "ti", Order = 1)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string _ti;

        [DataMember(Name = "pi", Order = 2)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string _pi;

        [DataMember(Name = "ai", Order = 3)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string[] _alphaInverse;

        [DataMember(Name = "b2", Order = 4)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string[] _beta2;

        [DataMember(Name = "h", Order = 5)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string[] _h;

        [DataMember(Name = "szp", Order = 6)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string[] _sigmaZPrime;

        [DataMember(Name = "sap", Order = 7)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string[] _sigmaAPrime;

        [DataMember(Name = "sbp", Order = 8)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string[] _sigmaBPrime;

        [DataMember(Name = "scp", Order = 9)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal string[] _sigmaCPrime;

        [DataMember(Name = "d", EmitDefaultValue = false, Order = 10)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal bool? _isDeviceProtected;

        [OnSerializing]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnSerializing(StreamingContext context)
        {
            _ti = this.TI.ToBase64String();
            _pi = this.PI.ToBase64String();
            _alphaInverse = this.AlphaInverse.ToBase64StringArray();
            _beta2 = this.Beta2.ToBase64StringArray();
            _h = this.H.ToBase64StringArray();
            _sigmaZPrime = this.SigmaZPrime.ToBase64StringArray();
            _sigmaAPrime = this.SigmaAPrime.ToBase64StringArray();
            _sigmaBPrime = this.SigmaBPrime.ToBase64StringArray();
            _sigmaCPrime = this.SigmaCPrime.ToBase64StringArray();
            _isDeviceProtected = this.IsDeviceProtected;
        }

        bool deserializationStarted = false;
        [OnDeserialized]
        [EditorBrowsable(EditorBrowsableState.Never)]
        internal void OnDeserialized(StreamingContext context)
        {
            // default to false if not provided
            if (_isDeviceProtected == null)
                _isDeviceProtected = false;

            TI = _ti.ToByteArray();
            PI = _pi.ToByteArray();
            IsDeviceProtected = _isDeviceProtected.Value;
            this.deserializationStarted = true;
        }

        void IParametrizedDeserialization.FinishDeserialization(IssuerParameters ip)
        {
            try
            {
                if (!this.deserializationStarted)
                {
                    throw new SerializationException("deserialization not started");
                }

                AlphaInverse = _alphaInverse.ToFieldElementArray(ip.Zq);
                Beta2 = _beta2.ToFieldElementArray(ip.Zq);
                H = _h.ToGroupElementArray(ip.Gq);
                SigmaZPrime = _sigmaZPrime.ToGroupElementArray(ip.Gq);
                SigmaAPrime = _sigmaAPrime.ToGroupElementArray(ip.Gq);
                SigmaBPrime = _sigmaBPrime.ToGroupElementArray(ip.Gq);
                SigmaCPrime = _sigmaCPrime.ToFieldElementArray(ip.Zq);

                Validate();
            }
            catch
            {
                throw;
            }
            finally
            {
                this.deserializationStarted = false;
            }
        }

        #endregion Serialization

    }

    /// <summary>
    /// Implements the <code>Prover</code> side of the U-Prove issuance protocol. One instance must be created for
    /// each run of the issuance protocol, in which many U-Prove tokens can be obtained in parallel.
    /// </summary>
    public class Prover
    {
        internal static readonly ushort DefaultBatchValidationSecurityLevel = 0;

        enum State { Initialized, Second, Tokens };
        private State state;
        int numberOfTokens;
        IssuerParameters ip;
        byte[] TI;
        byte[] PI;
        FieldZqElement beta0Inverse;
        GroupElement gamma; // needed for batch validation
        GroupElement sigmaZ; // needed for batch validation
        FieldZqElement[] alpha;
        FieldZqElement[] beta1;
        FieldZqElement[] beta2;
        GroupElement[] h;
        GroupElement[] t1;
        GroupElement[] sigmaZPrime;
        GroupElement[] sigmaAPrime;
        GroupElement[] sigmaBPrime;
        FieldZqElement[] sigmaCPrime;
        UProveKeyAndToken[] ukat;
        bool isDeviceProtected;
        ushort batchValidationSecurityLevel;

        /// <summary>
        /// Constructs a new <code>Prover</code> instance.
        /// </summary>
        /// <param name="ip">The Issuer parameters.</param>
        /// <param name="numberOfTokens">Number of tokens to issue.</param>
        /// <param name="A">The token attribute values.</param>
        /// <param name="TI">The token information field value.</param>
        /// <param name="PI">The Prover information field value.</param>
        /// <param name="hd">The Device public key. If this parameter is non-null, then the issued tokens will be Device-protected.</param>
        [Obsolete("Use ProverProtocolParameters.Create()")]
        public Prover(IssuerParameters ip, int numberOfTokens, byte[][] A, byte[] TI, byte[] PI, GroupElement hd)
            : this(ip, numberOfTokens, A, TI, PI, hd, null)
        { }

        /// <summary>
        /// Constructs a new <code>Prover</code> instance.
        /// </summary>
        /// <param name="ip">The Issuer parameters.</param>
        /// <param name="numberOfTokens">Number of tokens to issue.</param>
        /// <param name="A">The token attribute values.</param>
        /// <param name="TI">The token information field value.</param>
        /// <param name="PI">The Prover information field value.</param>
        /// <param name="hd">The Device public key. If this parameter is non-null, then the issued tokens will be Device-protected.</param>
        /// <param name="preGeneratedRandomData">Optional pregenerated ProverRandomData instance.</param>
        [Obsolete("Use ProverProtocolParameters.Create()")]
        public Prover(IssuerParameters ip, int numberOfTokens, byte[][] A, byte[] TI, byte[] PI, GroupElement hd, ProverRandomData preGeneratedRandomData)
            : this(ip, numberOfTokens, ProtocolHelper.ComputeIssuanceInput(ip, A, TI, hd), TI, PI, preGeneratedRandomData, hd != null, DefaultBatchValidationSecurityLevel)
        { }

        /// <summary>
        /// Constructs a new <code>Prover</code> instance.
        /// </summary>
        /// <param name="ip">The Issuer parameters.</param>
        /// <param name="psms">The post second message state.</param>
        public Prover(IssuerParameters ip, PostSecondMessageState psms)
        {
            psms.Validate();

            this.ip = ip;
            this.numberOfTokens = psms.AlphaInverse.Length;
            this.TI = psms.TI;
            this.PI = psms.PI;
            this.isDeviceProtected = psms.IsDeviceProtected;
            this.beta2 = psms.Beta2;

            this.h = psms.H;
            this.sigmaZPrime = psms.SigmaZPrime;
            this.sigmaAPrime = psms.SigmaAPrime;
            this.sigmaBPrime = psms.SigmaBPrime;
            this.sigmaCPrime = psms.SigmaCPrime;

            ukat = new UProveKeyAndToken[numberOfTokens];
            for (int i = 0; i < numberOfTokens; i++)
            {
                ukat[i] = new UProveKeyAndToken();
                ukat[i].PrivateKey = psms.AlphaInverse[i];
            }

            state = State.Second;
        }

        /// <summary>
        /// Constructs a new <code>Prover</code> instance.
        /// </summary>
        /// <param name="ip">The Issuer parameters.</param>
        /// <param name="numberOfTokens">Number of tokens to issue.</param>
        /// <param name="gamma">The gamma value encoding the token attributes. If <c>beta0</c> is non-null, then this value is blinded with <c>beta0</c>.</param>
        /// <param name="TI">The token information field value.</param>        
        /// <param name="PI">The Prover information field value.</param>
        /// <param name="preGeneratedRandomData">Optional pregenerated ProverRandomData instance.</param>
        /// <param name="isDeviceProtected">True if the token is to be device-protected, false otherwise.</param>
        /// <param name="batchValidationSecurityLevel">The security level of the batch token signature validation. Given a security level <code>l</code>,
        /// the probability for the Prover to accept an invalid token is <code>2^-l</code>. If set to 0, than
        /// regular validation is used. A value of 20 is recommended.</param>
        /// <param name="beta0">Non-null if the input <c>gamma</c> value is blinded (collaborative issuance, i.e., the input <c>gamma</c> is blinded with beta0).
        ///                            This parameter defaults to null if ommitted. </param>
        internal Prover(IssuerParameters ip, int numberOfTokens, GroupElement gamma, byte[] TI, byte[] PI, ProverRandomData preGeneratedRandomData,
            bool isDeviceProtected, ushort batchValidationSecurityLevel, FieldZqElement beta0 = null)
        {
            if (ip == null)
            {
                throw new ArgumentNullException("ip");
            }
            this.ip = ip;
            if (numberOfTokens <= 0)
            {
                throw new ArgumentException("numberOfTokens must be greater than 0");
            }
            this.numberOfTokens = numberOfTokens;
            this.TI = TI;
            this.PI = PI;
            if (preGeneratedRandomData != null &&
                (preGeneratedRandomData.Alpha.Length != numberOfTokens ||
                 preGeneratedRandomData.Beta1.Length != numberOfTokens ||
                 preGeneratedRandomData.Beta2.Length != numberOfTokens))
            {
                throw new ArgumentException("invalid preGeneratedRandomData");
            }
            this.isDeviceProtected = isDeviceProtected;
            this.batchValidationSecurityLevel = batchValidationSecurityLevel;

            this.gamma = gamma;
            if (beta0 != null)                          // inputs are blinded; collab issuance
                this.beta0Inverse = beta0.Invert();
            else                                        // no collab issuance
                this.beta0Inverse = ip.Zq.One;

            Precompute(gamma, preGeneratedRandomData);
        }

        private void Precompute(GroupElement gamma, ProverRandomData pregeneratedRandomData)
        {
            Group Gq = ip.Gq;
            FieldZq Zq = ip.Zq;

            if (pregeneratedRandomData == null)
            {
                alpha = Zq.GetRandomElements(numberOfTokens, true);
                beta1 = Zq.GetRandomElements(numberOfTokens, false);
                beta2 = Zq.GetRandomElements(numberOfTokens, false);
            }
            else
            {
                alpha = pregeneratedRandomData.Alpha;
                beta1 = pregeneratedRandomData.Beta1;
                beta2 = pregeneratedRandomData.Beta2;
            }

            h = new GroupElement[numberOfTokens];
            t1 = new GroupElement[numberOfTokens];
            // we don't compute t2 in the precomputation since we prefer to
            // compute h^beta2 as part of the sigmaBPrime multi-exponentiation
            ukat = new UProveKeyAndToken[numberOfTokens];
            for (int i = 0; i < numberOfTokens; i++)
            {
                ukat[i] = new UProveKeyAndToken();
                h[i] = gamma.Exponentiate(alpha[i].Multiply(beta0Inverse));     // remove collab issuance blind, if present
                t1[i] = Gq.MultiExponentiate(new GroupElement[] { ip.G[0], Gq.G }, new FieldZqElement[] { beta1[i], beta2[i] });
                ukat[i].PrivateKey = alpha[i].Invert();
            }
            state = State.Initialized;
        }

        /// <summary>
        /// Generates the second issuance message.
        /// </summary>
        /// <param name="message">The first issuance message.</param>
        /// <returns>The second issuance message.</returns>
        public SecondIssuanceMessage GenerateSecondMessage(FirstIssuanceMessage message)
        {
            if (state != State.Initialized)
            {
                throw new InvalidOperationException("Prover not initialized properly");
            }

            Group Gq = ip.Gq;
            this.sigmaZ = message.sigmaZ.Exponentiate(beta0Inverse);        // remove the blind that was included in gamma (if no blind beta0Inverse = 1)

            sigmaZPrime = new GroupElement[numberOfTokens];
            sigmaAPrime = new GroupElement[numberOfTokens];
            sigmaBPrime = new GroupElement[numberOfTokens];
            sigmaCPrime = new FieldZqElement[numberOfTokens];
            FieldZqElement[] sigmaC = new FieldZqElement[numberOfTokens];
            for (int i = 0; i < numberOfTokens; i++)
            {
                FieldZqElement sigmaBExponent = alpha[i].Multiply(beta0Inverse);  // will remove the collab-issuance blind, if present

                sigmaZPrime[i] = this.sigmaZ.Exponentiate(alpha[i]);
                sigmaAPrime[i] = t1[i] * message.sigmaA[i];
                sigmaBPrime[i] = Gq.MultiExponentiate(new GroupElement[] { sigmaZPrime[i], h[i], message.sigmaB[i] }, new FieldZqElement[] { beta1[i], beta2[i], sigmaBExponent });
                HashFunction hash = ip.HashFunction;
                hash.Hash(h[i]);
                hash.Hash(PI);
                hash.Hash(sigmaZPrime[i]);
                hash.Hash(sigmaAPrime[i]);
                hash.Hash(sigmaBPrime[i]);
                sigmaCPrime[i] = ip.Zq.GetElementFromDigest(hash.Digest);
                sigmaC[i] = sigmaCPrime[i] + beta1[i];
            }
            state = State.Second;
            return new SecondIssuanceMessage(sigmaC);
        }

        /// <summary>
        /// Get the issuance state after the second message generation.
        /// </summary>
        /// <returns>The issuance state after the second message generation.</returns>
        public PostSecondMessageState ExportPostSecondMessageState()
        {
            if (state != State.Second)
            {
                throw new InvalidOperationException("GenerateSeondMessage must be called first");
            }

            PostSecondMessageState psms = new PostSecondMessageState();
            psms.TI = TI;
            psms.PI = PI;
            FieldZqElement[] alphaInverse = new FieldZqElement[numberOfTokens];
            for (int i = 0; i < numberOfTokens; i++)
            {
                alphaInverse[i] = ukat[i].PrivateKey;
            }
            psms.AlphaInverse = alphaInverse;
            psms.Beta2 = beta2;
            psms.H = h;
            psms.SigmaZPrime = sigmaZPrime;
            psms.SigmaAPrime = sigmaAPrime;
            psms.SigmaBPrime = sigmaBPrime;
            psms.SigmaCPrime = sigmaCPrime;
            psms.IsDeviceProtected = isDeviceProtected;

            // we update the state so this object cannot be used by mistake to complete the issuance
            // (we don't want the same randomizers to be used twice on two issuer-provided messages)
            state = State.Tokens;

            return psms;
        }

        /// <summary>
        /// Generates the U-Prove key and tokens.
        /// </summary>
        /// <param name="message">The third issuance message.</param>
        /// <param name="skipTokenValidation">Set to <code>true</code> to skip token validation;
        /// <code>false</code> otherwise. Token validation SHOULD be performed before use, either
        /// by setting <code>skipTokenValidation</code> to <code>false</code>, or by later using the 
        /// <code>ProtocolHelper.VerifyTokenSignature</code> method.
        /// </param>
        /// <exception cref="InvalidUProveArtifactException">If the token signature is invalid.</exception>
        /// <returns>An array of U-Prove keys and tokens</returns>
        public UProveKeyAndToken[] GenerateTokens(ThirdIssuanceMessage message, bool skipTokenValidation = false)
        {
            if (state != State.Second)
            {
                throw new InvalidOperationException("GenerateSecondMessage must be called first");
            }

            bool doBatchValidation = !skipTokenValidation && batchValidationSecurityLevel > 0;
            bool doNormalValidation = !skipTokenValidation && batchValidationSecurityLevel <= 0;

            Group Gq = ip.Gq;
            FieldZq Zq = ip.Zq;
            FieldZqElement[] sigmaRPrime = new FieldZqElement[numberOfTokens];

            FieldZqElement phoAR = Zq.Zero, phoR = Zq.Zero, phoAC = Zq.Zero, phoC = Zq.Zero;
            GroupElement[] batchAccBases = new GroupElement[numberOfTokens];
            FieldZqElement[] s = null;
            if (!skipTokenValidation)
            {
                s = Zq.GetRandomElements(numberOfTokens, true, batchValidationSecurityLevel);
            }
            for (int i = 0; i < numberOfTokens; i++)
            {
                sigmaRPrime[i] = message.sigmaR[i] + beta2[i];
                if (doBatchValidation)
                {
                    phoAR += (s[i] * alpha[i] * sigmaRPrime[i]);
                    phoR += (s[i] * sigmaRPrime[i]);
                    phoAC += (s[i] * alpha[i] * sigmaCPrime[i]);
                    phoC += (s[i] * sigmaCPrime[i]);
                    batchAccBases[i] = sigmaAPrime[i] * sigmaBPrime[i];
                }
                else if (doNormalValidation)
                {
                    if (!(sigmaAPrime[i] * sigmaBPrime[i]).Equals(
                            Gq.MultiExponentiate(new GroupElement[] { Gq.G * h[i], ip.G[0] * sigmaZPrime[i] },
                                                  new FieldZqElement[] { sigmaRPrime[i], sigmaCPrime[i].Negate() })))
                    {
                        throw new InvalidUProveArtifactException("Invalid token signature: " + i);
                    }
                }
                ukat[i].Token = new UProveToken(ip.UidP, h[i], TI, PI, sigmaZPrime[i], sigmaCPrime[i], sigmaRPrime[i], isDeviceProtected);
            }
            if (doBatchValidation &&
                (Gq.MultiExponentiate(batchAccBases, s) !=
                 Gq.MultiExponentiate(new GroupElement[] { Gq.G, gamma, ip.G[0], sigmaZ },
                                      new FieldZqElement[] { phoR, phoAR, phoC.Negate(), phoAC.Negate() })))      // TODO: batch validation with blinded gamma needs to multiply beta0inverse to phoAR
            {
                throw new InvalidUProveArtifactException("Invalid token signature");
            }

            state = State.Tokens;
            return ukat;
        }

    }
}
