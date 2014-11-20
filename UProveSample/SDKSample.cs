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

using IDEscrow;
using System;
using System.Collections.Generic;
using UProveCrypto;
using UProveCrypto.DVARevocation;
using UProveCrypto.Math;
using UProveCrypto.PolyProof;

namespace UProveSample
{
    /// <summary>
    /// Illustrates how to use the U-Prove SDK, including extensions
    /// for revocation and identity escrow. 
    /// </summary>
    public class SDKSample
    {
        static System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();

        static byte[] HexToBytes(string hexString)
        {
            int length = hexString.Length;
            if ((length % 2) != 0)
            {
                // prepend 0
                hexString = "0" + hexString;
            }

            byte[] bytes = new byte[hexString.Length / 2];
            for (int i = 0; i < length; i += 2)
            {
                try
                {
                    bytes[i / 2] = Byte.Parse(hexString.Substring(i, 2), System.Globalization.NumberStyles.HexNumber);
                }
                catch (Exception)
                {
                    throw new ArgumentException("hexString is invalid");
                }
            }
            return bytes;
        }

        static private System.Security.Cryptography.RNGCryptoServiceProvider rng = new System.Security.Cryptography.RNGCryptoServiceProvider();
        // generates a random message with 20 random bytes and a timestamp
        private static byte[] GenerateNoncePlusTimestampMessage()
        {
            // get timestamp
            byte[] timestamp = encoding.GetBytes(DateTime.Now.ToUniversalTime().ToString());
            byte[] message = new byte[20 + timestamp.Length];
            // fill the message with random bytes
            rng.GetBytes(message);
            Array.Copy(timestamp, 0, message, 20, timestamp.Length);
            return message;
        }

        private static IssuerKeyAndParameters SetupUProveIssuer(string UIDP, int numberOfAttributes, GroupType groupType = GroupType.Subgroup, bool supportDevice = false)
        {
            WriteLine("Setting up Issuer parameters");
            IssuerSetupParameters isp = new IssuerSetupParameters();
            // pick a unique identifier for the issuer params
            isp.UidP = encoding.GetBytes(UIDP);
            // set the number of attributes in the U-Prove tokens
            isp.NumberOfAttributes = numberOfAttributes;
            // an application profile would define the format of the specification field,
            // we use a dummy value in this sample
            isp.S = encoding.GetBytes("application-specific specification");
            // specify the group type: subgroup (default) or ECC
            isp.GroupConstruction = groupType;

            return isp.Generate(supportDevice);
        }

        private static UProveKeyAndToken[] IssueUProveTokens(IssuerKeyAndParameters ikap, IssuerParameters ip, byte[][] attributes, int numOfTokens, byte[] ti = null, byte[] pi = null)
        {
            WriteLine("Issuing " + numOfTokens + " tokens");
            // setup the issuer and generate the first issuance message
            IssuerProtocolParameters ipp = new IssuerProtocolParameters(ikap);
            ipp.Attributes = attributes;
            ipp.NumberOfTokens = numOfTokens;
            ipp.TokenInformation = ti;
            Issuer issuer = ipp.CreateIssuer();
            string firstMessage = CryptoSerializer.Serialize<FirstIssuanceMessage>(issuer.GenerateFirstMessage());

            // setup the prover and generate the second issuance message
            ProverProtocolParameters ppp = new ProverProtocolParameters(ip);
            ppp.Attributes = attributes;
            ppp.NumberOfTokens = numOfTokens;
            ppp.TokenInformation = ti;
            ppp.ProverInformation = pi;
            Prover prover = ppp.CreateProver();
            string secondMessage = CryptoSerializer.Serialize<SecondIssuanceMessage>(prover.GenerateSecondMessage(ip.Deserialize<FirstIssuanceMessage>(firstMessage)));

            // generate the third issuance message
            string thirdMessage = CryptoSerializer.Serialize<ThirdIssuanceMessage>(issuer.GenerateThirdMessage(ip.Deserialize<SecondIssuanceMessage>(secondMessage)));

            // generate the tokens
            return prover.GenerateTokens(ip.Deserialize<ThirdIssuanceMessage>(thirdMessage));
        }

        private static CommitmentPrivateValues PresentUProveToken(IssuerParameters ip, UProveKeyAndToken upkt, byte[][] attributes, int[] disclosed, int[] committed, byte[] message, byte[] scope, IDevice device, byte[] deviceMessage)
        {
            ProverPresentationProtocolParameters pppp;
            VerifierPresentationProtocolParameters vppp;
            PresentationProof proof;
            return PresentUProveToken(ip, upkt, attributes, disclosed, committed, message, scope, device, deviceMessage, out pppp, out vppp, out proof);
        }

        private static CommitmentPrivateValues PresentUProveToken(IssuerParameters ip, UProveKeyAndToken upkt, byte[][] attributes, int[] disclosed, int[] committed, byte[] message, byte[] scope, IDevice device, byte[] deviceMessage, out ProverPresentationProtocolParameters pppp, out VerifierPresentationProtocolParameters vppp, out PresentationProof proof)
        {
            WriteLine("Presenting one token");
            // the returned commitment randomizer (to be used by an external proof module)
            CommitmentPrivateValues cpv;

            // generate the presentation proof
            string token = CryptoSerializer.Serialize<UProveToken>(upkt.Token);
            pppp = new ProverPresentationProtocolParameters(ip, disclosed, message, upkt, attributes);
            pppp.Committed = committed;
            // if a scope is defined, we use the first attribute to derive a scope exclusive pseudonym            
            pppp.PseudonymAttributeIndex = (scope == null ? 0 : 1);
            pppp.PseudonymScope = scope;
            if (device != null)
            {
                pppp.SetDeviceData(deviceMessage, device.GetPresentationContext());
            }
            proof = PresentationProof.Generate(pppp, out cpv);
            string jsonProof = CryptoSerializer.Serialize<PresentationProof>(proof);

            // verify the presentation proof
            vppp = new VerifierPresentationProtocolParameters(ip, disclosed, message, ip.Deserialize<UProveToken>(token));
            vppp.Committed = committed;
            // if a scope is defined, we use the first attribute to derive a scope exclusive pseudonym
            vppp.PseudonymAttributeIndex = (scope == null ? 0 : 1);
            vppp.PseudonymScope = scope;
            vppp.DeviceMessage = deviceMessage;
            ip.Deserialize<PresentationProof>(jsonProof).Verify(vppp);

            return cpv;
        }

        /// <summary>
        /// This sample illustrates how to issue and present software-only U-Prove tokens.
        /// </summary>
        public static void SoftwareOnlySample()
        {
            WriteLine("U-Prove SDK Sample");
            
            /*
             *  issuer setup
             */
            IssuerKeyAndParameters ikap = SetupUProveIssuer("sample software-only issuer", 3, GroupType.ECC);
            string privateKeyBase64 = ikap.PrivateKey.ToBase64String(); // this needs to be stored securely
            string ipJSON = ikap.IssuerParameters.Serialize();

            // the IssuerParameters instance needs to be distributed to the Prover and Verifier.
            // Each needs to verify the parameters before using them
            IssuerParameters ip = new IssuerParameters(ipJSON);
            ip.Verify();

            /*
             *  token issuance
             */
            // specify the attribute values agreed to by the Issuer and Prover
            byte[][] attributes = new byte[][] {
                    encoding.GetBytes("first attribute value"),
                    encoding.GetBytes("second attribute value"),
                    encoding.GetBytes("third attribute value")
            };
            // specify the special field values
            byte[] tokenInformation = encoding.GetBytes("token information value");
            byte[] proverInformation = encoding.GetBytes("prover information value");
            // specify the number of tokens to issue
            int numberOfTokens = 5;

            UProveKeyAndToken[] upkt = IssueUProveTokens(new IssuerKeyAndParameters(privateKeyBase64, ipJSON), ip, attributes, numberOfTokens, tokenInformation, proverInformation);           

            /*
             *  token presentation
             */
            // the indices of disclosed attributes
            int[] disclosed = new int[] { 2 };
            // the indices of the committed attributes (used by protocol extensions)
            int[] committed = null;
            // the application-specific message that the prover will sign. Typically this is a nonce combined
            // with any application-specific transaction data to be signed.
            byte[] message = GenerateNoncePlusTimestampMessage();
            // the application-specific verifier scope from which a scope-exclusive pseudonym will be created
            // (if null, then a pseudonym will not be presented)
            byte[] scope = encoding.GetBytes("verifier scope");

            PresentUProveToken(ip, upkt[0], attributes, disclosed, committed, message, scope, null, null);

            WriteLine("Sample completed.\n*************************************************************\n");
        }

        /// <summary>
        /// This sample illustrates how to use collaborative issuance to carry attributes from one
        /// token to another, and how to prove that they both contain the same attribute values without
        /// disclosing them.
        /// </summary>
        public static void CollaborativeIssuanceAndEqualitySample()
        {
            WriteLine("U-Prove Collaborative Issuance SDK Sample");

            /*
             *  Issuers setup. NOTE: both issuers MUST use the same recommended 
             *  parameters for collaborative issuance to work.
             */
            IssuerKeyAndParameters ikap1 = SetupUProveIssuer("issuer 1", 3);
            string ip1JSON = ikap1.IssuerParameters.Serialize();

            IssuerKeyAndParameters ikap2 = SetupUProveIssuer("issuer 2", 4);
            string ip2JSON = ikap2.IssuerParameters.Serialize();

            // the IssuerParameters instances needs to be distributed to the Prover and Verifier.
            // Each needs to verify the parameters before using them
            IssuerParameters ip1 = new IssuerParameters(ip1JSON);
            ip1.Verify();
            IssuerParameters ip2 = new IssuerParameters(ip2JSON);
            ip2.Verify();

            /*
             *  Alice gets a token from the 1st Issuer
             */
            byte[][] attributes = new byte[][] {
                encoding.GetBytes("attribute"),
                encoding.GetBytes("carried-over attribute"),  
                encoding.GetBytes("carried-over attribute 2"),  
            };
            int numberOfTokens = 1;
            UProveKeyAndToken[] upkt1 = IssueUProveTokens(ikap1, ip1, attributes, numberOfTokens, null, null);

            /*
             * Alice gets token from the 2nd Issuer, carrying attribute from the 1st token
             */
            WriteLine("Prover Creating a pre-issuance proof");
            // First the Prover creates a PreIssuanceProof.  The proof assures the Issuer that the attributes chosen by the user are valid
            ProverPreIssuanceParameters ppip = new ProverPreIssuanceParameters(ip2);
            ppip.Attributes = new byte[][] { 
                encoding.GetBytes("carried-over attribute"), // carried-over attribute, unknown to issuer
                encoding.GetBytes("secret attribute"), // unknown to issuer
                encoding.GetBytes("known attribute"), // known to issuer
                encoding.GetBytes("carried-over attribute 2")}; // carried-over attribute, unknown to issuer
            // The first and fourth attributes in the new token will be carried over from the old token
            // The issuer will not see the attribute values, but will be assured they come from a token it issued. 
            int[] sourceIndex = new int[] { 2, 3 };        // index of the attribute in the source token
            int[] destIndex = new int[] { 1, 4 };          // index of the attribute in the new token
            ppip.CarryOverAttribute(sourceIndex, destIndex, ip1, upkt1[0], attributes);     // Note these are the attributes in the source token
            // The second attribute will be a secret, known only to the prover.  It can be anything it chooses
            ppip.U = new int[] { 2 };           // Attributes _U_nknown to the Issuer
            // The third attribute will be _K_nown to the Issuer
            ppip.K = new int[] { 3 };
            byte[] message = encoding.GetBytes("Optional Message");

            FieldZqElement beta0; // this is a Prover secret created in the PreIssuanceProof that must be used during during the Issuance protocol, to link them together
            PreIssuanceProof proof = PreIssuanceProof.CreateProof(ppip, out beta0, message);

            // The proof and token are serialized and sent to the Issuer
            string _proof = ip2.Serialize<PreIssuanceProof>(proof);
            string _token = ip1.Serialize<UProveToken>(upkt1[0].Token);

            // --- Issuer steps ---
            // Deserialize
            WriteLine("Issuer verifies the pre-issuance proof");
            UProveToken receivedToken = ip1.Deserialize<UProveToken>(_token);
            PreIssuanceProof receivedProof = ip2.Deserialize<PreIssuanceProof>(_proof);

            // Create params -- same as Prover except two of the attributes are null, and the UProveKeyAndToken is replaced with a Token.
            IssuerPreIssuanceParameters ipip = new IssuerPreIssuanceParameters(ip2);
            ipip.Attributes = new byte[][] { null, null, encoding.GetBytes("known attribute"), null }; // only 3rd is known to the Issuer
            ipip.CarryOverAttribute(sourceIndex, destIndex, ip1, receivedToken);
            ipip.U = ppip.U;
            ipip.K = ppip.K;

            // Verify the proof.  If it succceds, a value is output for the Issuer to use in the Issuance protocol
            GroupElement blindedGamma = PreIssuanceProof.VerifyProof(ipip, receivedProof, message);
            if (blindedGamma == null)
            {
                // the proof is invalid
                throw new InvalidProgramException("Invalid PreIssuance proof -- Collaborative issuance sample failed");
            }
            // Collaborative Issuance 
            WriteLine("Prover and Issuer run the Issuance protocol");
            numberOfTokens = 2;
            IssuerProtocolParameters ipp2 = new IssuerProtocolParameters(ikap2);
            ipp2.NumberOfTokens = numberOfTokens;
            ipp2.Gamma = blindedGamma; // To the issuer the Issuance protocol is the same, except gamma is blinded.
            Issuer issuer2 = ipp2.CreateIssuer();
            FirstIssuanceMessage msg1_2 = issuer2.GenerateFirstMessage();

            ProverProtocolParameters ppp2 = new ProverProtocolParameters(ip2);
            ppp2.Attributes = attributes;
            ppp2.NumberOfTokens = numberOfTokens;
            ppp2.SetBlindedGamma(proof.GetBlindedGamma(), beta0); // The prover must use the values from the PreIssuanceProof.  After recieving the tokens, they may be deleted
            Prover prover2 = ppp2.CreateProver();
            SecondIssuanceMessage msg2_2 = prover2.GenerateSecondMessage(msg1_2);
            ThirdIssuanceMessage msg3_2 = issuer2.GenerateThirdMessage(msg2_2);
            UProveKeyAndToken[] upkt2 = prover2.GenerateTokens(msg3_2);

            /*
             *  token presentation -- same as when collaborative issuance is not used.
             */
            WriteLine("Presenting both tokens, proving that they share an attribute value");
            // the indices of the committed attributes (used by protocol extensions)
            PresentationProof proof1, proof2;
            ProverPresentationProtocolParameters pppp1, pppp2;
            VerifierPresentationProtocolParameters vppp1, vppp2;
            CommitmentPrivateValues cpv1 = PresentUProveToken(ip1, upkt1[0], attributes, null, sourceIndex, GenerateNoncePlusTimestampMessage(), null, null, null, out pppp1, out vppp1, out proof1);
            CommitmentPrivateValues cpv2 = PresentUProveToken(ip2, upkt2[0], ppip.Attributes, null, destIndex, GenerateNoncePlusTimestampMessage(), null, null, null, out pppp2, out vppp2, out proof2);
            WriteLine("Validate the equality proofs");
            for (int i = 0; i < sourceIndex.Length; i++)
            {
                // generate equality proof
                EqualityProof eQProof = EqualityProof.GenerateUProveEqualityProof(
                    new EQProofUProveProverData(pppp1, cpv1, proof1, sourceIndex[i]),
                    new EQProofUProveProverData(pppp2, cpv2, proof2, destIndex[i]));
                string jsonEQProof = ip1.Serialize<EqualityProof>(eQProof);

                EqualityProof receivedEQProof = ip1.Deserialize<EqualityProof>(jsonEQProof);
                EqualityProof.VerifyUProveEqualityProof(
                    new EQProofUProveVerifierData(vppp1, proof1, sourceIndex[i]),
                    new EQProofUProveVerifierData(vppp2, proof2, destIndex[i]),
                    receivedEQProof);
            }
            WriteLine("Sample completed.\n*************************************************************\n");
        }


        /// <summary>
        /// This sample illustrates how to issue and present device-protected U-Prove tokens.
        /// </summary>
        public static void DeviceSample()
        {

            WriteLine("U-Prove SDK Device Sample");

            /*
             *  issuer setup
             */

            IssuerKeyAndParameters ikap = SetupUProveIssuer("sample device-protected issuer", 3, GroupType.ECC, true);
            string ipJSON = ikap.IssuerParameters.Serialize();

            // the IssuerParameters instance needs to be distributed to the Prover, Device, and Verifier.
            // Each needs to verify the parameters before using them
            IssuerParameters ip = new IssuerParameters(ipJSON);
            ip.Verify();


            /*
             * device provisioning
             */

            // generate a new device
            IDevice device = new VirtualDevice(ip);
            // get the device public key
            GroupElement hd = device.GetDevicePublicKey();


            /*
             *  token issuance
             */

            // specify the attribute values
            byte[][] attributes = new byte[][] {
                    encoding.GetBytes("first attribute value"),
                    encoding.GetBytes("second attribute value"),
                    encoding.GetBytes("third attribute value"),
            };
            // specify the special field values
            byte[] tokenInformation = encoding.GetBytes("token information value");
            byte[] proverInformation = encoding.GetBytes("prover information value");
            // specify the number of tokens to issue
            int numberOfTokens = 5;

            UProveKeyAndToken[] upkt = IssueUProveTokens(ikap, ip, attributes, numberOfTokens, tokenInformation, proverInformation);


            /*
             *  token presentation
             */

            // the indices of disclosed attributes
            int[] disclosed = new int[] { 2 };
            // the application-specific messages that the prover and device will sign, respectively. Typically this 
            // is a nonce combined with any application-specific transaction data to be signed.
            byte[] message = GenerateNoncePlusTimestampMessage();
            byte[] deviceMessage = encoding.GetBytes("message for device");

            PresentUProveToken(ip, upkt[0], attributes, disclosed, null, message, null, device, deviceMessage);

            WriteLine("Sample completed.\n*************************************************************\n");
        }

        /// <summary>
        /// This sample illustrates how to issue and present software-only U-Prove tokens and how to revoke
        /// them using the accumulator extension. In this sample, the Issuer also plays the role of the
        /// Revocation Authority and the Verifier.
        /// </summary>
        public static void AccumulatorRevocationSample()
        {

            WriteLine("U-Prove SDK Accumulator Revocation Sample");

            //
            //  issuer / revocation authority setup
            //

            // generate the issuer and revocation authority parameters, and serialize them
            int revocationAttributeIndex = 1;
            IssuerKeyAndParameters ikap = SetupUProveIssuer("sample revocation issuer", 1, GroupType.ECC);
            RevocationAuthority RA = RevocationAuthority.GenerateRevocationAuthority(ikap.IssuerParameters);
            string ipJSON = ikap.IssuerParameters.Serialize();
            string rapJSON = ikap.IssuerParameters.Serialize<RAParameters>(RA.RAParameters);

            // pre-revoke some users
            string[] revokedUsers = new string[] { "Bob", "Charlie", "Dan", "Eric" };
            HashSet<FieldZqElement> revocationSet = new HashSet<FieldZqElement>();
            foreach (string revokedUser in revokedUsers)
            {
                revocationSet.Add(RevocationAuthority.ComputeRevocationValue(ikap.IssuerParameters, revocationAttributeIndex, encoding.GetBytes(revokedUser)));
            }
            RA.UpdateAccumulator(revocationSet);

            // the IssuerParameters and RAParameters instances are distributed to the Prover
            IssuerParameters ip = new IssuerParameters(ipJSON);
            ip.Verify();
            RAParameters rap = ip.Deserialize<RAParameters>(rapJSON);

            // tokens are issued with the revocation attribute set to the user name
            // (must be unique in the application)
            byte[][] attributes = new byte[][] { encoding.GetBytes("Alice") };
            int numberOfTokens = 2;
            UProveKeyAndToken[] upkt = IssueUProveTokens(ikap, ip, attributes, numberOfTokens);

            //
            // User periodically obtains the latest revocation witness for her revocation attribute
            //
            RevocationWitness witness = RA.ComputeRevocationWitness(
                revocationSet,
                RevocationAuthority.ComputeRevocationValue(ip, revocationAttributeIndex, attributes[revocationAttributeIndex - 1]));
            string witnessJSON = CryptoSerializer.Serialize<RevocationWitness>(witness); // sent to Prover
            RevocationWitness receivedWitness = ip.Deserialize<RevocationWitness>(witnessJSON);

            //
            //  Token presentation with non-revocation proof
            //
            WriteLine("Presenting a non-revoked U-Prove token for Alice");
            CommitmentPrivateValues cpv;
            byte[] message = GenerateNoncePlusTimestampMessage();
            int[] disclosed = null;
            int[] committed = new int[] { 1 };
            int revocationCommitmentIndex = 0;

            // generate the presentation proof (normal U-Prove way)
            int usedToken = 0;
            ProverPresentationProtocolParameters pppp = new ProverPresentationProtocolParameters(ip, disclosed, message, upkt[usedToken], attributes);
            pppp.Committed = committed;
            PresentationProof presentationProof = PresentationProof.Generate(pppp, out cpv);
            NonRevocationProof nrp = RevocationUser.GenerateNonRevocationProof(ip, rap, receivedWitness, revocationCommitmentIndex, presentationProof, cpv, revocationAttributeIndex, attributes);
            string tokenJSON = CryptoSerializer.Serialize<UProveToken>(upkt[usedToken].Token);
            string proofJSON = CryptoSerializer.Serialize<PresentationProof>(presentationProof);
            string nrProofJSON = CryptoSerializer.Serialize<NonRevocationProof>(nrp);

            // Verify the presentation and non-revocation proof 
            UProveToken receivedToken = ip.Deserialize<UProveToken>(tokenJSON);
            PresentationProof receivedPresentationProof = ip.Deserialize<PresentationProof>(proofJSON);
            NonRevocationProof receivedNonRevocationProof = ip.Deserialize<NonRevocationProof>(nrProofJSON);
            VerifierPresentationProtocolParameters vppp = new VerifierPresentationProtocolParameters(ip, disclosed, message, receivedToken);
            vppp.Committed = committed;
            receivedPresentationProof.Verify(vppp);
            RA.VerifyNonRevocationProof(ip, revocationCommitmentIndex, receivedPresentationProof, receivedNonRevocationProof);
            WriteLine("Proof of non-revocation passed (as expected)");

            //
            // revoke Alice
            //
            WriteLine("Revoking Alice");
            FieldZqElement aliceRevocationValue = RevocationAuthority.ComputeRevocationValue(ikap.IssuerParameters, revocationAttributeIndex, encoding.GetBytes("Alice"));
            revocationSet.Add(aliceRevocationValue);
            RA.UpdateAccumulator(aliceRevocationValue);
            WriteLine("Computing non revocation witness for Alice should fail");
            try
            {
                witness = RA.ComputeRevocationWitness(
                                revocationSet,
                                RevocationAuthority.ComputeRevocationValue(ip, revocationAttributeIndex, attributes[revocationAttributeIndex - 1]));
                WriteLine("non revocation witness for Alice computed successfully (Unexpected, the sample is broken)", true);
            }
            catch (ArgumentException e)
            {
                WriteLine("Indeed, it failed: " + e.Message);
            }

            WriteLine("Regardless, Alice tries to generate a non-revocation proof");

            // generate the presentation proof
            pppp.KeyAndToken = upkt[++usedToken];
            presentationProof = PresentationProof.Generate(pppp, out cpv);
            // Generate and serialize revocation proof. Alice will try using the old witness she created for the previous
            // revocation list, that was current when she wasn't revoked. 
            nrp = RevocationUser.GenerateNonRevocationProof(ip, rap, receivedWitness, revocationCommitmentIndex, presentationProof, cpv, revocationAttributeIndex, attributes);
            tokenJSON = CryptoSerializer.Serialize<UProveToken>(upkt[usedToken].Token);
            proofJSON = CryptoSerializer.Serialize<PresentationProof>(presentationProof);
            nrProofJSON = CryptoSerializer.Serialize<NonRevocationProof>(nrp);

            WriteLine("The verification of the presentation proof still passes");
            receivedToken = ip.Deserialize<UProveToken>(tokenJSON);
            receivedPresentationProof = ip.Deserialize<PresentationProof>(proofJSON);
            vppp.Token = receivedToken;
            receivedPresentationProof.Verify(vppp);

            WriteLine("But the verification of the non revocation proof should fail");
            try
            {
                receivedNonRevocationProof = ip.Deserialize<NonRevocationProof>(nrProofJSON);
                RA.VerifyNonRevocationProof(ip, revocationCommitmentIndex, receivedPresentationProof, receivedNonRevocationProof);
                WriteLine("Verification of the non revocation proof did not fail.  (Unexpected, the sample is broken)", true);
            }
            catch (InvalidUProveArtifactException e)
            {
                WriteLine("Indeed, it failed: " + e.Message);
            }

            WriteLine("Sample completed.\n*************************************************************\n");
        }

        /// <summary>
        /// This sample illustrates how to issue and present software-only U-Prove tokens and how to revoke
        /// them using the inequality proof extension. 
        /// </summary>
        public static void InequalityRevocationSample()
        {
            WriteLine("U-Prove SDK Inequality Revocation Sample");

            //
            //  issuer setup
            //
            IssuerKeyAndParameters ikap = SetupUProveIssuer("sample revocation issuer", 1, GroupType.ECC);
            string ipJSON = ikap.IssuerParameters.Serialize();

            // the IssuerParameters instance is distributed to the Prover and Verifier
            IssuerParameters ip = new IssuerParameters(ipJSON);
            ip.Verify();

            // tokens are issued with the revocation attribute set to the user name 
            // (must be unique in the application)
            byte[][] attributes = new byte[][] { encoding.GetBytes("Alice") };
            int numberOfTokens = 1;
            UProveKeyAndToken[] upkt = IssueUProveTokens(ikap, ip, attributes, numberOfTokens);

            // revoke some users
            byte[][] revokedValues = new byte[][] { encoding.GetBytes("Bob"), encoding.GetBytes("Charlie"), encoding.GetBytes("Dan"), encoding.GetBytes("Eric") };

            //
            //  Token presentation with non-revocation proof
            //
            WriteLine("Presenting a non-revoked U-Prove token for Alice");
            CommitmentPrivateValues cpv;
            byte[] message = GenerateNoncePlusTimestampMessage();
            int[] disclosed = null;
            int[] committed = new int[] { 1 };

            // generate the presentation proof and the inequality proofs
            int usedToken = 0;
            ProverPresentationProtocolParameters pppp = new ProverPresentationProtocolParameters(ip, disclosed, message, upkt[usedToken], attributes);
            pppp.Committed = committed;
            PresentationProof presentationProof = PresentationProof.Generate(pppp, out cpv);
            InequalityProof[] nrProofs = InequalityProof.GenerateUProveInequalityProofs(new EQProofUProveProverData(pppp, cpv, presentationProof, 1), revokedValues);
            string tokenJSON = CryptoSerializer.Serialize<UProveToken>(upkt[usedToken].Token);
            string proofJSON = CryptoSerializer.Serialize<PresentationProof>(presentationProof);
            string[] nrProofJSON = new string[nrProofs.Length];
            for (int i = 0; i < nrProofs.Length; i++) { nrProofJSON[i] = CryptoSerializer.Serialize<InequalityProof>(nrProofs[i]); }

            // Verify the presentation and non-revocation proof 
            UProveToken receivedToken = ip.Deserialize<UProveToken>(tokenJSON);
            PresentationProof receivedPresentationProof = ip.Deserialize<PresentationProof>(proofJSON);
            InequalityProof[] receivedNonRevocationProofs = new InequalityProof[nrProofJSON.Length];
            for (int i = 0; i < nrProofJSON.Length; i++) { ip.Deserialize<InequalityProof>(nrProofJSON[i]); }
            VerifierPresentationProtocolParameters vppp = new VerifierPresentationProtocolParameters(ip, disclosed, message, receivedToken);
            vppp.Committed = committed;
            receivedPresentationProof.Verify(vppp);
            InequalityProof.VerifyUProveEqualityProofs(new EQProofUProveVerifierData(vppp, presentationProof, 1), revokedValues, nrProofs);

            WriteLine("Proof of non-revocation passed (as expected)");

            WriteLine("Sample completed.\n*************************************************************\n");

        }


        /// <summary>
        /// Simple database class to hold a table of pairs (pseudonym, real identity), used
        /// for ID escrow.  When the auditor decrypts an encrypted identity, it's actually
        /// a pseudoym.  The link between nym and real ID is stored in the <c>IDEscrowDB</c>
        /// </summary>
        class IDEscrowDB
        {
            IDEscrowParams ieParams;
            System.Collections.Generic.Dictionary<GroupElement, string> users = new System.Collections.Generic.Dictionary<GroupElement, string>();
            internal IDEscrowDB(IDEscrowParams ieParams)
            {
                if (ieParams == null)
                {
                    throw new ArgumentNullException();
                }
                this.ieParams = ieParams;
            }

            internal void AddUser(string userID)
            {
                users.Add(
                    // the pseudonym that would be decrypted by auditor
                    ieParams.Ge.Exponentiate(ProtocolHelper.ComputeXi(ieParams.ip, 0, encoding.GetBytes(userID))),
                    // the corresponding user ID
                    userID);
            }

            internal string GetUser(GroupElement PE)
            {
                string id;
                if (!users.TryGetValue(PE, out id))
                {
                    throw new ArgumentException("Pseudonym not in DB");
                }
                return id;
            }
        }

        /// <summary>
        /// This sample illustrates how to issue and present software-only U-Prove tokens supporting ID escrow.
        /// </summary>
        public static void IDEscrowSample()
        {
            WriteLine("U-Prove ID Escrow Sample");

            /*
             *  issuer setup (normal U-Prove process)
             */
            
            // generate the issuer parameters
            IssuerKeyAndParameters ikap = SetupUProveIssuer("sample ID Escrow issuer", 3);
            
            // serialize and send the issuer parameters to the Prover, Verifier, and Auditor
            string ipJSON = ikap.IssuerParameters.Serialize();
            // ... send on wire ...            
            IssuerParameters ip = new IssuerParameters(ipJSON); // for simplicity, they share the parameters in this sample
            // Each party needs to verify the parameters before using them
            ip.Verify();


            /*
             * auditor setup
             */

            // generate the id escrow parameters and Autitor key pair 
            IDEscrowParams ieParams = new IDEscrowParams(ip);
            IDEscrowPrivateKey escrowPrivateKey = new IDEscrowPrivateKey(ieParams);
            IDEscrowPublicKey _escrowPublicKey = new IDEscrowPublicKey(ieParams, escrowPrivateKey);
            
            // serialize the id escrow parameters and public key, and send them to Prover and Verifier
            // Authenticating the parameters and public key is omitted from the sample, but must be
            // done for the scheme to be secure. 
            string ieParamJSON = ip.Serialize(ieParams);
            string escrowPublicKeyJSON = ip.Serialize(_escrowPublicKey);
            // ... send on wire ...
            IDEscrowParams escrowParams = ip.Deserialize<IDEscrowParams>(ieParamJSON);
            IDEscrowPublicKey escrowPublicKey = ip.Deserialize<IDEscrowPublicKey>(escrowPublicKeyJSON);

            /*
             *  token issuance
             */
            // The issuer maintains a DB of user IDs and corresponding pseudonyms. The auditor 
            // would decrypted a pseudonym, and the issuer would query it in this database to recover the 
            // user's true identity.
            IDEscrowDB escrowDB = new IDEscrowDB(escrowParams);
            // set up the attribute values for the user
            // the userID will be encrypted for the auditor, and decrypted in case of abuse/fraud
            string userID = "149833893"; 
            WriteLine("User ID: " + userID);
            // add the user to the escrow DB (the escrowDB will compute the pseudonym and store it with the userID)
            escrowDB.AddUser(userID);
            // specify the attribute values agreed to by the Issuer and Prover
            byte[][] attributes = new byte[][] {
                    encoding.GetBytes(userID), // User UID
                    encoding.GetBytes("Secret"), // clearance
                    encoding.GetBytes("USA") // country
            };
            // index of the ID attribute
            int idAttributeIndex = 1;
            // specify the number of tokens to issue
            int numberOfTokens = 1;

            UProveKeyAndToken[] upkt = IssueUProveTokens(ikap, ip, attributes, numberOfTokens);


            /*
             *  token presentation + ID escrow encryption
             */
            
            WriteLine("Presenting a U-Prove token with encrypted ID for auditor");

            // the indices of disclosed attributes
            int[] disclosed = new int[] { 2, 3 };
            // the indices of the committed attributes (the ID Escrow proof will use a committed attribute)
            int[] committed = new int[] { idAttributeIndex };
            // the application-specific message that the prover will sign. Typically this is a nonce combined
            // with any application-specific transaction data to be signed.
            byte[] message = GenerateNoncePlusTimestampMessage();
            // the ID escrow policy, e.g., a description of the conditions under which the identity may be revealed
            byte[] additionalInfo = encoding.GetBytes("<description of the application-specific auditor decryption policy>");

            // generate the presentation proof and ID encryption

            CommitmentPrivateValues cpv;        // commitment openings, output by Generate
            ProverPresentationProtocolParameters pppp = new ProverPresentationProtocolParameters(ip, disclosed, message, upkt[0], attributes);
            pppp.Committed = committed;
            PresentationProof proof = PresentationProof.Generate(pppp, out cpv);
            // The commitment to first attribute will be used for ID escrow

            // Encrypt the ID
            IDEscrowCiphertext ctext = IDEscrowFunctions.UProveVerifableEncrypt(escrowParams, escrowPublicKey, upkt[0].Token, 
                                                                  additionalInfo, proof, cpv, idAttributeIndex, attributes);

            // send presentation proof and ciphertext to verifier (send proof and ctext)
            string tokenJSON = CryptoSerializer.Serialize<UProveToken>(upkt[0].Token);
            string proofJSON = CryptoSerializer.Serialize<PresentationProof>(proof);
            string ctextJSON = CryptoSerializer.Serialize<IDEscrowCiphertext>(ctext);

            // verify the presentation proof
            UProveToken vToken = ip.Deserialize<UProveToken>(tokenJSON);
            PresentationProof vProof = ip.Deserialize<PresentationProof>(proofJSON);
            IDEscrowCiphertext vCiphertext = ip.Deserialize<IDEscrowCiphertext>(ctextJSON);
            try
            {
                VerifierPresentationProtocolParameters vppp = new VerifierPresentationProtocolParameters(ip, disclosed, message, vToken);
                vppp.Committed = committed;
                vProof.Verify(vppp);
                WriteLine("Proof is valid.");
            }
            catch (InvalidUProveArtifactException)
            {
                WriteLine("Invalid proof. Sample failed!", true);
                return;
            }

            // verify the ID encryption
            if (!IDEscrowFunctions.UProveVerify(escrowParams, vCiphertext, vProof, vToken, escrowPublicKey))
            {
                WriteLine("Invalid encryption. Sample failed!", true);
                return;
            }
            else
            {
                WriteLine("ID escrow proof is valid too");
            }

            // if user commits fraud/abuse, violating the ID escrow policy, then the verifier sends
            // the ciphertext to the auditor for decryption
            
            
            /*
             * auditor decrypts the ciphertext containing the ID
             */ 

            // decrypt the pseudonym
            GroupElement PE = IDEscrowFunctions.Decrypt(ieParams, ip.Deserialize<IDEscrowCiphertext>(ctextJSON), escrowPrivateKey);
            // auditor sends the pseudonym to the issuer to reveal the user ID
            string peJSON = PE.ToBase64String();
            
            /*
             * Issuer identifies the user
             */

            string decryptedID = escrowDB.GetUser(peJSON.ToGroupElement(ip));
            WriteLine("UserID decrypted by auditor: " + decryptedID);

            WriteLine("Sample completed.\n*************************************************************\n");
        }



        enum Clearance : byte { UNCLASSIFIED, CONFIDENTIAL, SECRET, TOPSECRET };
        enum Attributes { NAME = 1, CLEARANCE, AFFILIATION, COUNTRY };
        /// <summary>
        /// This sample illustrates how to use the set membership extension. The user will prove that his
        /// security clearance is in a certain set.
        /// </summary>
        public static void SetMembershipSample()
        {
            WriteLine("U-Prove Set Membership Sample");

            /*
             *  token issuance (normal U-Prove process)
             */

            // generate the issuer parameters
            IssuerKeyAndParameters ikap = SetupUProveIssuer("sample set membership issuer", Enum.GetValues(typeof(Attributes)).Length, GroupType.ECC);

            // serialize and send the issuer parameters to the Prover and Verifier
            string ipJSON = ikap.IssuerParameters.Serialize();
            // ... send on wire ...            
            IssuerParameters ip = new IssuerParameters(ipJSON); // for simplicity, they share the parameters in this sample
            // Each party needs to verify the parameters before using them
            ip.Verify();
        
            // specify the attribute values agreed to by the Issuer and Prover
            byte[][] attributes = new byte[][] {
                    encoding.GetBytes("James Bond"), // Name
                    new byte[] {(byte) Clearance.TOPSECRET}, // clearance
                    encoding.GetBytes("MI6"), // affiliation
                    encoding.GetBytes("UK") // country
            };
            // specify the number of tokens to issue
            int numberOfTokens = 1;

            UProveKeyAndToken[] upkt = IssueUProveTokens(ikap, ip, attributes, numberOfTokens);

            /*
             *  token presentation + set membership proof
             */

            WriteLine("Presenting a U-Prove token proving that user is from USA and with at least a SECRET clearance");

            // the indices of disclosed attributes (the country attribute)
            int[] disclosed = new int[] { (int) Attributes.COUNTRY };
            // the indices of the committed attributes (the clearance attribute from which we'll make a set membership proof)
            int[] committed = new int[] { (int) Attributes.CLEARANCE };
            // authorized classification levels for resource
            byte[][] AuthorizedClassifications = new byte[][] { 
                new byte[] {(byte) Clearance.SECRET}, 
                new byte[] {(byte) Clearance.TOPSECRET}
            };
 
            // the application-specific message that the prover will sign. Typically this is a nonce combined
            // with any application-specific transaction data to be signed.
            byte[] message = GenerateNoncePlusTimestampMessage();

            // generate the presentation proof
            CommitmentPrivateValues cpv;
            ProverPresentationProtocolParameters pppp = new ProverPresentationProtocolParameters(ip, disclosed, message, upkt[0], attributes);
            pppp.Committed = committed;
            PresentationProof proof = PresentationProof.Generate(pppp, out cpv);
            string tokenJSON = CryptoSerializer.Serialize<UProveToken>(upkt[0].Token);
            string proofJSON = CryptoSerializer.Serialize<PresentationProof>(proof);

            // generate the set membership proof
            SetMembershipProof setMembershipProof = SetMembershipProof.Generate(pppp, proof, cpv, (int)Attributes.CLEARANCE, AuthorizedClassifications);
			string setProofJSON = CryptoSerializer.Serialize<SetMembershipProof>(setMembershipProof);

            // verify the presentation proof
            try
            {
                IssuerParameters vIP = new IssuerParameters(ipJSON);
                PresentationProof vProof = vIP.Deserialize<PresentationProof>(proofJSON);
                SetMembershipProof vSetProof = vIP.Deserialize<SetMembershipProof>(setProofJSON);

                VerifierPresentationProtocolParameters vppp = new VerifierPresentationProtocolParameters(vIP, disclosed, message, vIP.Deserialize<UProveToken>(tokenJSON));
                vppp.Committed = committed;
                vProof.Verify(vppp);
                if (!SetMembershipProof.Verify(vppp, vProof, vSetProof, (int)Attributes.CLEARANCE, AuthorizedClassifications))
                {
                    throw new InvalidUProveArtifactException("Invalid set membership proof");
                }

                WriteLine("Proof is valid.");
            }
            catch (InvalidUProveArtifactException e)
            {
                WriteLine("Invalid proof. Sample failed! " + e.Message, true);
                return;
            }

            WriteLine("Sample completed.\n*************************************************************\n");

        }

        private static DateTime MinBirthdate = new DateTime(1900, 1, 1);
        private static DateTime MaxBirthdate = new DateTime(2026, 12, 31);
        /// <summary>
        /// This sample illustrates how to use the range proof extension. The user will prove that
        /// she is over 21 of age.
        /// </summary>
        public static void RangeProofSample()
        {
            WriteLine("U-Prove Range Proof Sample");

            /*
             * issuer setup
             */

            IssuerSetupParameters isp = new IssuerSetupParameters();
            isp.UidP = encoding.GetBytes("sample range proof issuer");
            // specify the group type: subgroup (default) or ECC
            isp.UseRecommendedParameterSet = true;
            isp.E = new byte[] { 0 }; // 0 indicates that the attribute must be encoded directly (vs. hashed); this is needed for a range proof
            IssuerKeyAndParameters ikap = isp.Generate();

            /*
             *  token issuance
             */

            // generate the issuer parameters. the token encodes one attribute: the date of birth of the subject

            // serialize and send the issuer parameters to the Prover and Verifier
            string ipJSON = ikap.IssuerParameters.Serialize();
            // ... send on wire ...            
            IssuerParameters ip = new IssuerParameters(ipJSON); // for simplicity, they share the parameters in this sample
            // Each party needs to verify the parameters before using them
            ip.Verify();

            // specify the attribute values agreed to by the Issuer and Prover
            DateTime proverDOB = new DateTime(1970, 01, 23);
            WriteLine("Prover's DOB: " + proverDOB.ToShortDateString());
            int encodedProverBirthday = RangeProofParameterFactory.EncodeYearAndDay(proverDOB, MinBirthdate.Year);
            byte[] proverBirthdayAttribute = RangeProofParameterFactory.EncodeIntAsUProveAttribute(encodedProverBirthday);

            byte[][] attributes = new byte[][] { proverBirthdayAttribute };
            // specify the number of tokens to issue
            int numberOfTokens = 1;
            UProveKeyAndToken[] upkt = IssueUProveTokens(ikap, ip, attributes, numberOfTokens);

            /*
             * token presentation
             */

            WriteLine("Presenting a U-Prove token proving that user is over-21");

            int dobAttributeIndex = 1;
            if (ip.E[dobAttributeIndex - 1] != 0) {
                throw new InvalidUProveArtifactException("DOB attribute must be encoded directly in order to create a range proof");
            }
            int[] disclosed = new int[] {  };
            int[] committed = new int[] { dobAttributeIndex };
            int commitmentIndex = Array.FindIndex<int>(committed, x => x == dobAttributeIndex);
            VerifierRangeProofParameters.ProofType rangeProofType = VerifierRangeProofParameters.ProofType.LESS_THAN_OR_EQUAL_TO;
            DateTime over21TargetDate = DateTime.Today.AddYears(-21);
            WriteLine("Target over-21 date: " + proverDOB.ToShortDateString());

            // the application-specific message that the prover will sign. Typically this is a nonce combined
            // with any application-specific transaction data to be signed.
            byte[] message = GenerateNoncePlusTimestampMessage();

            // generate the presentation proof
            CommitmentPrivateValues cpv;
            ProverPresentationProtocolParameters pppp = new ProverPresentationProtocolParameters(ip, disclosed, message, upkt[0], attributes);
            pppp.Committed = committed;
            PresentationProof proof = PresentationProof.Generate(pppp, out cpv);
            string tokenJSON = CryptoSerializer.Serialize<UProveToken>(upkt[0].Token);
            string proofJSON = CryptoSerializer.Serialize<PresentationProof>(proof);

            // generate the range proof
            RangeProof rangeProof = new RangeProof(
                RangeProofParameterFactory.GetDateTimeProverParameters(
                              new CryptoParameters(ip),
                              new PedersenCommitment(pppp, proof, cpv, commitmentIndex),
                              rangeProofType,
                              over21TargetDate,
                              MinBirthdate.Year,
                              MaxBirthdate.Year));
            string rangeProofJSON = CryptoSerializer.Serialize<RangeProof>(rangeProof);

            // verify the presentation proof
            try
            {
                // parse the JSON messages
                IssuerParameters vIP = new IssuerParameters(ipJSON);
                PresentationProof vProof = vIP.Deserialize<PresentationProof>(proofJSON);
                RangeProof vRangeProof = vIP.Deserialize<RangeProof>(rangeProofJSON);

                // verify the presentation proof
                VerifierPresentationProtocolParameters vppp = new VerifierPresentationProtocolParameters(vIP, disclosed, message, vIP.Deserialize<UProveToken>(tokenJSON));
                vppp.Committed = committed;
                vProof.Verify(vppp);
                
                // and verify the range proof
                if (!vRangeProof.Verify(
                    RangeProofParameterFactory.GetDateTimeVerifierParameters(
                        new CryptoParameters(vIP),
                        new ClosedPedersenCommitment(vIP, vProof, commitmentIndex).Value,
                        rangeProofType,
                        over21TargetDate,
                        MinBirthdate.Year,
                        MaxBirthdate.Year)))
                {
                    throw new InvalidUProveArtifactException("invalid range proof");
                }

                WriteLine("Proof is valid.");
            }
            catch (InvalidUProveArtifactException e)
            {
                WriteLine("Invalid proof. Sample failed! " + e.Message, true);
                return;
            }

            WriteLine("Sample completed.\n*************************************************************\n");
        }

        public static void Main()
        {
			while (true) {
			//	SoftwareOnlySample ();
			 //	DeviceSample ();
			 //	AccumulatorRevocationSample ();
			 //	InequalityRevocationSample ();
			 //	IDEscrowSample ();
  				 SetMembershipSample();
 
                //CollaborativeIssuanceAndEqualitySample();
                  RangeProofSample();
				WriteLine ("Press enter to exit...");
				Console.ReadLine ();
			}
        }


        public delegate void OutputLine(string text);

        public static OutputLine outputFunction;

        public static void WriteLine(string text, bool error = false)
        {
            // if a consumer of this class has supplied a function to get the outup 
            // send it 
            if (outputFunction != null) outputFunction(text);

            var color = Console.ForegroundColor;
            if (error)
            {
                Console.ForegroundColor = ConsoleColor.Red;
            }
            Console.WriteLine(text);
            Console.ForegroundColor = color;
        }

    }
}
