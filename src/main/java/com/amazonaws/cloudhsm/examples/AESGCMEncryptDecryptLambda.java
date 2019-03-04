/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package com.amazonaws.cloudhsm.examples;

import java.io.IOException;
import java.security.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;

import software.amazon.awssdk.services.cloudhsmv2.CloudHsmV2Client;
import software.amazon.awssdk.services.cloudhsmv2.model.DescribeClustersRequest;
import software.amazon.awssdk.services.cloudhsmv2.model.DescribeClustersResponse;
import software.amazon.awssdk.services.cloudhsmv2.model.Cluster;
import software.amazon.awssdk.services.cloudhsmv2.model.Hsm;

import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.LoginManager;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.File;
import java.util.regex.*;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.BufferedReader;


/**
 * This sample demonstrates how to encrypt data with AES GCM. It shows where the IV is generated
 * and how to pass authenticated tags to the encrypt and decrypt functions.
 */
public class AESGCMEncryptDecryptLambda {

	public static void myhandler(Context context) throws Exception {

		// Start the Lambda logger
		LambdaLogger logger = context.getLogger();

		// Get the CU credentials from aws secrets manager
		//
		String secret_id = System.getenv("SECRET_ID");

		if (secret_id == null || secret_id.isEmpty()) {
			logger.log("ERROR: Please set the Secret id in the SECRET_ID environmental variable");
			System.exit(1);
		}

		String secret_value = getCUSecretValue(secret_id, logger);

		JSONParser secret_parser = new JSONParser();
		JSONObject secret_json = (JSONObject) secret_parser.parse(secret_value);

		if (! secret_json.containsKey("HSM_USER") || ! secret_json.containsKey("HSM_PASSWORD") ) {
			logger.log("ERROR: Credentials not found in secret \""+secret_id+"\" , Please make sure it contains the keys HSM_USER and HSM_PASSWORD");
			System.exit(1);
		}

		String hsm_user = (String) secret_json.get("HSM_USER");
		String hsm_password = (String) secret_json.get("HSM_PASSWORD");
		String hsm_partition = "PARTITION_1";

		// Get Ip of the first HSM in the Cluster

		String HsmIp = getHsmIp(logger);

		logger.log("DescribeClusters returned the HSM IP = "+HsmIp);

		// Get the Ip from the configuration file
		logger.log("* Getting the HSM IP of the configuration file ... ");

		String confFile = "etc/cloudhsm_client.cfg";

		JSONParser parser = new JSONParser();
		Object obj = parser.parse(new FileReader(confFile));
		JSONObject jsonObject = (JSONObject) obj;

		JSONObject server = (JSONObject) jsonObject.get("server");
		String confIp = (String) server.get("hostname");

		logger.log("The configuration file has the HSM IP = "+confIp);

		// If the HSM ip is different from the ip in the configuration file modify the configuration file
		if (! confIp.equals(HsmIp)){

			logger.log("* The HSM IP returned is different the IP in the configuration file. Updating the configuration file ... ");

			confFile = "/tmp/cloudhsm_client.cfg";
			server.put("hostname",HsmIp);

			FileWriter file = new FileWriter(confFile);
			file.write(jsonObject.toJSONString());
			file.close();
		}

		// Start the client process 

		Process pr = StartClientProcess(confFile, logger);

		// Add the provider

		logger.log("* Adding the Cavium provider ... ");

		try {
			Security.addProvider(new com.cavium.provider.CaviumProvider());
		} catch (IOException ex) {
			logger.log(String.valueOf(ex));
			return;
		}

		// Login to the HSM

		logger.log("* Using credentials to Login to the CloudHSM Cluster ... ");

		loginWithExplicitCredentials(hsm_user, hsm_password, hsm_partition, logger);

		// Generate a new AES Key to use for encryption.

		logger.log("* Generating AES Key ... ");

		Key key = SymmetricKeys.generateAESKey(256, "AesGcmTest");


		// Generate some random data to encrypt

		logger.log("* Generating Random data to encrypt ... ");

		byte[] plainText = new byte[32];
		Random r = new Random();
		r.nextBytes(plainText);

		logger.log("Plain Text data = "+byteToString(plainText));


		// Encrypt the plaintext with authenticated data.

		logger.log("* Encrypting data ... ");

		String aad = "16 bytes of data";
		List<byte[]> result = encrypt(key, plainText, aad.getBytes());

		// Store the HSM's IV and the ciphertext.
		byte[] iv = result.get(0);
		byte[] cipherText = result.get(1);

		// The IV will have 12 bytes of data and a 4 byte counter.
		logger.log("Cipher Text data = "+byteToString(cipherText));

		// Decrypt the ciphertext.

		logger.log("* Decrypting ciphertext ... ");

		byte[] decryptedText = decrypt(key, cipherText, iv, aad.getBytes());
		logger.log("Decrypted Text data = "+byteToString(decryptedText));
		assert(java.util.Arrays.equals(plainText, decryptedText));
		logger.log(" * Successful decryption");

		// Logging out
		logger.log("* Logging out the CloudHSM Cluster");
		logout();

		//Close the client process

		logger.log("* Closing client ... ");
		pr.destroy();

	}


	/** 
	 * Get the value of the secret containing the CU credentials
	 * @param secret_id
	 * @param logger
	 * @return String containing the JSON secret_value
	 */
	public static String getCUSecretValue(String secret_id, LambdaLogger logger) {

		logger.log("* Running GetSecretValue to get the CU credentials ... ");

		SecretsManagerClient sm_client = SecretsManagerClient.create();

		GetSecretValueRequest getsecretreq = GetSecretValueRequest.builder().secretId(secret_id).build();

		GetSecretValueResponse sm_response = null;
		try {
			sm_response = sm_client.getSecretValue(getsecretreq);
		} catch (Exception e) {
			logger.log("ERROR: Unable to get the value of the secret \""+secret_id+"\"");
			logger.log(e.getMessage());
			System.exit(1);
		}

		return sm_response.secretString();

	}

	/** 
	 * Get the IP of the first HSM in the CloudHSM cluster
	 * @param logger
	 * @return String containing the HSM IP
	 */
	public static String getHsmIp(LambdaLogger logger) {

		logger.log("* Running DescribeClusters to get the HSM IP ... ");

		String ClusterId = System.getenv("CLUSTER_ID");

		if (ClusterId == null || ClusterId.isEmpty()) {
			logger.log("ERROR: Please set the Cluster id in the CLUSTER_ID environmental variable");
			System.exit(1);
		}

		ArrayList<String> ClusterIds = new ArrayList<String>();
		ClusterIds.add(ClusterId);
		HashMap<String,ArrayList<String>> filters = new HashMap<String,ArrayList<String>>();
		filters.put("clusterIds",ClusterIds);


		CloudHsmV2Client client = CloudHsmV2Client.create();

		DescribeClustersRequest describeClustersRequest = DescribeClustersRequest.builder().filters(filters).build();

		DescribeClustersResponse response = client.describeClusters(describeClustersRequest);

		if (response.clusters().size()<1) {
			logger.log("ERROR: Cluster \""+ClusterId+"\" not found");
			System.exit(1);
		}

		if (response.clusters().get(0).hsms().size()<1){
			logger.log("ERROR: No HSMs were found in the Cluster \""+ClusterId+"\"");
			System.exit(1);
		}

		return response.clusters().get(0).hsms().get(0).eniIp();

	}

	/** 
	 * Start the CloudHSM client process
	 * @param confFile
	 * @param logger
	 * @return Process referring to the client process
	 */
	public static Process StartClientProcess(String confFile, LambdaLogger logger) throws Exception {

		logger.log("* Starting the cloudhsm client ... ");

		File logFile = new File("/tmp/client.log");
		Process pr = new ProcessBuilder("bin/cloudhsm_client",confFile).redirectErrorStream(true).redirectOutput(logFile).start();

		// Wait for the client to start

		logger.log("* Waiting for the cloudhsm client to start ... ");

		Pattern pat = Pattern.compile("libevmulti_init: Ready !");

		FileReader lf = new FileReader(logFile);
		BufferedReader in = new BufferedReader(lf);

		String line="";
		Matcher match = pat.matcher(line);
		while (! match.find()) {
			line=in.readLine();
			if (line!=null) {
				match = pat.matcher(line);
			}
		}

		logger.log("* cloudhsm client started ... ");
		return pr;
	}

	/**
	 * Encrypt some plaintext and authentication data using the GCM cipher mode.
	 * @param key
	 * @param plainText
	 * @param aad
	 * @return List of byte[] containing the IV and cipherText
	 */
	public static List<byte[]> encrypt(Key key, byte[] plainText, byte[] aad) {
		try {
			// Create an encryption cipher.
			Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding", "Cavium");
			encCipher.init(Cipher.ENCRYPT_MODE, key);
			encCipher.updateAAD(aad);
			encCipher.update(plainText);
			byte[] ciphertext = encCipher.doFinal();

			// The IV is generated inside the HSM. It is needed for decryption, so
			// both the ciphertext and the IV are returned.
			return Arrays.asList(encCipher.getIV(), ciphertext);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Decrypt the ciphertext using the HSM supplied IV and the user supplied tag data.
	 * @param key
	 * @param cipherText
	 * @param iv
	 * @param aad
	 * @return byte[] of the decrypted ciphertext.
	 */
	public static byte[] decrypt(Key key, byte[] cipherText, byte[] iv, byte[] aad) {
		Cipher decCipher;
		try {
			// Only 128 bit tags are supported
			GCMParameterSpec gcmSpec = new GCMParameterSpec(16 * Byte.SIZE, iv);

			decCipher = Cipher.getInstance("AES/GCM/NoPadding", "Cavium");
			decCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
			decCipher.updateAAD(aad);
			return decCipher.doFinal(cipherText);

		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * The explicit login method allows users to pass credentials to the Cluster manually. If you obtain credentials
	 * from a provider during runtime, this method allows you to login.
	 * @param user Name of CU user in HSM
	 * @param pass Password for CU user.
	 * @param partition HSM ID
	 */
	public static void loginWithExplicitCredentials(String user, String pass, String partition, LambdaLogger logger) {
		LoginManager lm = LoginManager.getInstance();
		try {
			lm.login(partition, user, pass);
			logger.log("Login successful!");
		} catch (CFM2Exception e) {
			if (CFM2Exception.isAuthenticationFailure(e)) {
				logger.log("Detected invalid credentials");
			}

			e.printStackTrace();
			System.exit(1);
		}
	}

	/**
	 * Logout will force the LoginManager to end your session.
	 */
	public static void logout() {
		try {
			LoginManager.getInstance().logout();
		} catch (CFM2Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Converts byte[] to Hex String
	 */
	public static String byteToString(byte[] data) {
		String data_string="";
		for (int i=0; i<data.length; i++) {
			data_string+=String.format("%02X", data[i]);
		}
		return data_string;
	}
}
