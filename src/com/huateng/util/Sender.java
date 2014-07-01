package com.huateng.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;


/**
 * 发送方。
 * 
 * @author shenshaomin
 * 
 */
public class Sender {

	/**
	 * 
	 * @param privateFileName : 私钥文件名
	 * @param publicFileName : 公钥文件名
	 * @throws NoSuchAlgorithmException : 算法没找到
	 * @throws FileNotFoundException : 文件没找到
	 * @throws IOException : 读写异常
	 */
	public void writeKeysToFiles(String privateFileName, String publicFileName) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");
		keygen.initialize(1024);
		KeyPair kp = keygen.generateKeyPair();
		PrivateKey privateKey = kp.getPrivate();
		PublicKey publicKey = kp.getPublic();
		ObjectOutputStream out_private = new ObjectOutputStream(new FileOutputStream(privateFileName));
		out_private.writeObject(privateKey);
		out_private.close();

		ObjectOutputStream out_public = new ObjectOutputStream(new FileOutputStream(publicFileName));
		out_public.writeObject(publicKey);
		out_public.close();

		System.out.println("已生成私钥文件：" + privateFileName + ",公钥文件：" + publicFileName);
	}

	/**
	 * 读取私钥文件得到私钥，并根据文件内容生成签名并写入签名文件。
	 * 
	 * @param privateFile ：私钥文件。
	 * @param f ：要发送的文件
	 * @throws FileNotFoundException ：如果文件未找到
	 * @throws IOException ：如果出现读写异常
	 * @throws ClassNotFoundException ：如果类未找到
	 * @throws NoSuchAlgorithmException ：如果没有此算法
	 * @throws InvalidKeyException ：如果私钥不可用
	 * @throws SignatureException ：如果签名失败
	 */
	public void send(File privateFile, File sigendFile, File f) throws FileNotFoundException, IOException, ClassNotFoundException,
			NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		if (privateFile == null) {
			throw new FileNotFoundException("没有找到私钥文件！");
		}
		if (f == null) {
			throw new FileNotFoundException("没有找到要加密的文件！");
		}
		// 读取文件，得到私钥
		ObjectInputStream in = new ObjectInputStream(new FileInputStream(privateFile));
		PrivateKey privateKey = (PrivateKey) in.readObject();
		in.close();

		// 根据文件生成签名，并保存到文件signature.dxt
		byte[] data = new byte[(int) f.length()];
		FileInputStream fis = new FileInputStream(f);
		fis.read(data);
		fis.close();

		Signature sign = Signature.getInstance("DSA");
		sign.initSign(privateKey);
		sign.update(data);
		// 生成签名
		byte[] signedBytes = sign.sign();
		// 将签名写入文件
		FileOutputStream fos = new FileOutputStream(sigendFile);
		fos.write(signedBytes, 0, signedBytes.length);
		fos.close();

		System.out.println("根据文件内容生成签名并写入签名文件完毕！");
		System.out.println("签名文件写入到" + sigendFile.getName());
	}

	public static void main(String[] args) {
		// 私钥文件
		String privateFileName = "private.key";
		// 公钥文件
		String publicFileName = "public.key";
		// 签名文件
		String signedFileName = "signature.dtx";
		// 发送方要发送的文件。
		File f = new File("/Users/ice/Downloads/file_check_test.txt");
		File privateFile = new File(privateFileName);
		File sigendFile = new File(signedFileName);

		try {
			Sender sender = new Sender();
			// 发送方将公钥和私钥保存到文件private.key和public.key
			sender.writeKeysToFiles(privateFileName, publicFileName);
			// 发送方根据文件内容生成签名并写入signature.dtx
			sender.send(privateFile, sigendFile, f);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
	}
}
