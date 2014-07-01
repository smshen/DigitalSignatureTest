package com.huateng.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;


/**
 * 接受方。
 * @author shenshaomin
 *
 */
public class Receiver {
	
	/**
	 * 接受方读取发送方的公钥文件得到公钥，并以公钥验证签名。
	 * @param publicKeyFile:公钥文件。
	 * @param f：发送方发送的文件。
	 * @return：签名是否验证OK。
	 * @throws NoSuchAlgorithmException：如果没有此算法。
	 * @throws FileNotFoundException：如果文件未找到。
	 * @throws IOException：如果读写异常
	 * @throws ClassNotFoundException：如果类未找到
	 * @throws InvalidKeyException：如果公钥不可用
	 * @throws SignatureException：如果签名失败 
	 */
	public boolean receive(File publicKeyFile,File signedFile,File f) throws NoSuchAlgorithmException, FileNotFoundException, IOException, ClassNotFoundException, InvalidKeyException, SignatureException {
		if (publicKeyFile == null) {
			throw new FileNotFoundException("公钥文件未找到！");
		}
		if (f == null) {
			throw new FileNotFoundException("发送方没有发送文件！");
		}
		// 读取公钥文件得到公钥
		ObjectInputStream in = new ObjectInputStream(new FileInputStream(publicKeyFile));
		PublicKey pk = (PublicKey) in.readObject();
		in.close();
		
		// 读取发送方发送的文件，读入字节数组
		byte[] data = new byte[(int) f.length()];
		FileInputStream fis = new FileInputStream(f);
		fis.read(data);
		
		// 读取发送方的签名文件
		byte[] signData = new byte[(int) signedFile.length()];
		FileInputStream fis2 = new FileInputStream(signedFile);
		fis2.read(signData);
		fis2.close();
		
		// 使用发送方的公钥验证签名
		Signature sign = Signature.getInstance("DSA");
		sign.initVerify(pk);
		sign.update(data);
		fis.close();
		return sign.verify(signData);
	}
	
	public static void main(String[] args) {
		// 公钥文件
		String publicFileName = "public.key";
		// 签名文件
		String signedFileName = "signature.dtx";
		// 发送方发送的文件。
		File f = new File("/Users/ice/Downloads/file_check_test.txt");
		File publicFile = new File(publicFileName);
		File sigendFile = new File(signedFileName);
		
		try {
			Receiver recv = new Receiver();
			// 接受方读取发送方提供的公钥文件验证签名是否一致
			boolean isOk = recv.receive(publicFile,sigendFile, f);
			if (isOk) {
				System.out.println("接受方验证文件无篡改！");
			} else {
				System.out.println("接受方验证文件被篡改！");
			}
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


