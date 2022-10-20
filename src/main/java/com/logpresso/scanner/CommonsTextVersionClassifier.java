package com.logpresso.scanner;

import com.logpresso.scanner.utils.IoUtils;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class CommonsTextVersionClassifier {
	private static final char[] HEX_CODES = "0123456789abcdef".toCharArray();
	private static final Map<String, String> digests;

	static {
		digests = new HashMap<String, String>();
		digests.put("824b0d4b505f13d8ce318a7d55bb4b83", "1.10.0");
		digests.put("48e58baa150997f6a30a9fc334f9b0b3", "1.9");
		//digests.put("a37e99a5a2f32119abf4099d4d676dad", "1.8");
		digests.put("a37e99a5a2f32119abf4099d4d676dad", "1.7");
		//digests.put("ecac671470dc8853f1387247fae412df", "1.6");
		digests.put("ecac671470dc8853f1387247fae412df", "1.5");
		digests.put("038f37a7cca07bb09c40aa14fd7e9664", "1.4");
		digests.put("19c6368c3ebc4e484c6017c320eb512e", "1.3");
	}

	public static List<String> getCommonsTextMd5Entries() {
		return Arrays.asList("/commons/text/WordUtils.class");
	}


	@SuppressWarnings("unchecked")
	public static String classifyCommonsTextVersion(Map<String, String> entryMd5Map) {

		final String[] classFileNames = new String[] { "WordUtils.class" };

		final Map<String, String>[] digestMaps = new Map[] {digests};

		for (int i = 0; i < classFileNames.length; i++) {
			String version = detectVersion(classFileNames[i], entryMd5Map, digestMaps[i]);
			if (version != null)
				return version;
		}

		return null;
	}

	private static String detectVersion(String classFileName, Map<String, String> entryMd5Map,
			Map<String, String> digests) {
		String md5 = entryMd5Map.get(classFileName);
		if (md5 == null)
			return null;

		return digests.get(md5);
	}

	public static Map<String, String> generateSignature(File f) {
		Map<String, String> digests = new LinkedHashMap<String, String>();
		ZipInputStream zis = null;
		ZipEntry entry = null;
		try {
			zis = new ZipInputStream(new FileInputStream(f));
			while (true) {
				entry = zis.getNextEntry();
				if (entry == null)
					break;

				if (entry.getName().endsWith("/"))
					continue;

				String md5 = md5(zis);
				digests.put(entry.getName(), md5);
			}
			return digests;
		} catch (IOException e) {
			throw new IllegalStateException("cannot load zip entry " + entry, e);
		} finally {
			IoUtils.ensureClose(zis);
		}
	}

	public static String md5(InputStream is) {
		try {
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			byte[] b = new byte[8192];
			while (true) {
				int len = is.read(b);
				if (len < 0)
					break;
				md5.update(b, 0, len);
			}

			return toHex(md5.digest());
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException("md5 is not supported");
		} catch (IOException e) {
			throw new IllegalStateException("md5 error", e);
		}
	}

	private static String toHex(byte[] data) {
		char[] hex = new char[data.length * 2];
		for (int i = 0; i < data.length; i++) {
			hex[i * 2] = HEX_CODES[(data[i] >> 4) & 0xF];
			hex[i * 2 + 1] = HEX_CODES[data[i] & 0xF];
		}
		return new String(hex);
	}

	public static void main(String[] args) throws IOException {
		File[] files = new File(args[0]).listFiles();
		for (File f : files) {
			if (f.getName().endsWith(".sig"))
				continue;

			FileOutputStream fos = null;
			try {
				fos = new FileOutputStream(new File(f.getAbsolutePath() + ".sig"));
				Map<String, String> signatures = generateSignature(f);
				System.out.println(f.getAbsolutePath());

				for (String name : signatures.keySet()) {
					String md5 = signatures.get(name);
					String line = md5 + " " + name + "\n";
					System.out.print(line);

					fos.write(line.getBytes("utf-8"));
				}

				System.out.println("---");
			} finally {
				IoUtils.ensureClose(fos);
			}
		}
	}
}
