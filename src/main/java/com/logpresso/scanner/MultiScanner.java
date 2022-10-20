package com.logpresso.scanner;

import com.logpresso.scanner.utils.FileUtils;
import com.logpresso.scanner.utils.IoUtils;
import com.logpresso.scanner.utils.StringUtils;
import com.logpresso.scanner.utils.ZipUtils;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class MultiScanner {

	public static final String VERSION = "1.0.0";
	public static final String RELEASE_DATE = "2022-10-19";
	public static final String BANNER = "Multi Vulnerability Scanner " + VERSION + " (" + RELEASE_DATE + ")";

	public static void main(String[] args) {
		try {
			System.out.println(BANNER);
			int returnCode = run(args);
			System.exit(returnCode);
		} catch (Throwable t) {
			System.out.println("Error: " + t.getMessage());
			if (!(t instanceof IllegalArgumentException))
				t.printStackTrace();
			System.exit(-1);
		}
	}
	public static int run(String[] args) throws Exception {
		if (args.length < 1) {
			Configuration.pringUsage();
			return 0;
		}

		Configuration config = Configuration.parseArguments(args);
		int returnCode;

		if (config.isScanForCommonsText()) {
			CommonsTextScanner commonsTextScanner = new CommonsTextScanner();
			returnCode = commonsTextScanner.run(config);
		} else {
			Log4j2Scanner log4j2Scanner = new Log4j2Scanner();
			returnCode = log4j2Scanner.run(config);
		}

		return returnCode;
	}

}
