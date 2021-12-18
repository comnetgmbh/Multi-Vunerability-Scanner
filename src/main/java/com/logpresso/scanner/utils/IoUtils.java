package com.logpresso.scanner.utils;

import java.io.Closeable;

public class IoUtils {
	public static void ensureClose(Closeable c) {
		if (c != null) {
			try {
				c.close();
			} catch (Throwable t) {
			}
		}
	}
}
