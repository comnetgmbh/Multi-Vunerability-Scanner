package com.logpresso.scanner.utils;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

public class ZipFileIterator implements Closeable {

	private ZipFile zipFile;
	private ZipInputStream zis;
	private Enumeration<? extends ZipEntry> e;
	private ZipEntry nextEntry;

	public ZipFileIterator(File file) throws IOException {
		this.zipFile = new ZipFile(file);
		e = zipFile.entries();
	}

	public ZipFileIterator(ZipInputStream zis) {
		this.zis = zis;
	}

	public ZipEntry getNextEntry() throws IOException {
		if (zipFile != null) {
			if (e.hasMoreElements()) {
				this.nextEntry = e.nextElement();
				return nextEntry;
			} else {
				return null;
			}
		} else {
			this.nextEntry = zis.getNextEntry();
			return nextEntry;
		}
	}

	public InputStream getNextInputStream() throws IOException {
		if (zipFile != null)
			return zipFile.getInputStream(nextEntry);

		return zis;
	}

	public void close() throws IOException {
		if (zipFile != null)
			zipFile.close();

		if (zis != null)
			IoUtils.ensureClose(zis);
	}

}
