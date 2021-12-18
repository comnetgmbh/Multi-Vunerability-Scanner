package com.logpresso.scanner.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.reflect.Method;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;

public class FileUtils {
	private FileUtils() {
	}

	// use JDK7 feature
	public static boolean isSymlink(File f) {
		Path path = f.toPath();
		boolean isWindows = File.separatorChar == '\\';
		if (isWindows) {
			try {
				BasicFileAttributes attr = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
				if (DosFileAttributes.class.isInstance(attr)) {
					Method m = attr.getClass().getDeclaredMethod("isReparsePoint");
					m.setAccessible(true);
					boolean isReparsePoint = (Boolean) m.invoke(attr);
					if (isReparsePoint)
						return true;
				}
			} catch (Exception e) {
			}
		}

		return Files.isSymbolicLink(f.toPath());
	}

	public static boolean isLocked(File f) {
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(f, "rw");
			FileLock lock = raf.getChannel().lock();
			lock.release();
			return false;
		} catch (Throwable t) {
			return true;
		} finally {
			IoUtils.ensureClose(raf);
		}
	}

	public static boolean truncate(File f) {
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(f, "rw");
			raf.setLength(0);
			return true;
		} catch (Throwable t) {
			return false;
		} finally {
			IoUtils.ensureClose(raf);
		}
	}

	public static int readMagic(File f) throws IOException {
		RandomAccessFile raf = null;
		try {
			raf = new RandomAccessFile(f, "r");
			return raf.readInt();
		} finally {
			IoUtils.ensureClose(raf);
		}
	}

	public static boolean copyAsIs(File srcFile, File dstFile) {
		FileInputStream is = null;
		FileOutputStream os = null;

		try {
			is = new FileInputStream(srcFile);
			os = new FileOutputStream(dstFile);

			byte[] buf = new byte[32768];
			while (true) {
				int len = is.read(buf);
				if (len < 0)
					break;

				os.write(buf, 0, len);
			}

			return true;
		} catch (Throwable t) {
			System.out.println("Error: Cannot copy file " + srcFile.getAbsolutePath() + " - " + t.getMessage());
			return false;
		} finally {
			IoUtils.ensureClose(is);
			IoUtils.ensureClose(os);
		}
	}
}
