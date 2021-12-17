package com.logpresso.scanner;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.FileSystems;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class PartitionLoader {
	private static final boolean IS_WINDOWS = File.separatorChar == '\\';
	private static final Set<String> DEFAULT_EXCLUDE_FILE_SYSTEMS;
	static {
		DEFAULT_EXCLUDE_FILE_SYSTEMS = new HashSet<String>(Arrays.asList("nfs", "tmpfs", "devtmpfs", "iso9660"));
	}

	public static List<String> getExcludePaths(Set<String> excludeTypes) throws IOException {
		if (excludeTypes == null)
			excludeTypes = DEFAULT_EXCLUDE_FILE_SYSTEMS;

		List<String> paths = new ArrayList<String>();
		for (Partition p : getPartitions()) {
			if (excludeTypes.contains(p.getType()))
				paths.add(p.getPath());
		}
		return paths;
	}

	public static List<Partition> getPartitions() throws IOException {
		List<Partition> partitions = new ArrayList<Partition>();

		for (FileStore store : FileSystems.getDefault().getFileStores()) {
			String type = store.type();
			String path = store.name();
			if (IS_WINDOWS) {
				path = store.toString();
				char driveLetter = path.charAt(path.length() - 3);
				path = driveLetter + ":\\";

				if (isNetworkDrive(driveLetter))
					type = "Network Share";
			}

			partitions.add(new Partition(type, path, store.name()));
		}

		return partitions;
	}

	private static boolean isNetworkDrive(char driveLetter) {
		if (!IS_WINDOWS)
			return false;

		List<String> cmd = Arrays.asList("cmd", "/c", "net", "use", driveLetter + ":");
		try {
			File nullFile = new File(IS_WINDOWS ? "NUL" : "/dev/null");
			Process p = new ProcessBuilder(cmd).redirectOutput(nullFile).redirectErrorStream(true).start();
			p.getOutputStream().close();

			return p.waitFor() == 0;
		} catch (Exception e) {
			throw new IllegalStateException("Cannot run 'net use' on " + driveLetter, e);
		}
	}
}
