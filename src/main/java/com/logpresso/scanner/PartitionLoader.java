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

			if (p.getName().contains("Google Drive"))
				paths.add(p.getPath());
		}
		return paths;
	}

	public static List<Partition> getPartitions() throws IOException {
		boolean isWindows = File.separatorChar == '\\';
		List<Partition> partitions = new ArrayList<Partition>();

		for (FileStore store : FileSystems.getDefault().getFileStores()) {
			String path = store.name();
			if (isWindows) {
				path = store.toString();
				path = path.charAt(path.length() - 3) + ":\\";
			}

			String type = store.type();

			partitions.add(new Partition(type, path, store.name()));
		}

		return partitions;
	}

}
