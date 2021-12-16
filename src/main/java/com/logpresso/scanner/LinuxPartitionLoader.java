package com.logpresso.scanner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class LinuxPartitionLoader {

	private static final Set<String> DEFAULT_EXCLUDE_FILE_SYSTEMS;
	static {
		DEFAULT_EXCLUDE_FILE_SYSTEMS = new HashSet<String>(Arrays.asList("nfs", "tmpfs", "devtmpfs", "iso9660"));
	}

	public static List<String> getExcludePaths(Set<String> excludeTypes) throws IOException {
		if (excludeTypes == null)
			excludeTypes = DEFAULT_EXCLUDE_FILE_SYSTEMS;

		List<String> paths = new ArrayList<String>();
		for (LinuxPartition p : getPartitions()) {
			if (excludeTypes.contains(p.getType()))
				paths.add(p.getPath());
		}
		return paths;
	}

	public static List<LinuxPartition> getPartitions() throws IOException {
		Process p = null;
		try {
			p = Runtime.getRuntime().exec("df -T");

			// follow system locale
			BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
			List<String> lines = new ArrayList<String>();
			while (true) {
				String line = br.readLine();
				if (line == null)
					break;

				lines.add(line);
			}

			return getPartitions(lines);
		} finally {
			if (p != null)
				p.destroy();
		}
	}

	public static List<LinuxPartition> getPartitions(List<String> lines) {
		List<LinuxPartition> partitions = new ArrayList<LinuxPartition>();
		int typeIndex = 0;

		int columnCount = 0;
		int dataIndex = 0;
		String[] data = null;

		for (String line : lines) {
			line = line.trim();
			if (line.endsWith("Mounted on")) {
				String[] headers = line.split("\\s+");

				typeIndex = findTypeHeader(typeIndex, headers);
				if (typeIndex == -1)
					throw new IllegalStateException("cannot detect partition type: " + line);

				// count without last 'on' token
				columnCount = headers.length - 1;
				data = new String[columnCount];
			} else {
				String[] tokens = line.split("\\s+");

				// one partition information can be splitted into two lines.
				for (int i = 0; i < tokens.length; i++)
					data[dataIndex++] = tokens[i];

				if (dataIndex == columnCount) {
					String type = data[typeIndex];
					String path = data[columnCount - 1];
					partitions.add(new LinuxPartition(type, path));

					dataIndex = 0;
				}
			}
		}

		return partitions;
	}

	private static int findTypeHeader(int typeIndex, String[] headers) {
		int i = 0;
		for (String header : headers) {
			if (header.equals("Type"))
				return i;

			i++;
		}
		return -1;
	}
}
