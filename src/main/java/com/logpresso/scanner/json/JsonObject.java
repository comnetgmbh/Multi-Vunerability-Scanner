package com.logpresso.scanner.json;

import java.io.IOException;
import java.io.Writer;
import java.util.LinkedHashMap;
import java.util.Map;

public class JsonObject {

	private static final Null NULL = new Null();
	private final Map<String, Object> map = new LinkedHashMap<String, Object>();

	public void put(String key, boolean b) {
		map.put(key, Boolean.valueOf(b));
	}

	public void put(String key, long l) {
		map.put(key, Long.valueOf(l));
	}

	public void put(String key, int i) {
		map.put(key, Integer.valueOf(i));
	}

	public void put(String key, String s) {
		if (s == null) {
			map.put(key, NULL);
		} else {
			map.put(key, escape(s));
		}
	}

	public void put(String key, JsonObject jsonObject) {
		if (jsonObject == null) {
			map.put(key, NULL);
		} else {
			map.put(key, jsonObject);
		}
	}

	public void put(String key, JsonArray jsonArray) {
		if (jsonArray == null) {
			map.put(key, NULL);
		} else {
			map.put(key, jsonArray);
		}
	}

	public void write(Writer writer) throws IOException {
		write(writer, 0);
	}

	public void write(Writer writer, int depth) throws IOException {
		boolean comma = false;
		writer.write("{\n");

		for (Map.Entry<String, Object> entry : map.entrySet()) {
			if (comma) {
				writer.write(',');
				writer.write('\n');
			}

			writeTab(writer, depth + 1);
			writer.write(quote(entry.getKey()));
			writer.write(": ");
			writeValue(writer, entry.getValue(), depth + 1);
			comma = true;
		}

		writer.write('\n');
		writeTab(writer, depth);
		writer.write('}');
	}

	private void writeValue(Writer writer, Object value, int depth) throws IOException {
		if (value == null) {
			writer.write("null");
		} else {
			if (value instanceof Boolean) {
				boolean b = ((Boolean) value).booleanValue();
				writer.write(b ? "true" : "false");
			} else if (value instanceof Number) {
				writer.write(((Number) value).toString());
			} else if (value instanceof String) {
				writer.write(quote(value.toString()));
			} else if (value instanceof JsonObject) {
				((JsonObject) value).write(writer, depth);
			} else if (value instanceof JsonArray) {
				((JsonArray) value).write(writer, depth);
			} else if (value == NULL) {
				writer.write("null");
			}
		}
	}

	public static String escape(String raw) {
		String escaped = raw;
		escaped = escaped.replace("\\", "\\\\");
		escaped = escaped.replace("\"", "\\\"");
		escaped = escaped.replace("\b", "\\b");
		escaped = escaped.replace("\f", "\\f");
		escaped = escaped.replace("\n", "\\n");
		escaped = escaped.replace("\r", "\\r");
		escaped = escaped.replace("\t", "\\t");
		return escaped;
	}

	private void writeTab(Writer writer, int depth) throws IOException {
		for (int i = 0; i < depth; i++)
			writer.write("    ");
	}

	static String quote(String s) {
		if (s == null) {
			return null;
		} else {
			return "\"" + s + "\"";
		}
	}

	private static class Null {
	}
}
