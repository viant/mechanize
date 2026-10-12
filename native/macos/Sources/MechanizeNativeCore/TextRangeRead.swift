import Foundation

public enum TextRangeReadError: Error { case unavailable, changed }

/// Reads the complete text of an already-authorized field, never a truncated prefix.
public enum TextRangeRead {
    public static func read(count: () throws -> Int?, range: (Int) throws -> String?,
                            revalidate: () throws -> Void) throws -> String {
        try revalidate()
        guard let length = try count(), length >= 0, length <= 65_536 else { throw TextRangeReadError.unavailable }
        guard let value = try range(length), value.utf16.count == length,
              value.utf8.count <= 65_536, !value.contains("\0") else { throw TextRangeReadError.unavailable }
        try revalidate()
        guard try count() == length else { throw TextRangeReadError.changed }
        try revalidate()
        return value
    }
}
