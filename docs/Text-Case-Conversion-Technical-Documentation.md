# Technical Documentation: Text Case Conversion Utilities

## Introduction

The Text Case Conversion utilities provide comprehensive support for converting text between various case formats commonly used in programming, documentation, and data processing. This implementation offers 12 different case conversion formats with unicode-aware word splitting and intelligent case detection.

## Features

- **12 Case Conversion Formats**: Support for all major text case conventions
- **Unicode-Aware Processing**: Proper handling of international characters and scripts
- **Intelligent Word Splitting**: Advanced algorithms for detecting word boundaries
- **Case Detection**: Automatic identification of existing case formats
- **Bidirectional Conversion**: Convert between any supported case formats
- **Performance Optimized**: Efficient algorithms with minimal memory overhead

## Supported Case Formats

### 1. **lowercase**
- **Pattern**: `^[a-z0-9\s]+$`
- **Example**: `hello world example`
- **Use Case**: General text, descriptions, content

### 2. **UPPERCASE**
- **Pattern**: `^[A-Z0-9\s]+$`
- **Example**: `HELLO WORLD EXAMPLE`
- **Use Case**: Headers, emphasis, constants

### 3. **camelCase**
- **Pattern**: `^[a-z][a-z0-9]*([A-Z][a-z0-9]*)+$`
- **Example**: `helloWorldExample`
- **Use Case**: Variable names, method names in Java/JavaScript

### 4. **PascalCase**
- **Pattern**: `^[A-Z][a-z0-9]*([A-Z][a-z0-9]*)*$`
- **Example**: `HelloWorldExample`
- **Use Case**: Class names, type names

### 5. **snake_case**
- **Pattern**: `^[a-z0-9_]+$` (contains `_`)
- **Example**: `hello_world_example`
- **Use Case**: File names, database columns, Python variables

### 6. **kebab-case**
- **Pattern**: `^[a-z0-9\-]+$` (contains `-`)
- **Example**: `hello-world-example`
- **Use Case**: URLs, CSS classes, HTML attributes

### 7. **CONSTANT_CASE**
- **Pattern**: `^[A-Z0-9_]+$` (contains `_`)
- **Example**: `HELLO_WORLD_EXAMPLE`
- **Use Case**: Constants, environment variables, configuration keys

### 8. **dot.case**
- **Pattern**: `^[a-z0-9\.]+$` (contains `.`)
- **Example**: `hello.world.example`
- **Use Case**: Domain names, package names, file extensions

### 9. **space case**
- **Pattern**: `^[a-z0-9\s]+$` (contains spaces)
- **Example**: `hello world example`
- **Use Case**: Human-readable text, titles, descriptions

### 10. **SCREAMING_SNAKE_CASE**
- **Pattern**: `^[A-Z0-9_]+$` (contains `_`)
- **Example**: `HELLO_WORLD_EXAMPLE`
- **Use Case**: Constants, environment variables (same as CONSTANT_CASE)

### 11. **Train-Case**
- **Pattern**: `^[A-Z][a-z0-9]*(\-[A-Z][a-z0-9]*)*$`
- **Example**: `Hello-World-Example`
- **Use Case**: Titles, headings, product names

### 12. **Title Case**
- **Pattern**: `^[A-Z][a-z0-9]*(\s+[A-Z][a-z0-9]*)*$`
- **Example**: `Hello World Example`
- **Use Case**: Article titles, book titles, section headers

## Word Splitting Algorithm

### Unicode-Aware Boundary Detection

The implementation uses sophisticated regex patterns to detect word boundaries:

```java
// Pattern for lowercase-to-uppercase transitions
private static final Pattern JS_J = Pattern.compile("([\\p{Ll}\\d])(\\p{Lu})", Pattern.UNICODE_CHARACTER_CLASS);

// Pattern for uppercase-to-uppercase transitions
private static final Pattern JS_X = Pattern.compile("(\\p{Lu})([\\p{Lu}][\\p{Ll}])", Pattern.UNICODE_CHARACTER_CLASS);

// Pattern for letter-number transitions
private static final Pattern JS_Y = Pattern.compile("(\\d)\\p{Ll}|(\\p{L})\\d", Pattern.UNICODE_CHARACTER_CLASS);

// Pattern for non-alphanumeric separators
private static final Pattern JS_A = Pattern.compile("[^\\p{L}\\d]+", Pattern.UNICODE_CHARACTER_CLASS);
```

### Word Splitting Process

1. **Preprocessing**: Insert null characters (`\u0000`) at detected boundaries
2. **Splitting**: Split the string by null characters
3. **Number Separation**: Optionally separate letters and numbers
4. **Normalization**: Clean up empty segments and join with target separator

### Example Word Splitting

```java
Input: "helloWorld123Example"
Process:
1. Insert boundaries: "hello\u0000World\u0000123\u0000Example"
2. Split: ["hello", "World", "123", "Example"]
3. Result: "hello World 123 Example"
```

## Case Detection Algorithm

### Detection Priority

The case detection follows a specific priority order:

1. **CONSTANT_CASE** - All caps with underscores
2. **SNAKE_CASE** - All lowercase with underscores
3. **KEBAB_CASE** - All lowercase with hyphens
4. **DOT_CASE** - All lowercase with dots
5. **UPPERCASE** - All caps (no separators)
6. **PASCAL_CASE** - Starts with uppercase, no separators
7. **CAMEL_CASE** - Starts with lowercase, has uppercase transitions
8. **TITLE_CASE** - Words separated by spaces, each capitalized
9. **LOWERCASE** - All lowercase (no separators)
10. **MIXED** - Doesn't match any specific pattern

### Detection Logic

```java
public static CaseFormat detectCase(String text) {
    // Check patterns in priority order
    if (text.matches("^[A-Z0-9_]+$") && text.contains("_")) {
        return CaseFormat.CONSTANT_CASE;
    }
    // ... other patterns
    return CaseFormat.MIXED;
}
```

## Performance Characteristics

### Time Complexity

- **Word Splitting**: O(n) where n is the length of the input string
- **Case Detection**: O(n) for regex pattern matching
- **Case Conversion**: O(n) for the conversion process

### Memory Usage

- **Word Splitting**: O(n) for storing split words
- **Case Detection**: O(1) for pattern matching
- **Case Conversion**: O(n) for the output string

### Optimization Features

- **Fast Path**: Direct separator replacement for already-separated text
- **Pattern Caching**: Compiled regex patterns for reuse
- **StringBuilder**: Efficient string concatenation

## Implementation Details

### Core Conversion Method

```java
public static String toSnakeCase(String text) {
    if (text == null || text.isEmpty()) {
        return text;
    }
    
    String normalized = normalizeAndSeparate(text, "_");
    return normalized.toLowerCase();
}
```

### Normalization Process

```java
private static String normalizeAndSeparate(String text, String separator) {
    // Fast path for already separated text
    if (ALREADY_SEPARATED_PATTERN.matcher(text).matches()) {
        return SEPARATOR_PATTERN.matcher(text).replaceAll(separator);
    }
    
    // Use unicode-aware splitting
    List<String> words = splitWords(text, true);
    return String.join(separator, words);
}
```

## Error Handling

### Input Validation

- **Null Input**: Returns the input as-is
- **Empty String**: Returns the input as-is
- **Invalid Characters**: Handled gracefully through regex patterns

### Edge Cases

- **Single Characters**: Properly classified (e.g., "a" → LOWERCASE, "A" → UPPERCASE)
- **Numbers Only**: Treated as valid input
- **Mixed Separators**: Normalized to consistent format
- **Leading/Trailing Separators**: Preserved in output

## Usage Examples

### Basic Conversions

```java
// Convert between formats
String snakeCase = TextCaseUtil.toSnakeCase("helloWorldExample");
// Result: "hello_world_example"

String camelCase = TextCaseUtil.toCamelCase("hello_world_example");
// Result: "helloWorldExample"

String titleCase = TextCaseUtil.toTitleCase("hello world example");
// Result: "Hello World Example"
```

### Case Detection

```java
// Detect existing format
CaseFormat format = TextCaseUtil.detectCase("helloWorld");
// Result: CaseFormat.CAMEL_CASE

boolean isSnakeCase = TextCaseUtil.isCase("hello_world", CaseFormat.SNAKE_CASE);
// Result: true
```

### Format Conversion

```java
// Convert between specific formats
String converted = TextCaseUtil.convertCase("hello_world", 
    CaseFormat.SNAKE_CASE, CaseFormat.CAMEL_CASE);
// Result: "helloWorld"
```

## Integration with crypto-utils

### Package Structure

```
com.haiphamcoder.crypto.text
├── TextCaseUtil.java          # Main utility class
└── TextCaseUtilTest.java      # Unit tests
```

### Dependencies

- **Java 8+**: Uses modern Java features and patterns
- **No External Dependencies**: Pure Java implementation
- **Unicode Support**: Built-in Java unicode character classes

### Thread Safety

- **Static Methods**: All methods are static and stateless
- **Immutable Operations**: No shared state between method calls
- **Concurrent Access**: Safe for multi-threaded environments

## Best Practices

### Performance Considerations

1. **Reuse CaseFormat Enums**: Avoid creating new enum instances
2. **Batch Processing**: Process multiple strings together when possible
3. **Cache Results**: Store conversion results for repeated use

### Memory Management

1. **String Interning**: Consider interning frequently used case formats
2. **Buffer Reuse**: Reuse StringBuilder instances for large-scale operations
3. **Garbage Collection**: Large strings are automatically cleaned up

### Error Handling

1. **Input Validation**: Always validate input before processing
2. **Graceful Degradation**: Handle edge cases gracefully
3. **Logging**: Log unexpected input patterns for debugging

## Testing Strategy

### Test Coverage

- **Unit Tests**: 100% method coverage
- **Edge Cases**: Null, empty, single character inputs
- **Format Validation**: All 12 case formats tested
- **Round-trip Conversion**: Verify conversion consistency
- **Performance Tests**: Large input validation

### Test Vectors

```java
// Standard test cases
assertEquals("hello_world", TextCaseUtil.toSnakeCase("helloWorld"));
assertEquals("helloWorld", TextCaseUtil.toCamelCase("hello_world"));
assertEquals("Hello World", TextCaseUtil.toTitleCase("hello world"));
```

## Future Enhancements

### Planned Features

1. **Locale Support**: Language-specific case conversion rules
2. **Custom Separators**: User-defined separator characters
3. **Batch Processing**: Process multiple strings efficiently
4. **Streaming Support**: Process large text files
5. **Case Format Templates**: Custom case format definitions

### Performance Improvements

1. **Pattern Compilation**: Cache compiled regex patterns
2. **String Pooling**: Reuse common string patterns
3. **Parallel Processing**: Multi-threaded conversion for large inputs

## Conclusion

The Text Case Conversion utilities provide a robust, performant, and comprehensive solution for text case manipulation. With unicode-aware processing, intelligent word splitting, and support for 12 different case formats, it serves as a complete solution for text processing needs in the crypto-utils library.

The implementation balances performance with accuracy, providing both fast-path optimizations for common cases and sophisticated algorithms for complex text patterns. The comprehensive test coverage ensures reliability across various input scenarios.

## References

- [Unicode Standard](https://unicode.org/standard/standard.html)
- [Java Regular Expressions](https://docs.oracle.com/javase/tutorial/essential/regex/)
- [Text Case Conventions](https://en.wikipedia.org/wiki/Naming_convention_(programming))
- [Java String API](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/lang/String.html)
