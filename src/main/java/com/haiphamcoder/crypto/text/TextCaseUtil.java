package com.haiphamcoder.crypto.text;

import java.util.regex.Pattern;

/**
 * Utility methods for converting text between different case formats.
 * 
 * <p>This utility provides comprehensive support for converting text between
 * various case formats commonly used in programming, documentation, and
 * data processing. It handles edge cases and provides consistent behavior
 * across different input formats.</p>
 * 
 * <p>Supported case formats:</p>
 * <ul>
 *   <li><strong>lowercase</strong>: all characters in lowercase</li>
 *   <li><strong>UPPERCASE</strong>: all characters in uppercase</li>
 *   <li><strong>camelCase</strong>: first word lowercase, subsequent words capitalized</li>
 *   <li><strong>PascalCase</strong>: all words capitalized (also known as UpperCamelCase)</li>
 *   <li><strong>snake_case</strong>: words separated by underscores, all lowercase</li>
 *   <li><strong>kebab-case</strong>: words separated by hyphens, all lowercase</li>
 *   <li><strong>CONSTANT_CASE</strong>: words separated by underscores, all uppercase</li>
 * </ul>
 * 
 * <p>Examples:</p>
 * <pre>
 * Input: "hello world example"
 * 
 * lowercase:     "hello world example"
 * UPPERCASE:     "HELLO WORLD EXAMPLE"
 * camelCase:     "helloWorldExample"
 * PascalCase:    "HelloWorldExample"
 * snake_case:    "hello_world_example"
 * kebab-case:    "hello-world-example"
 * CONSTANT_CASE: "HELLO_WORLD_EXAMPLE"
 * </pre>
 * 
 * <p>Note: This utility is designed for text processing and case conversion
 * tasks, not for cryptographic operations. It's included in the crypto-utils
 * library for convenience in data preprocessing and formatting tasks.</p>
 */
public final class TextCaseUtil {
    
    // Pattern to detect if text is already in a specific format
    private static final Pattern ALREADY_SEPARATED_PATTERN = Pattern.compile(
        "^[a-z]+([_\\-\\s][a-z]+)*$|^[A-Z]+([_\\-\\s][A-Z]+)*$|^[A-Z][a-z]+([_\\-\\s][A-Z][a-z]+)*$"
    );
    
    private static final Pattern SEPARATOR_PATTERN = Pattern.compile(
        "[\\s_\\-]+"
    );
    
    // ===== Unicode-aware word splitting =====
    // Patterns for detecting word boundaries and transitions
    private static final Pattern JS_J = Pattern.compile("([\\p{Ll}\\d])(\\p{Lu})", Pattern.UNICODE_CHARACTER_CLASS);
    private static final Pattern JS_X = Pattern.compile("(\\p{Lu})([\\p{Lu}][\\p{Ll}])", Pattern.UNICODE_CHARACTER_CLASS);
    private static final Pattern JS_Y = Pattern.compile("(\\d)\\p{Ll}|(\\p{L})\\d", Pattern.UNICODE_CHARACTER_CLASS);
    private static final Pattern JS_A = Pattern.compile("[^\\p{L}\\d]+", Pattern.UNICODE_CHARACTER_CLASS);

    /**
     * Split input string into words following unicode-aware boundaries.
     * This performs unicode-aware boundaries and optionally separates letter-number junctions.
     */
    private static java.util.List<String> splitWords(String input, boolean separateNumbers) {
        java.util.ArrayList<String> result = new java.util.ArrayList<>();
        if (input == null) {
            return result;
        }
        String s = input.trim();
        s = JS_J.matcher(s).replaceAll("$1\u0000$2");
        s = JS_X.matcher(s).replaceAll("$1\u0000$2");
        s = JS_A.matcher(s).replaceAll("\u0000");
        int start = 0;
        int end = s.length();
        while (start < end && start < s.length() && s.charAt(start) == '\u0000') start++;
        while (end > start && s.charAt(end - 1) == '\u0000') end--;
        if (start >= end) {
            return result;
        }
        String core = s.substring(start, end);
        String[] baseParts = core.split("\\u0000");
        for (String part : baseParts) {
            if (part.isEmpty()) continue;
            if (separateNumbers) {
                // Split at first number-letter or letter-number boundary repeatedly
                String token = part;
                boolean splitDone = true;
                while (splitDone) {
                    splitDone = false;
                    java.util.regex.Matcher m = JS_Y.matcher(token);
                    if (m.find()) {
                        int idx = m.start() + (m.group(1) != null ? 1 : 1);
                        // idx is boundary between the two characters
                        String left = token.substring(0, idx);
                        String right = token.substring(idx);
                        if (!left.isEmpty()) result.add(left);
                        token = right;
                        splitDone = true;
                    }
                }
                if (!token.isEmpty()) result.add(token);
            } else {
                result.add(part);
            }
        }
        return result;
    }

    private TextCaseUtil() {
        // Utility class, prevent instantiation
    }
    
    // ===== Basic Case Conversions =====
    
    /**
     * Convert text to lowercase.
     * 
     * @param text input text to convert
     * @return text converted to lowercase
     */
    public static String toLowerCase(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        return text.toLowerCase();
    }
    
    /**
     * Convert text to uppercase.
     * 
     * @param text input text to convert
     * @return text converted to uppercase
     */
    public static String toUpperCase(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        return text.toUpperCase();
    }
    
    /**
     * Convert text to title case (first letter of each word capitalized).
     * 
     * @param text input text to convert
     * @return text converted to title case
     */
    public static String toTitleCase(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        
        // First normalize to get proper word boundaries
        String normalized = normalizeAndSeparate(text, " ");
        String[] words = normalized.split("\\s+");
        StringBuilder result = new StringBuilder();
        
        for (int i = 0; i < words.length; i++) {
            if (words[i].isEmpty()) {
                continue;
            }
            
            if (i > 0) {
                result.append(' ');
            }
            
            if (words[i].length() == 1) {
                result.append(words[i].toUpperCase());
            } else {
                result.append(words[i].substring(0, 1).toUpperCase())
                      .append(words[i].substring(1).toLowerCase());
            }
        }
        
        return result.toString();
    }
    
    // ===== camelCase Conversions =====
    
    /**
     * Convert text to camelCase (first word lowercase, subsequent words capitalized).
     * 
     * @param text input text to convert
     * @return text converted to camelCase
     */
    public static String toCamelCase(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        
        String[] words = SEPARATOR_PATTERN.split(text.trim());
        if (words.length == 0) {
            return "";
        }
        
        StringBuilder result = new StringBuilder();
        
        // First word in lowercase
        if (words[0].length() > 0) {
            result.append(words[0].toLowerCase());
        }
        
        // Subsequent words capitalized
        for (int i = 1; i < words.length; i++) {
            if (words[i].length() > 0) {
                if (words[i].length() == 1) {
                    result.append(words[i].toUpperCase());
                } else {
                    result.append(words[i].substring(0, 1).toUpperCase())
                          .append(words[i].substring(1).toLowerCase());
                }
            }
        }
        
        return result.toString();
    }
    
    /**
     * Convert text to PascalCase (all words capitalized, also known as UpperCamelCase).
     * 
     * @param text input text to convert
     * @return text converted to PascalCase
     */
    public static String toPascalCase(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        
        String[] words = SEPARATOR_PATTERN.split(text.trim());
        if (words.length == 0) {
            return "";
        }
        
        StringBuilder result = new StringBuilder();
        
        // All words capitalized
        for (String word : words) {
            if (word.length() > 0) {
                if (word.length() == 1) {
                    result.append(word.toUpperCase());
                } else {
                    result.append(word.substring(0, 1).toUpperCase())
                          .append(word.substring(1).toLowerCase());
                }
            }
        }
        
        return result.toString();
    }
    
    // ===== Separator-based Conversions =====
    
    /**
     * Convert text to snake_case (words separated by underscores, all lowercase).
     * 
     * @param text input text to convert
     * @return text converted to snake_case
     */
    public static String toSnakeCase(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        
        return normalizeAndSeparate(text, "_").toLowerCase();
    }
    
    /**
     * Convert text to kebab-case (words separated by hyphens, all lowercase).
     * 
     * @param text input text to convert
     * @return text converted to kebab-case
     */
    public static String toKebabCase(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        
        return normalizeAndSeparate(text, "-").toLowerCase();
    }
    
    /**
     * Convert text to CONSTANT_CASE (words separated by underscores, all uppercase).
     * 
     * @param text input text to convert
     * @return text converted to CONSTANT_CASE
     */
    public static String toConstantCase(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        
        return normalizeAndSeparate(text, "_").toUpperCase();
    }
    
    // ===== Advanced Conversions =====
    
    /**
     * Convert text to dot.case (words separated by dots, all lowercase).
     * 
     * @param text input text to convert
     * @return text converted to dot.case
     */
    public static String toDotCase(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        
        return normalizeAndSeparate(text, ".").toLowerCase();
    }
    
    /**
     * Convert text to space case (words separated by spaces, all lowercase).
     * 
     * @param text input text to convert
     * @return text converted to space case
     */
    public static String toSpaceCase(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        
        return normalizeAndSeparate(text, " ").toLowerCase();
    }
    
    /**
     * Convert text to SCREAMING_SNAKE_CASE (words separated by underscores, all uppercase).
     * This is an alias for toConstantCase().
     * 
     * @param text input text to convert
     * @return text converted to SCREAMING_SNAKE_CASE
     */
    public static String toScreamingSnakeCase(String text) {
        return toConstantCase(text);
    }
    
    /**
     * Convert text to Train-Case (words separated by hyphens, all capitalized).
     * 
     * @param text input text to convert
     * @return text converted to Train-Case
     */
    public static String toTrainCase(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        
        // First normalize to get proper word boundaries
        String normalized = normalizeAndSeparate(text, " ");
        String[] words = normalized.split("\\s+");
        if (words.length == 0) {
            return "";
        }
        
        StringBuilder result = new StringBuilder();
        
        for (int i = 0; i < words.length; i++) {
            if (words[i].length() > 0) {
                if (i > 0) {
                    result.append('-');
                }
                
                if (words[i].length() == 1) {
                    result.append(words[i].toUpperCase());
                } else {
                    result.append(words[i].substring(0, 1).toUpperCase())
                          .append(words[i].substring(1).toLowerCase());
                }
            }
        }
        
        return result.toString();
    }
    
    // ===== Case Detection =====
    
    /**
     * Detect the case format of the input text.
     * 
     * @param text input text to analyze
     * @return CaseFormat enum representing the detected case
     */
    public static CaseFormat detectCase(String text) {
        if (text == null || text.isEmpty()) {
            return CaseFormat.UNKNOWN;
        }
        
        // Check for constant case (SCREAMING_SNAKE_CASE)
        if (text.matches("^[A-Z0-9_]+$") && text.contains("_")) {
            return CaseFormat.CONSTANT_CASE;
        }
        
        // Check for snake_case
        if (text.matches("^[a-z0-9_]+$") && text.contains("_")) {
            return CaseFormat.SNAKE_CASE;
        }
        
        // Check for kebab-case
        if (text.matches("^[a-z0-9\\-]+$") && text.contains("-")) {
            return CaseFormat.KEBAB_CASE;
        }
        
        // Check for dot.case
        if (text.matches("^[a-z0-9\\.]+$") && text.contains(".")) {
            return CaseFormat.DOT_CASE;
        }
        
        // Check for UPPERCASE
        if (text.matches("^[A-Z0-9\\s]+$")) {
            return CaseFormat.UPPERCASE;
        }
        
        // Check for PascalCase
        if (text.matches("^[A-Z][a-z0-9]*([A-Z][a-z0-9]*)*$")) {
            return CaseFormat.PASCAL_CASE;
        }
        
        // Check for camelCase (require at least one uppercase transition)
        if (text.matches("^[a-z][a-z0-9]*([A-Z][a-z0-9]*)+$")) {
            return CaseFormat.CAMEL_CASE;
        }
        
        // Check for lowercase
        if (text.matches("^[a-z0-9\\s]+$")) {
            return CaseFormat.LOWERCASE;
        }
        
        // Check for single lowercase letter
        if (text.matches("^[a-z]$")) {
            return CaseFormat.LOWERCASE;
        }
        
        // Check for Title Case
        if (text.matches("^[A-Z][a-z0-9]*(\\s+[A-Z][a-z0-9]*)*$")) {
            return CaseFormat.TITLE_CASE;
        }
        
        return CaseFormat.MIXED;
    }
    
    /**
     * Check if text is in a specific case format.
     * 
     * @param text input text to check
     * @param caseFormat case format to check against
     * @return true if text matches the specified case format
     */
    public static boolean isCase(String text, CaseFormat caseFormat) {
        return detectCase(text) == caseFormat;
    }
    
    // ===== Utility Methods =====
    
    /**
     * Normalize text by adding separators at word boundaries and cleaning up separators.
     * 
     * @param text input text to normalize
     * @param separator separator character to use
     * @return normalized text with separators
     */
    private static String normalizeAndSeparate(String text, String separator) {
        if (text == null || text.isEmpty()) {
            return text;
        }

        // Fast path if already separated: just normalize separators
        if (ALREADY_SEPARATED_PATTERN.matcher(text).matches()) {
            return SEPARATOR_PATTERN.matcher(text).replaceAll(separator);
        }

        // Use unicode-aware splitting with number separation for robust behavior
        java.util.List<String> words = splitWords(text, true);
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < words.size(); i++) {
            if (i > 0) result.append(separator);
            result.append(words.get(i));
        }
        return result.toString();
    }
    
    /**
     * Convert text between different case formats.
     * 
     * @param text input text to convert
     * @param fromCase source case format
     * @param toCase target case format
     * @return text converted to the target case format
     */
    public static String convertCase(String text, CaseFormat fromCase, CaseFormat toCase) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        
        // First normalize to a standard format
        String normalized = normalizeToStandard(text, fromCase);
        
        // Then convert to target format
        return convertFromStandard(normalized, toCase);
    }
    
    /**
     * Normalize text to a standard format (space-separated words).
     * 
     * @param text input text
     * @param fromCase source case format
     * @return normalized text in standard format
     */
    private static String normalizeToStandard(String text, CaseFormat fromCase) {
        switch (fromCase) {
            case CONSTANT_CASE:
            case SNAKE_CASE:
                return text.replaceAll("[_\\-]", " ").toLowerCase();
            case KEBAB_CASE:
                return text.replaceAll("[\\-]", " ").toLowerCase();
            case DOT_CASE:
                return text.replaceAll("[\\.]", " ").toLowerCase();
            case PASCAL_CASE:
            case CAMEL_CASE:
                return normalizeAndSeparate(text, " ").toLowerCase();
            case UPPERCASE:
                return text.toLowerCase();
            case LOWERCASE:
            case TITLE_CASE:
            case MIXED:
            default:
                return text.toLowerCase();
        }
    }
    
    /**
     * Convert normalized text to target case format.
     * 
     * @param normalized normalized text in standard format
     * @param toCase target case format
     * @return text in target case format
     */
    private static String convertFromStandard(String normalized, CaseFormat toCase) {
        switch (toCase) {
            case CONSTANT_CASE:
                return toConstantCase(normalized);
            case SNAKE_CASE:
                return toSnakeCase(normalized);
            case KEBAB_CASE:
                return toKebabCase(normalized);
            case DOT_CASE:
                return toDotCase(normalized);
            case PASCAL_CASE:
                return toPascalCase(normalized);
            case CAMEL_CASE:
                return toCamelCase(normalized);
            case UPPERCASE:
                return toUpperCase(normalized);
            case LOWERCASE:
                return toLowerCase(normalized);
            case TITLE_CASE:
                return toTitleCase(normalized);
            case SPACE_CASE:
                return toSpaceCase(normalized);
            case TRAIN_CASE:
                return toTrainCase(normalized);
            default:
                return normalized;
        }
    }
    
    /**
     * Enum representing different case formats.
     */
    public enum CaseFormat {
        /** All characters in lowercase */
        LOWERCASE,
        
        /** All characters in uppercase */
        UPPERCASE,
        
        /** First word lowercase, subsequent words capitalized */
        CAMEL_CASE,
        
        /** All words capitalized (UpperCamelCase) */
        PASCAL_CASE,
        
        /** Words separated by underscores, all lowercase */
        SNAKE_CASE,
        
        /** Words separated by hyphens, all lowercase */
        KEBAB_CASE,
        
        /** Words separated by underscores, all uppercase */
        CONSTANT_CASE,
        
        /** Words separated by dots, all lowercase */
        DOT_CASE,
        
        /** Words separated by spaces, all lowercase */
        SPACE_CASE,
        
        /** Words separated by hyphens, all capitalized */
        TRAIN_CASE,
        
        /** First letter of each word capitalized */
        TITLE_CASE,
        
        /** Mixed case formats */
        MIXED,
        
        /** Unknown or unrecognized format */
        UNKNOWN
    }
}
