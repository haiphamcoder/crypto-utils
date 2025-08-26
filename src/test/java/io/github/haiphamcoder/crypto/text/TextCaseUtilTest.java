package io.github.haiphamcoder.crypto.text;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import io.github.haiphamcoder.crypto.text.TextCaseUtil.CaseFormat;

class TextCaseUtilTest {

    // ===== Basic Case Conversions =====
    
    @Test
    void testToLowerCase() {
        assertEquals("hello world", TextCaseUtil.toLowerCase("Hello World"));
        assertEquals("hello world", TextCaseUtil.toLowerCase("HELLO WORLD"));
        assertEquals("hello world", TextCaseUtil.toLowerCase("hello world"));
        assertEquals("", TextCaseUtil.toLowerCase(""));
        assertNull(TextCaseUtil.toLowerCase(null));
    }
    
    @Test
    void testToUpperCase() {
        assertEquals("HELLO WORLD", TextCaseUtil.toUpperCase("Hello World"));
        assertEquals("HELLO WORLD", TextCaseUtil.toUpperCase("hello world"));
        assertEquals("HELLO WORLD", TextCaseUtil.toUpperCase("HELLO WORLD"));
        assertEquals("", TextCaseUtil.toUpperCase(""));
        assertNull(TextCaseUtil.toUpperCase(null));
    }
    
    @Test
    void testToTitleCase() {
        assertEquals("Hello World Example", TextCaseUtil.toTitleCase("hello world example"));
        assertEquals("Hello World Example", TextCaseUtil.toTitleCase("HELLO WORLD EXAMPLE"));
        assertEquals("Hello World Example", TextCaseUtil.toTitleCase("hello_world_example"));
        assertEquals("Hello World Example", TextCaseUtil.toTitleCase("hello-world-example"));
        assertEquals("Hello World Example", TextCaseUtil.toTitleCase("helloWorldExample"));
        assertEquals("Hello World Example", TextCaseUtil.toTitleCase("HelloWorldExample"));
        assertEquals("", TextCaseUtil.toTitleCase(""));
        assertNull(TextCaseUtil.toTitleCase(null));
    }
    
    // ===== camelCase Conversions =====
    
    @Test
    void testToCamelCase() {
        assertEquals("helloWorldExample", TextCaseUtil.toCamelCase("hello world example"));
        assertEquals("helloWorldExample", TextCaseUtil.toCamelCase("HELLO WORLD EXAMPLE"));
        assertEquals("helloWorldExample", TextCaseUtil.toCamelCase("hello_world_example"));
        assertEquals("helloWorldExample", TextCaseUtil.toCamelCase("hello-world-example"));
        assertEquals("helloWorldExample", TextCaseUtil.toCamelCase("Hello World Example"));
        assertEquals("", TextCaseUtil.toCamelCase(""));
        assertNull(TextCaseUtil.toCamelCase(null));
    }
    
    @Test
    void testToCamelCaseWithSingleWord() {
        assertEquals("hello", TextCaseUtil.toCamelCase("hello"));
        assertEquals("hello", TextCaseUtil.toCamelCase("HELLO"));
        assertEquals("hello", TextCaseUtil.toCamelCase("Hello"));
    }
    
    @Test
    void testToCamelCaseWithNumbers() {
        assertEquals("hello123World", TextCaseUtil.toCamelCase("hello 123 world"));
        assertEquals("hello123World", TextCaseUtil.toCamelCase("hello_123_world"));
        assertEquals("hello123World", TextCaseUtil.toCamelCase("hello-123-world"));
    }
    
    // ===== PascalCase Conversions =====
    
    @Test
    void testToPascalCase() {
        assertEquals("HelloWorldExample", TextCaseUtil.toPascalCase("hello world example"));
        assertEquals("HelloWorldExample", TextCaseUtil.toPascalCase("HELLO WORLD EXAMPLE"));
        assertEquals("HelloWorldExample", TextCaseUtil.toPascalCase("hello_world_example"));
        assertEquals("HelloWorldExample", TextCaseUtil.toPascalCase("hello-world-example"));
        assertEquals("HelloWorldExample", TextCaseUtil.toPascalCase("Hello World Example"));
        assertEquals("", TextCaseUtil.toPascalCase(""));
        assertNull(TextCaseUtil.toPascalCase(null));
    }
    
    @Test
    void testToPascalCaseWithSingleWord() {
        assertEquals("Hello", TextCaseUtil.toPascalCase("hello"));
        assertEquals("Hello", TextCaseUtil.toPascalCase("HELLO"));
        assertEquals("Hello", TextCaseUtil.toPascalCase("Hello"));
    }
    
    @Test
    void testToPascalCaseWithNumbers() {
        assertEquals("Hello123World", TextCaseUtil.toPascalCase("hello 123 world"));
        assertEquals("Hello123World", TextCaseUtil.toPascalCase("hello_123_world"));
        assertEquals("Hello123World", TextCaseUtil.toPascalCase("hello-123-world"));
    }
    
    // ===== Separator-based Conversions =====
    
    @Test
    void testToSnakeCase() {
        assertEquals("hello_world_example", TextCaseUtil.toSnakeCase("hello world example"));
        assertEquals("hello_world_example", TextCaseUtil.toSnakeCase("HELLO WORLD EXAMPLE"));
        assertEquals("hello_world_example", TextCaseUtil.toSnakeCase("helloWorldExample"));
        assertEquals("hello_world_example", TextCaseUtil.toSnakeCase("HelloWorldExample"));
        assertEquals("hello_world_example", TextCaseUtil.toSnakeCase("hello-world-example"));
        assertEquals("", TextCaseUtil.toSnakeCase(""));
        assertNull(TextCaseUtil.toSnakeCase(null));
    }
    
    @Test
    void testToKebabCase() {
        assertEquals("hello-world-example", TextCaseUtil.toKebabCase("hello world example"));
        assertEquals("hello-world-example", TextCaseUtil.toKebabCase("HELLO WORLD EXAMPLE"));
        assertEquals("hello-world-example", TextCaseUtil.toKebabCase("helloWorldExample"));
        assertEquals("hello-world-example", TextCaseUtil.toKebabCase("HelloWorldExample"));
        assertEquals("hello-world-example", TextCaseUtil.toKebabCase("hello_world_example"));
        assertEquals("", TextCaseUtil.toKebabCase(""));
        assertNull(TextCaseUtil.toKebabCase(null));
    }
    
    @Test
    void testToConstantCase() {
        assertEquals("HELLO_WORLD_EXAMPLE", TextCaseUtil.toConstantCase("hello world example"));
        assertEquals("HELLO_WORLD_EXAMPLE", TextCaseUtil.toConstantCase("HELLO WORLD EXAMPLE"));
        assertEquals("HELLO_WORLD_EXAMPLE", TextCaseUtil.toConstantCase("helloWorldExample"));
        assertEquals("HELLO_WORLD_EXAMPLE", TextCaseUtil.toConstantCase("HelloWorldExample"));
        assertEquals("HELLO_WORLD_EXAMPLE", TextCaseUtil.toConstantCase("hello-world-example"));
        assertEquals("", TextCaseUtil.toConstantCase(""));
        assertNull(TextCaseUtil.toConstantCase(null));
    }
    
    // ===== Advanced Conversions =====
    
    @Test
    void testToDotCase() {
        assertEquals("hello.world.example", TextCaseUtil.toDotCase("hello world example"));
        assertEquals("hello.world.example", TextCaseUtil.toDotCase("HELLO WORLD EXAMPLE"));
        assertEquals("hello.world.example", TextCaseUtil.toDotCase("helloWorldExample"));
        assertEquals("hello.world.example", TextCaseUtil.toDotCase("HelloWorldExample"));
        assertEquals("hello.world.example", TextCaseUtil.toDotCase("hello_world_example"));
        assertEquals("", TextCaseUtil.toDotCase(""));
        assertNull(TextCaseUtil.toDotCase(null));
    }
    
    @Test
    void testToSpaceCase() {
        assertEquals("hello world example", TextCaseUtil.toSpaceCase("hello world example"));
        assertEquals("hello world example", TextCaseUtil.toSpaceCase("HELLO WORLD EXAMPLE"));
        assertEquals("hello world example", TextCaseUtil.toSpaceCase("helloWorldExample"));
        assertEquals("hello world example", TextCaseUtil.toSpaceCase("HelloWorldExample"));
        assertEquals("hello world example", TextCaseUtil.toSpaceCase("hello_world_example"));
        assertEquals("", TextCaseUtil.toSpaceCase(""));
        assertNull(TextCaseUtil.toSpaceCase(null));
    }
    
    @Test
    void testToScreamingSnakeCase() {
        assertEquals("HELLO_WORLD_EXAMPLE", TextCaseUtil.toScreamingSnakeCase("hello world example"));
        assertEquals("HELLO_WORLD_EXAMPLE", TextCaseUtil.toScreamingSnakeCase("HELLO WORLD EXAMPLE"));
        assertEquals("HELLO_WORLD_EXAMPLE", TextCaseUtil.toScreamingSnakeCase("helloWorldExample"));
        assertEquals("HELLO_WORLD_EXAMPLE", TextCaseUtil.toScreamingSnakeCase("HelloWorldExample"));
        assertEquals("HELLO_WORLD_EXAMPLE", TextCaseUtil.toScreamingSnakeCase("hello-world-example"));
        assertEquals("", TextCaseUtil.toScreamingSnakeCase(""));
        assertNull(TextCaseUtil.toScreamingSnakeCase(null));
    }
    
    @Test
    void testToTrainCase() {
        assertEquals("Hello-World-Example", TextCaseUtil.toTrainCase("hello world example"));
        assertEquals("Hello-World-Example", TextCaseUtil.toTrainCase("HELLO WORLD EXAMPLE"));
        assertEquals("Hello-World-Example", TextCaseUtil.toTrainCase("helloWorldExample"));
        assertEquals("Hello-World-Example", TextCaseUtil.toTrainCase("HelloWorldExample"));
        assertEquals("Hello-World-Example", TextCaseUtil.toTrainCase("hello_world_example"));
        assertEquals("", TextCaseUtil.toTrainCase(""));
        assertNull(TextCaseUtil.toTrainCase(null));
    }
    
    // ===== Case Detection =====
    
    @Test
    void testDetectCase() {
        assertEquals(CaseFormat.LOWERCASE, TextCaseUtil.detectCase("hello world"));
        assertEquals(CaseFormat.UPPERCASE, TextCaseUtil.detectCase("HELLO WORLD"));
        assertEquals(CaseFormat.CAMEL_CASE, TextCaseUtil.detectCase("helloWorld"));
        assertEquals(CaseFormat.PASCAL_CASE, TextCaseUtil.detectCase("HelloWorld"));
        assertEquals(CaseFormat.SNAKE_CASE, TextCaseUtil.detectCase("hello_world"));
        assertEquals(CaseFormat.KEBAB_CASE, TextCaseUtil.detectCase("hello-world"));
        assertEquals(CaseFormat.CONSTANT_CASE, TextCaseUtil.detectCase("HELLO_WORLD"));
        assertEquals(CaseFormat.DOT_CASE, TextCaseUtil.detectCase("hello.world"));
        assertEquals(CaseFormat.TITLE_CASE, TextCaseUtil.detectCase("Hello World"));
        assertEquals(CaseFormat.MIXED, TextCaseUtil.detectCase("Hello world"));
        assertEquals(CaseFormat.UNKNOWN, TextCaseUtil.detectCase(""));
        assertEquals(CaseFormat.UNKNOWN, TextCaseUtil.detectCase(null));
    }
    
    @Test
    void testDetectCaseWithNumbers() {
        assertEquals(CaseFormat.CAMEL_CASE, TextCaseUtil.detectCase("hello123World"));
        assertEquals(CaseFormat.PASCAL_CASE, TextCaseUtil.detectCase("Hello123World"));
        assertEquals(CaseFormat.SNAKE_CASE, TextCaseUtil.detectCase("hello_123_world"));
        assertEquals(CaseFormat.KEBAB_CASE, TextCaseUtil.detectCase("hello-123-world"));
        assertEquals(CaseFormat.CONSTANT_CASE, TextCaseUtil.detectCase("HELLO_123_WORLD"));
        assertEquals(CaseFormat.DOT_CASE, TextCaseUtil.detectCase("hello.123.world"));
    }
    
    @Test
    void testDetectCaseEdgeCases() {
        assertEquals(CaseFormat.LOWERCASE, TextCaseUtil.detectCase("a"));
        assertEquals(CaseFormat.UPPERCASE, TextCaseUtil.detectCase("A"));
        assertEquals(CaseFormat.CAMEL_CASE, TextCaseUtil.detectCase("aB"));
        assertEquals(CaseFormat.PASCAL_CASE, TextCaseUtil.detectCase("Ab"));
        assertEquals(CaseFormat.SNAKE_CASE, TextCaseUtil.detectCase("a_b"));
        assertEquals(CaseFormat.KEBAB_CASE, TextCaseUtil.detectCase("a-b"));
        assertEquals(CaseFormat.CONSTANT_CASE, TextCaseUtil.detectCase("A_B"));
        assertEquals(CaseFormat.DOT_CASE, TextCaseUtil.detectCase("a.b"));
    }
    
    @Test
    void testIsCase() {
        assertTrue(TextCaseUtil.isCase("hello world", CaseFormat.LOWERCASE));
        assertTrue(TextCaseUtil.isCase("HELLO WORLD", CaseFormat.UPPERCASE));
        assertTrue(TextCaseUtil.isCase("helloWorld", CaseFormat.CAMEL_CASE));
        assertTrue(TextCaseUtil.isCase("HelloWorld", CaseFormat.PASCAL_CASE));
        assertTrue(TextCaseUtil.isCase("hello_world", CaseFormat.SNAKE_CASE));
        assertTrue(TextCaseUtil.isCase("hello-world", CaseFormat.KEBAB_CASE));
        assertTrue(TextCaseUtil.isCase("HELLO_WORLD", CaseFormat.CONSTANT_CASE));
        assertTrue(TextCaseUtil.isCase("hello.world", CaseFormat.DOT_CASE));
        assertTrue(TextCaseUtil.isCase("Hello World", CaseFormat.TITLE_CASE));
        
        assertFalse(TextCaseUtil.isCase("Hello world", CaseFormat.LOWERCASE));
        assertFalse(TextCaseUtil.isCase("hello world", CaseFormat.UPPERCASE));
        assertFalse(TextCaseUtil.isCase("HelloWorld", CaseFormat.CAMEL_CASE));
        assertFalse(TextCaseUtil.isCase("helloWorld", CaseFormat.PASCAL_CASE));
    }
    
    // ===== Case Conversion Between Formats =====
    
    @Test
    void testConvertCase() {
        // Convert from snake_case to camelCase
        assertEquals("helloWorld", TextCaseUtil.convertCase("hello_world", CaseFormat.SNAKE_CASE, CaseFormat.CAMEL_CASE));
        
        // Convert from kebab-case to PascalCase
        assertEquals("HelloWorld", TextCaseUtil.convertCase("hello-world", CaseFormat.KEBAB_CASE, CaseFormat.PASCAL_CASE));
        
        // Convert from camelCase to snake_case
        assertEquals("hello_world", TextCaseUtil.convertCase("helloWorld", CaseFormat.CAMEL_CASE, CaseFormat.SNAKE_CASE));
        
        // Convert from PascalCase to kebab-case
        assertEquals("hello-world", TextCaseUtil.convertCase("HelloWorld", CaseFormat.PASCAL_CASE, CaseFormat.KEBAB_CASE));
        
        // Convert from UPPERCASE to lowercase
        assertEquals("hello world", TextCaseUtil.convertCase("HELLO WORLD", CaseFormat.UPPERCASE, CaseFormat.LOWERCASE));
        
        // Convert from lowercase to CONSTANT_CASE
        assertEquals("HELLO_WORLD", TextCaseUtil.convertCase("hello world", CaseFormat.LOWERCASE, CaseFormat.CONSTANT_CASE));
    }
    
    @Test
    void testConvertCaseWithNumbers() {
        assertEquals("hello123World", TextCaseUtil.convertCase("hello_123_world", CaseFormat.SNAKE_CASE, CaseFormat.CAMEL_CASE));
        assertEquals("Hello123World", TextCaseUtil.convertCase("hello-123-world", CaseFormat.KEBAB_CASE, CaseFormat.PASCAL_CASE));
        assertEquals("hello_123_world", TextCaseUtil.convertCase("hello123World", CaseFormat.CAMEL_CASE, CaseFormat.SNAKE_CASE));
        assertEquals("hello-123-world", TextCaseUtil.convertCase("Hello123World", CaseFormat.PASCAL_CASE, CaseFormat.KEBAB_CASE));
    }
    
    // ===== Edge Cases and Special Characters =====
    
    @Test
    void testEdgeCases() {
        // Empty strings
        assertEquals("", TextCaseUtil.toCamelCase(""));
        assertEquals("", TextCaseUtil.toPascalCase(""));
        assertEquals("", TextCaseUtil.toSnakeCase(""));
        assertEquals("", TextCaseUtil.toKebabCase(""));
        assertEquals("", TextCaseUtil.toConstantCase(""));
        
        // Single characters
        assertEquals("h", TextCaseUtil.toCamelCase("h"));
        assertEquals("H", TextCaseUtil.toPascalCase("h"));
        assertEquals("h", TextCaseUtil.toSnakeCase("h"));
        assertEquals("h", TextCaseUtil.toKebabCase("h"));
        assertEquals("H", TextCaseUtil.toConstantCase("h"));
        
        // Numbers only
        assertEquals("123", TextCaseUtil.toCamelCase("123"));
        assertEquals("123", TextCaseUtil.toPascalCase("123"));
        assertEquals("123", TextCaseUtil.toSnakeCase("123"));
        assertEquals("123", TextCaseUtil.toKebabCase("123"));
        assertEquals("123", TextCaseUtil.toConstantCase("123"));
    }
    
    @Test
    void testSpecialCharacters() {
        // Mixed separators
        assertEquals("hello_world_example", TextCaseUtil.toSnakeCase("hello world_example"));
        assertEquals("hello_world_example", TextCaseUtil.toSnakeCase("hello-world_example"));
        assertEquals("hello_world_example", TextCaseUtil.toSnakeCase("hello world-example"));
        
        // Multiple spaces
        assertEquals("hello_world_example", TextCaseUtil.toSnakeCase("hello   world   example"));
        assertEquals("hello_world_example", TextCaseUtil.toSnakeCase("hello\tworld\nexample"));
        
        // Leading and trailing separators
        assertEquals("hello_world_example", TextCaseUtil.toSnakeCase("_hello_world_example_"));
        assertEquals("hello_world_example", TextCaseUtil.toSnakeCase("-hello-world-example-"));
        assertEquals("hello_world_example", TextCaseUtil.toSnakeCase(" hello world example "));
    }
    
    @Test
    void testComplexExamples() {
        // Real-world examples
        assertEquals("userProfile", TextCaseUtil.toCamelCase("user profile"));
        assertEquals("UserProfile", TextCaseUtil.toPascalCase("user profile"));
        assertEquals("user_profile", TextCaseUtil.toSnakeCase("user profile"));
        assertEquals("user-profile", TextCaseUtil.toKebabCase("user profile"));
        assertEquals("USER_PROFILE", TextCaseUtil.toConstantCase("user profile"));
        
        // API endpoint examples
        assertEquals("getUserById", TextCaseUtil.toCamelCase("get user by id"));
        assertEquals("GetUserById", TextCaseUtil.toPascalCase("get user by id"));
        assertEquals("get_user_by_id", TextCaseUtil.toSnakeCase("get user by id"));
        assertEquals("get-user-by-id", TextCaseUtil.toKebabCase("get user by id"));
        assertEquals("GET_USER_BY_ID", TextCaseUtil.toConstantCase("get user by id"));
        
        // Database column examples
        assertEquals("firstName", TextCaseUtil.toCamelCase("first name"));
        assertEquals("FirstName", TextCaseUtil.toPascalCase("first name"));
        assertEquals("first_name", TextCaseUtil.toSnakeCase("first name"));
        assertEquals("first-name", TextCaseUtil.toKebabCase("first name"));
        assertEquals("FIRST_NAME", TextCaseUtil.toConstantCase("first name"));
    }
    
    @Test
    void testNullHandling() {
        // All methods should handle null gracefully
        assertNull(TextCaseUtil.toLowerCase(null));
        assertNull(TextCaseUtil.toUpperCase(null));
        assertNull(TextCaseUtil.toTitleCase(null));
        assertNull(TextCaseUtil.toCamelCase(null));
        assertNull(TextCaseUtil.toPascalCase(null));
        assertNull(TextCaseUtil.toSnakeCase(null));
        assertNull(TextCaseUtil.toKebabCase(null));
        assertNull(TextCaseUtil.toConstantCase(null));
        assertNull(TextCaseUtil.toDotCase(null));
        assertNull(TextCaseUtil.toSpaceCase(null));
        assertNull(TextCaseUtil.toScreamingSnakeCase(null));
        assertNull(TextCaseUtil.toTrainCase(null));
        
        assertEquals(CaseFormat.UNKNOWN, TextCaseUtil.detectCase(null));
        assertFalse(TextCaseUtil.isCase(null, CaseFormat.LOWERCASE));
        assertNull(TextCaseUtil.convertCase(null, CaseFormat.LOWERCASE, CaseFormat.UPPERCASE));
    }
    
    @Test
    void testConsistency() {
        String input = "Hello World Example";
        
        // Test that converting through multiple formats and back produces consistent results
        String camelCase = TextCaseUtil.toCamelCase(input);
        String snakeCase = TextCaseUtil.toSnakeCase(camelCase);
        String backToCamel = TextCaseUtil.toCamelCase(snakeCase);
        
        assertEquals(camelCase, backToCamel);
        
        // Test round-trip conversions
        String original = "hello_world_example";
        String converted = TextCaseUtil.convertCase(original, CaseFormat.SNAKE_CASE, CaseFormat.CAMEL_CASE);
        String back = TextCaseUtil.convertCase(converted, CaseFormat.CAMEL_CASE, CaseFormat.SNAKE_CASE);
        
        assertEquals(original, back);
    }

    /**
     * Test that camelCase and PascalCase inputs are preserved correctly
     * when they already have the correct format.
     */
    @Test
    void testPreserveExistingCaseFormats() {
        // Test camelCase preservation
        assertEquals("helloWorld", TextCaseUtil.toCamelCase("       helloWorld    "));
        assertEquals("helloWorld", TextCaseUtil.toCamelCase("helloWorld"));
        assertEquals("helloWorld", TextCaseUtil.toCamelCase("  helloWorld  "));
        
        // Test PascalCase preservation  
        assertEquals("HelloWorld", TextCaseUtil.toPascalCase("     HelloWorld    "));
        assertEquals("HelloWorld", TextCaseUtil.toPascalCase("HelloWorld"));
        assertEquals("HelloWorld", TextCaseUtil.toPascalCase("  HelloWorld  "));
        
        // Test that mixed formats are still processed correctly
        assertEquals("helloWorld", TextCaseUtil.toCamelCase("hello_world"));
        assertEquals("helloWorld", TextCaseUtil.toCamelCase("hello-world"));
        assertEquals("helloWorld", TextCaseUtil.toCamelCase("hello world"));
        
        assertEquals("HelloWorld", TextCaseUtil.toPascalCase("hello_world"));
        assertEquals("HelloWorld", TextCaseUtil.toPascalCase("hello-world"));
        assertEquals("HelloWorld", TextCaseUtil.toPascalCase("hello world"));
    }

    @Test
    void testUserExample() {
        String input = "xin cHAo    caC   BAN";
        
        // Test all case conversions
        // Basic methods preserve spacing, advanced methods normalize spacing
        assertEquals("xin chao    cac   ban", TextCaseUtil.toLowerCase(input));
        assertEquals("XIN CHAO    CAC   BAN", TextCaseUtil.toUpperCase(input));
        assertEquals("Xin Chao Cac Ban", TextCaseUtil.toTitleCase(input));
        assertEquals("xinChaoCacBan", TextCaseUtil.toCamelCase(input));
        assertEquals("XinChaoCacBan", TextCaseUtil.toPascalCase(input));
        assertEquals("xin_chao_cac_ban", TextCaseUtil.toSnakeCase(input));
        assertEquals("xin-chao-cac-ban", TextCaseUtil.toKebabCase(input));
        assertEquals("XIN_CHAO_CAC_BAN", TextCaseUtil.toConstantCase(input));
        assertEquals("xin.chao.cac.ban", TextCaseUtil.toDotCase(input));
        assertEquals("xin chao cac ban", TextCaseUtil.toSpaceCase(input));
    }
}
