<?php
/**
 * SQL Formatter is a collection of utilities for debugging SQL queries.
 * It includes methods for formatting, syntax highlighting, removing comments, etc.
 *
 * @package    SqlFormatter
 * @author     Jeremy Dorn <jeremy@jeremydorn.com>
 * @author     Florin Patan <florinpatan@gmail.com>
 * @author     epoxa
 * @copyright  2013 Jeremy Dorn
 * @license    http://opensource.org/licenses/MIT
 * @link       http://github.com/jdorn/sql-formatter
 * @version    1.2.18
 */
class SqlFormatter
{
    // Constants for token types
    const TOKEN_TYPE_EMPTY_LINE = -1;
    const TOKEN_TYPE_WHITESPACE = 0;
    const TOKEN_TYPE_WORD = 1;
    const TOKEN_TYPE_QUOTE = 2;
    const TOKEN_TYPE_BACKTICK_QUOTE = 3;
    const TOKEN_TYPE_RESERVED = 4;
    const TOKEN_TYPE_RESERVED_TOPLEVEL = 5;
    const TOKEN_TYPE_RESERVED_NEWLINE = 6;
    const TOKEN_TYPE_BOUNDARY = 7;
    const TOKEN_TYPE_COMMENT = 8;
    const TOKEN_TYPE_BLOCK_COMMENT = 9;
    const TOKEN_TYPE_NUMBER = 10;
    const TOKEN_TYPE_ERROR = 11;
    const TOKEN_TYPE_VARIABLE = 12;
    const TOKEN_TYPE_RESERVED_NEWLINE_TOPLEVEL = 13;


    // Constants for different components of a token
    const TOKEN_TYPE = 0;
    const TOKEN_VALUE = 1;

    // Reserved words (for syntax highlighting)
    protected static $reserved = [
        'TRY', 'CATCH',
        'ADD', 'EXTERNAL', 'PROCEDURE', 'ALL', 'EXIT',
        'PROC', 'FETCH', 'PUBLIC', 'ALTER', 'FILE',
        'RAISERROR', 'AND', 'FILLFACTOR', 'READ', 'ANY', 'FOR', 'READTEXT', 'AS',
        'FOREIGN', 'RECONFIGURE', 'ASC', 'FREETEXT', 'REFERENCES', 'AUTHORIZATION', 'FREETEXTTABLE', 'REPLICATION',
        'BACKUP', 'FROM', 'RESTORE', 'BEGIN', 'FULL', 'RESTRICT', 'BETWEEN', 'FUNCTION',
        'RETURN', 'BREAK', 'GOTO', 'REVERT', 'BROWSE', 'GRANT', 'REVOKE', 'BULK',
        'GROUP', 'RIGHT', 'BY', 'HAVING', 'ROLLBACK', 'CASCADE', 'HOLDLOCK', 'ROWCOUNT',
        'CASE', 'IDENTITY', 'ROWGUIDCOL', 'CHECK', 'IDENTITY_INSERT', 'RULE', 'CHECKPOINT', 'IDENTITYCOL',
        'SAVE', 'CLOSE', 'IF', 'SCHEMA', 'CLUSTERED', 'IN', 'SECURITYAUDIT', 'COALESCE',
        'INDEX', 'SELECT', 'COLLATE', 'INNER', 'SEMANTICKEYPHRASETABLE', 'COLUMN', 'INSERT', 'SEMANTICSIMILARITYDETAILSTABLE',
        'COMMIT', 'INTERSECT', 'SEMANTICSIMILARITYTABLE', 'COMPUTE', 'INTO', 'SESSION_USER', 'CONSTRAINT', 'IS',
        'SET', 'CONTAINS', 'JOIN', 'SETUSER', 'CONTAINSTABLE', 'KEY', 'SHUTDOWN', 'CONTINUE',
        'KILL', 'SOME', 'CONVERT', 'LEFT', 'STATISTICS', 'CREATE', 'LIKE', 'SYSTEM_USER',
        'CROSS', 'LINENO', 'TABLE', 'CURRENT', 'LOAD', 'TABLESAMPLE', 'CURRENT_DATE', 'MERGE',
        'TEXTSIZE', 'CURRENT_TIME', 'NATIONAL', 'THEN', 'CURRENT_TIMESTAMP', 'NOCHECK', 'TO', 'CURRENT_USER',
        'NONCLUSTERED', 'TOP', 'CURSOR', 'NOT', 'TRAN', 'DATABASE', 'NULL', 'TRANSACTION',
        'DBCC', 'NULLIF', 'TRIGGER', 'DEALLOCATE', 'OF', 'TRUNCATE', 'DECLARE', 'OFF',
        'TRY_CONVERT', 'DEFAULT', 'OFFSETS', 'TSEQUAL', 'DELETE', 'ON', 'UNION', 'DENY',
        'OPEN', 'UNIQUE', 'DESC', 'OPENDATASOURCE', 'UNPIVOT', 'DISK', 'OPENQUERY', 'UPDATE',
        'DISTINCT', 'OPENROWSET', 'UPDATETEXT', 'DISTRIBUTED', 'OPENXML', 'USE', 'DOUBLE', 'OPTION',
        'USER', 'DROP', 'OR', 'VALUES', 'DUMP', 'ORDER', 'VARYING', 'ELSE',
        'OUTER', 'VIEW', 'END', 'OVER', 'WAITFOR', 'ERRLVL', 'PERCENT', 'WHEN',
        'ESCAPE', 'PIVOT', 'WHERE', 'EXCEPT', 'PLAN', 'WHILE', 'EXEC', 'PRECISION',
        'WITH', 'EXECUTE', 'PRIMARY', 'WITHIN', 'GROUP', 'EXISTS', 'PRINT', 'WRITETEXT',
        'PARTITION',
    ];


    // For SQL formatting
    // These keywords will all be on their own line
    protected static $reserved_toplevel = array(
        'DECLARE',
        'WITH',
        'SELECT',
        'DELETE',
        'INSERT',
        'FROM', 'WHERE', 'SET', 'LIMIT',
        'VALUES', 'UPDATE', 'HAVING', 'ADD', 'AFTER', 'UNION', 'EXCEPT', 'INTERSECT',
        'WHILE',
        'CREATE', 'DROP', 'ALTER', 'TRUNCATE',
        'RETURN',
        'END',
        'IF', 'ELSE',
        'EXEC', 'EXECUTE',
        'OPEN', 'CLOSE', 'FETCH',
        'INTO',
        'ORDER BY', 'GROUP BY', 'ALTER TABLE', 'DELETE FROM', 'UNION ALL',
    );

    protected static $reserved_newline = array(
        'LEFT OUTER JOIN', 'RIGHT OUTER JOIN', 'LEFT JOIN', 'RIGHT JOIN', 'OUTER JOIN', 'INNER JOIN', 'JOIN', 'XOR', 'OR', 'AND',
        'ROLLBACK', 'COMMIT',
    );

    protected static $reserved_newline_toplevel = array(
        'BEGIN TRY', 'BEGIN CATCH',
    );


    protected static $functions = [
        'TRY_CAST', 'TRY_CONVERT', 'TRY_PARSE', 'CAST', 'PARSE', 'CONVERT',
        'OPENDATASOURCE', 'OPENJSON', 'OPENROWSET', 'OPENQUERY', 'OPENXML',
        'AVG', 'MIN', 'CHECKSUM_AGG', 'SUM', 'COUNT', 'STDEV', 'COUNT_BIG', 'STDEVP',
        'GROUPING', 'VAR', 'GROUPING_ID', 'VARP', 'MAX', 'RANK', 'NTILE', 'DENSE_RANK',
        'ROW_NUMBER', 'SYSDATETIME', 'SYSDATETIMEOFFSET', 'SYSUTCDATETIME', 'CURRENT_TIMESTAMP', 'GETDATE', 'GETUTCDATE', 'DATENAME',
        'DATEPART', 'DAY', 'MONTH', 'YEAR', 'DATEFROMPARTS', 'DATETIME2FROMPARTS', 'DATETIMEFROMPARTS', 'DATETIMEOFFSETFROMPARTS',
        'SMALLDATETIMEFROMPARTS', 'TIMEFROMPARTS', 'DATEDIFF', 'DATEDIFF_BIG', 'DATEADD', 'EOMONTH', 'SWITCHOFFSET', 'TODATETIMEOFFSET',
        'ISDATE', 'ABS', 'DEGREES', 'RAND', 'ACOS', 'EXP', 'ROUND', 'ASIN',
        'FLOOR', 'SIGN', 'ATAN', 'LOG', 'SIN', 'ATN2', 'LOG10', 'SQRT',
        'CEILING', 'PI', 'SQUARE', 'COS', 'POWER', 'TAN', 'COT', 'RADIANS',
        'INDEX_COL', 'APP_NAME', 'INDEXKEY_PROPERTY', 'APPLOCK_MODE', 'INDEXPROPERTY', 'APPLOCK_TEST', 'NEXT', 'VALUE', 'FOR',
        'ASSEMBLYPROPERTY', 'OBJECT_DEFINITION', 'COL_LENGTH', 'OBJECT_ID', 'COL_NAME', 'OBJECT_NAME', 'COLUMNPROPERTY', 'OBJECT_SCHEMA_NAME',
        'DATABASE_PRINCIPAL_ID', 'OBJECTPROPERTY', 'DATABASEPROPERTYEX', 'OBJECTPROPERTYEX', 'DB_ID', 'ORIGINAL_DB_NAME', 'DB_NAME', 'PARSENAME',
        'FILE_ID', 'SCHEMA_ID', 'FILE_IDEX', 'SCHEMA_NAME', 'FILE_NAME', 'SCOPE_IDENTITY', 'FILEGROUP_ID', 'SERVERPROPERTY',
        'FILEGROUP_NAME', 'STATS_DATE', 'FILEGROUPPROPERTY', 'TYPE_ID', 'FILEPROPERTY', 'TYPE_NAME', 'FULLTEXTCATALOGPROPERTY', 'TYPEPROPERTY',
        'FULLTEXTSERVICEPROPERTY', 'CERTENCODED', 'PWDCOMPARE', 'CERTPRIVATEKEY', 'PWDENCRYPT', 'CURRENT_USER', 'SCHEMA_ID', 'DATABASE_PRINCIPAL_ID',
        'SCHEMA_NAME', 'SESSION_USER', 'SUSER_ID', 'SUSER_SID', 'HAS_PERMS_BY_NAME', 'SUSER_SNAME', 'IS_MEMBER', 'SYSTEM_USER',
        'IS_ROLEMEMBER', 'SUSER_NAME', 'IS_SRVROLEMEMBER', 'USER_ID', 'ORIGINAL_LOGIN', 'USER_NAME', 'PERMISSIONS', 'ASCII',
        'LTRIM', 'SOUNDEX', 'CHAR', 'NCHAR', 'SPACE', 'CHARINDEX', 'PATINDEX', 'STR',
        'CONCAT', 'QUOTENAME', 'STUFF', 'DIFFERENCE', 'REPLACE', 'SUBSTRING', 'FORMAT', 'REPLICATE',
        'UNICODE', 'LEFT', 'REVERSE', 'UPPER', 'LEN', 'RIGHT', 'LOWER', 'RTRIM',
        'ERROR_SEVERITY', 'ERROR_STATE', 'FORMATMESSAGE', 'GETANSINULL', 'GET_FILESTREAM_TRANSACTION_CONTEXT', 'HOST_ID', 'BINARY_CHECKSUM', 'HOST_NAME',
        'CHECKSUM', 'ISNULL', 'CONNECTIONPROPERTY', 'ISNUMERIC', 'CONTEXT_INFO', 'MIN_ACTIVE_ROWVERSION', 'CURRENT_REQUEST_ID', 'NEWID',
        'ERROR_LINE', 'NEWSEQUENTIALID', 'ERROR_MESSAGE', 'ROWCOUNT_BIG', 'ERROR_NUMBER', 'XACT_STATE', 'ERROR_PROCEDURE', 'PATINDEX',
        'TEXTVALID', 'TEXTPTR',
    ];


    // Punctuation that can be used as a boundary between other tokens
    protected static $boundaries = array(',', ';', ':', ')', '(', '.', '=', '<', '>', '+', '-', '*', '/', '!', '^', '%', '|', '&');

    // For HTML syntax highlighting
    // Styles applied to different token types
    public static $quote_attributes = 'style="color: blue;"';
    public static $backtick_quote_attributes = 'style="color: purple;"';
    public static $reserved_attributes = 'style="font-weight:bold;"';
    public static $boundary_attributes = '';
    public static $number_attributes = 'style="color: green;"';
    public static $word_attributes = 'style="color: #333;"';
    public static $error_attributes = 'style="background-color: red;"';
    public static $comment_attributes = 'style="color: #aaa;"';
    public static $variable_attributes = 'style="color: orange;"';
    public static $pre_attributes = 'style="color: black; background-color: white;"';

    // Boolean - whether or not the current environment is the CLI
    // This affects the type of syntax highlighting
    // If not defined, it will be determined automatically
    public static $cli;

    // For CLI syntax highlighting
    public static $cli_quote = "\x1b[34;1m";
    public static $cli_backtick_quote = "\x1b[35;1m";
    public static $cli_reserved = "\x1b[37m";
    public static $cli_boundary = "";
    public static $cli_number = "\x1b[32;1m";
    public static $cli_word = "";
    public static $cli_error = "\x1b[31;1;7m";
    public static $cli_comment = "\x1b[30;1m";
    public static $cli_functions = "\x1b[37m";
    public static $cli_variable = "\x1b[36;1m";

    // The tab character to use when formatting SQL
    public static $tab = '  ';

    // This flag tells us if queries need to be enclosed in <pre> tags
    public static $use_pre = true;

    // This flag determines if keywords should be uppercased
    public static $uppercase = false;

    // This flag tells us if SqlFormatted has been initialized
    protected static $init;

    // Regular expressions for tokenizing
    protected static $regex_boundaries;
    protected static $regex_reserved;
    protected static $regex_reserved_newline;
    protected static $regex_reserved_toplevel;
    protected static $regex_reserved_newline_toplevel;
    protected static $regex_function;

    // Cache variables
    // Only tokens shorter than this size will be cached.  Somewhere between 10 and 20 seems to work well for most cases.
    public static $max_cachekey_size = 15;
    protected static $token_cache = array();
    protected static $cache_hits = 0;
    protected static $cache_misses = 0;

    /**
     * Get stats about the token cache
     *
     * @return Array An array containing the keys 'hits', 'misses', 'entries', and 'size' in bytes
     */
    public static function getCacheStats()
    {
        return array(
            'hits' => self::$cache_hits,
            'misses' => self::$cache_misses,
            'entries' => count(self::$token_cache),
            'size' => mb_strlen(serialize(self::$token_cache)),
        );
    }

    /**
     * Stuff that only needs to be done once.  Builds regular expressions and sorts the reserved words.
     */
    protected static function init()
    {
        if (self::$init) return;

        // Sort reserved word list from longest word to shortest, 3x faster than usort
        $reservedMap = array_combine(self::$reserved, array_map('mb_strlen', self::$reserved));
        arsort($reservedMap);
        self::$reserved = array_keys($reservedMap);

        // Set up regular expressions
        self::$regex_boundaries = '(' . implode('|', array_map(array(__CLASS__, 'quote_regex'), self::$boundaries)) . ')';
        self::$regex_reserved = '(' . implode('|', array_map(array(__CLASS__, 'quote_regex'), self::$reserved)) . ')';
        self::$regex_reserved_toplevel = str_replace(' ', '\\s+', '(' . implode('|', array_map(array(__CLASS__, 'quote_regex'), self::$reserved_toplevel)) . ')');
        self::$regex_reserved_newline = str_replace(' ', '\\s+', '(' . implode('|', array_map(array(__CLASS__, 'quote_regex'), self::$reserved_newline)) . ')');
        self::$regex_reserved_newline_toplevel = str_replace(' ', '\\s+', '(' . implode('|', array_map(array(__CLASS__, 'quote_regex'), self::$reserved_newline_toplevel)) . ')');

        self::$regex_function = '(' . implode('|', array_map(array(__CLASS__, 'quote_regex'), self::$functions)) . ')';

        self::$init = true;
    }

    /**
     * Return the next token and token type in a SQL string.
     * Quoted strings, comments, reserved words, whitespace, and punctuation are all their own tokens.
     *
     * @param String $string   The SQL string
     * @param array  $previous The result of the previous getNextToken() call
     *
     * @return Array An associative array containing the type and value of the token.
     */
    protected static function getNextToken($string, $previous = null)
    {
        // Whitespace
        if (preg_match('/^ *(\r\n|[\r\n])/', $string, $matches)) {
            return array(
                self::TOKEN_VALUE => $matches[0],
                self::TOKEN_TYPE => self::TOKEN_TYPE_EMPTY_LINE,
            );
        } elseif (preg_match('/^\s+/', $string, $matches)) {
            return array(
                self::TOKEN_VALUE => $matches[0],
                self::TOKEN_TYPE => self::TOKEN_TYPE_WHITESPACE,
            );
        }

        // Comment
        if ((isset($string[1]) && ($string[0] === '-' && $string[1] === '-') || ($string[0] === '/' && $string[1] === '*'))) {
            // Comment until end of line
            if ($string[0] === '-') {
                $type = self::TOKEN_TYPE_COMMENT;
                $last = mb_strpos($string, "\n");
            } else {
            // Comment until closing comment tag (may be nested)
                $type = self::TOKEN_TYPE_BLOCK_COMMENT;
                $level = 1; $offset = 2;
                $finish = mb_strlen($string);
                do {
                    $last = mb_strpos($string, "*/", $offset);
                    if ($last === false) break;
                    $nextOpen = mb_strpos($string, "/*", $offset);
                    if ($nextOpen === false) $nextOpen = $finish;
                    if ($nextOpen < $last) {
                        $level++;
                        $offset = $nextOpen + 2;
                    } else {
                        $level--;
                        $last += 1;
                        $offset = $last;
                    }
                } while ($level && $last);
            }

            if ($last === false) {
                $last = mb_strlen($string);
            }

            return array(
                self::TOKEN_VALUE => mb_substr($string, 0, $last + 1),
                self::TOKEN_TYPE => $type,
            );
        }

        // Quoted String
        if ($string[0] === '"' || $string[0] === '\'' || $string[0] === '`' || $string[0] === '[') {
            $return = array(
                self::TOKEN_TYPE => (($string[0] === '`' || $string[0] === '[') ? self::TOKEN_TYPE_BACKTICK_QUOTE : self::TOKEN_TYPE_QUOTE),
                self::TOKEN_VALUE => self::getQuotedString($string),
            );

            return $return;
        }

        // User-defined Variable
        if (($string[0] === '@' || $string[0] === ':') && isset($string[1])) {
            $ret = array(
                self::TOKEN_VALUE => null,
                self::TOKEN_TYPE => self::TOKEN_TYPE_VARIABLE,
            );

            // If the variable name is quoted
            if ($string[1] === '"' || $string[1] === '\'' || $string[1] === '`') {
                $ret[self::TOKEN_VALUE] = $string[0] . self::getQuotedString(mb_substr($string, 1));
            } // Non-quoted variable name
            else {
                preg_match('/^(' . $string[0] . '[А-Яа-яa-zA-Z0-9\._\$]+)/u', $string, $matches);
                if ($matches) {
                    $ret[self::TOKEN_VALUE] = $matches[1];
                }
            }

            if ($ret[self::TOKEN_VALUE] !== null) return $ret;
        }

        // Number (decimal, binary, or hex)
        if (preg_match('/^([0-9]+(\.[0-9]+)?|0x[0-9a-fA-F]+|0b[01]+)($|\s|"\'`|' . self::$regex_boundaries . ')/', $string, $matches)) {
            return array(
                self::TOKEN_VALUE => $matches[1],
                self::TOKEN_TYPE => self::TOKEN_TYPE_NUMBER,
            );
        }

        // Boundary Character (punctuation and symbols)
        if (preg_match('/^(' . self::$regex_boundaries . ')/', $string, $matches)) {
            return array(
                self::TOKEN_VALUE => $matches[1],
                self::TOKEN_TYPE => self::TOKEN_TYPE_BOUNDARY,
            );
        }

        // A reserved word cannot be preceded by a '.'
        // this makes it so in "mytable.from", "from" is not considered a reserved word
        if (!$previous || !isset($previous[self::TOKEN_VALUE]) || $previous[self::TOKEN_VALUE] !== '.') {
            $upper = strtoupper($string);
            // Top Level Reserved Word
            if (preg_match('/^(' . self::$regex_reserved_toplevel . ')($|\s|' . self::$regex_boundaries . ')/', $upper, $matches)) {
                return array(
                    self::TOKEN_TYPE => self::TOKEN_TYPE_RESERVED_TOPLEVEL,
                    self::TOKEN_VALUE => mb_substr($string, 0, mb_strlen($matches[1])),
                );
            }
            // Newline Reserved Word
            if (preg_match('/^(' . self::$regex_reserved_newline . ')($|\s|' . self::$regex_boundaries . ')/', $upper, $matches)) {
                return array(
                    self::TOKEN_TYPE => self::TOKEN_TYPE_RESERVED_NEWLINE,
                    self::TOKEN_VALUE => mb_substr($string, 0, mb_strlen($matches[1])),
                );
            }
            // Newline & Top Level Reserved Word
            if (preg_match('/^(' . self::$regex_reserved_newline_toplevel . ')($|\s|' . self::$regex_boundaries . ')/', $upper, $matches)) {
                return array(
                    self::TOKEN_TYPE => self::TOKEN_TYPE_RESERVED_NEWLINE_TOPLEVEL,
                    self::TOKEN_VALUE => mb_substr($string, 0, mb_strlen($matches[1])),
                );
            }
            // Other Reserved Word
            if (preg_match('/^(' . self::$regex_reserved . ')($|\s|' . self::$regex_boundaries . ')/', $upper, $matches)) {
                return array(
                    self::TOKEN_TYPE => self::TOKEN_TYPE_RESERVED,
                    self::TOKEN_VALUE => mb_substr($string, 0, mb_strlen($matches[1])),
                );
            }
        }

        // A function must be suceeded by '('
        // this makes it so "count(" is considered a function, but "count" alone is not
        $upper = strtoupper($string);
        // function
        if (preg_match('/^(' . self::$regex_function . '[(]|\s|[)])/', $upper, $matches)) {
            return array(
                self::TOKEN_TYPE => self::TOKEN_TYPE_RESERVED,
                self::TOKEN_VALUE => mb_substr($string, 0, mb_strlen($matches[1]) - 1),
            );
        }

        // Non reserved word
        preg_match('/^(.*?)($|\s|["\'`]|' . self::$regex_boundaries . ')/', $string, $matches);

        return array(
            self::TOKEN_VALUE => $matches[1],
            self::TOKEN_TYPE => self::TOKEN_TYPE_WORD,
        );
    }

    protected static function getQuotedString($string)
    {
        $ret = null;

        // This checks for the following patterns:
        // 1. backtick quoted string using `` to escape
        // 2. square bracket quoted string (SQL Server) using ]] to escape
        // 3. double quoted string using "" or \" to escape
        // 4. single quoted string using '' or \' to escape
        if (preg_match('/^(((`[^`]*($|`))+)|((\[[^\]]*($|\]))(\][^\]]*($|\]))*)|(("[^"\\\\]*(?:\\\\.[^"\\\\]*)*("|$))+)|((\'[^\'\\\\]*(?:\\\\.[^\'\\\\]*)*(\'|$))+))/s',
            $string, $matches)) {
            $ret = $matches[1];
        }

        return $ret;
    }

    /**
     * Takes a SQL string and breaks it into tokens.
     * Each token is an associative array with type and value.
     *
     * @param String $string The SQL string
     *
     * @return Array An array of tokens.
     */
    protected static function tokenize($string)
    {
        self::init();

        $tokens = array();

        // Used for debugging if there is an error while tokenizing the string
        $original_length = mb_strlen($string);

        // Used to make sure the string keeps shrinking on each iteration
        $old_string_len = mb_strlen($string) + 1;

        $token = null;

        $current_length = mb_strlen($string);

        // Keep processing the string until it is empty
        while ($current_length) {
            // If the string stopped shrinking, there was a problem
            if ($old_string_len <= $current_length) {
                $tokens[] = array(
                    self::TOKEN_VALUE => $string,
                    self::TOKEN_TYPE => self::TOKEN_TYPE_ERROR,
                );

                return $tokens;
            }
            $old_string_len = $current_length;

            // Determine if we can use caching
            if ($current_length >= self::$max_cachekey_size) {
                $cacheKey = mb_substr($string, 0, self::$max_cachekey_size);
            } else {
                $cacheKey = false;
            }

            // See if the token is already cached
            if ($cacheKey && isset(self::$token_cache[$cacheKey])) {
                // Retrieve from cache
                $token = self::$token_cache[$cacheKey];
                $token_length = mb_strlen($token[self::TOKEN_VALUE]);
                self::$cache_hits++;
            } else {
                // Get the next token and the token type
                $token = self::getNextToken($string, $token);
                $token_length = mb_strlen($token[self::TOKEN_VALUE]);
                self::$cache_misses++;

                // If the token is shorter than the max length, store it in cache
                if ($cacheKey && $token_length < self::$max_cachekey_size) {
                    self::$token_cache[$cacheKey] = $token;
                }
            }

            $tokens[] = $token;

            // Advance the string
            $string = mb_substr($string, $token_length);

            $current_length -= $token_length;
        }

        return $tokens;
    }

    /**
     * Format the whitespace in a SQL string to make it easier to read.
     *
     * @param String  $string    The SQL string
     * @param boolean $highlight If true, syntax highlighting will also be performed
     *
     * @return String The SQL string with HTML styles and formatting wrapped in a <pre> tag
     */
    public static function format($string, $highlight = true)
    {
        // This variable will be populated with formatted html
        $return = '';

        // Use an actual tab while formatting and then switch out with self::$tab at the end
        $tab = "\t";

        $indent_level = 0;
        $newline = false;
        $blankline = false;
        $inline_parentheses = false;
        $increase_indent_type = null;
        $indent_types = array();
        $added_newline = false;
        $inline_count = 0;
        $inline_indented = false;

        // Tokenize String
        $original_tokens = self::tokenize($string);

        // Remove existing whitespaces and singleton newlines
        $tokens = array();
        $was_empty = false;
        foreach ($original_tokens as $i => $token) {
            if ($token[self::TOKEN_TYPE] !== self::TOKEN_TYPE_WHITESPACE) {
                $token['i'] = $i;
                if ($token[self::TOKEN_TYPE] === self::TOKEN_TYPE_EMPTY_LINE) {
                    if ($was_empty) {
                        $token[self::TOKEN_VALUE] = "\n";
                        $was_empty = false;
                    } else {
                        $was_empty = true;
                        continue;
                    }
                } else {
                    $token[self::TOKEN_VALUE] = trim($token[self::TOKEN_VALUE]);
                    $was_empty = false;
                }
                $tokens[] = $token;
            }
        }

        // Format token by token

        $LAST_VALUE = $TOKEN_VALUE = null;
        $LAST_TYPE = $TOKEN_TYPE = null;

        foreach ($tokens as $i => $token) {

            if ( ! in_array($TOKEN_TYPE, [self::TOKEN_TYPE_WHITESPACE, self::TOKEN_TYPE_EMPTY_LINE])) {
                $LAST_VALUE = $TOKEN_VALUE;
                $LAST_TYPE = $TOKEN_TYPE;
            }

            $TOKEN_VALUE = strtoupper($token[self::TOKEN_VALUE]);
            $TOKEN_TYPE = $token[self::TOKEN_TYPE];

            // For lookahead cases
            $NEXT_VALUE = null;
            $NEXT_TYPE = null;
            for ($j = $i + 1; $j < count($tokens); $j++) {
                $next = $tokens[$j];
                if ( ! in_array($next[self::TOKEN_TYPE], [self::TOKEN_TYPE_WHITESPACE, self::TOKEN_TYPE_EMPTY_LINE])) {
                    $NEXT_VALUE = strtoupper($next[self::TOKEN_VALUE]);
                    $NEXT_TYPE = $next[self::TOKEN_TYPE];
                    break;
                }
            }

            // Get highlighted token if doing syntax highlighting
            if ($highlight) {
                $highlighted = self::highlightToken($token);
            } else { // If returning raw text
                $highlighted = $token[self::TOKEN_VALUE];
            }

            if ($TOKEN_TYPE === self::TOKEN_TYPE_RESERVED_NEWLINE_TOPLEVEL) {

                if (count($indent_types) && $indent_types[0] === 'special') {
                    array_shift($indent_types);
                    $indent_level--;
                }

                $newline = true;

                // If the token may have extra whitespace
                if (mb_strpos($TOKEN_VALUE, ' ') !== false || mb_strpos($TOKEN_VALUE, "\n") !== false
                    || mb_strpos($TOKEN_VALUE, "\t") !== false
                ) {
                    $highlighted = preg_replace('/\s+/', ' ', $highlighted);
                }
            }

            // If we need a new line before the token
            if ($newline) {
                if ($increase_indent_type) {
                    $indent_level++;
                    array_unshift($indent_types, $increase_indent_type);
                }
                $increase_indent_type = null;

                if ($blankline) {
                    $return .= "\n";
                    $blankline = false;
                }
                $return .= "\n" . str_repeat($tab, $indent_level);
                $newline = false;
                $added_newline = true;
            } else {
                $added_newline = false;
            }

            // Display comments directly where they appear in the source
            if (in_array($TOKEN_TYPE, [self::TOKEN_TYPE_COMMENT, self::TOKEN_TYPE_BLOCK_COMMENT])) {

                if ($TOKEN_TYPE === self::TOKEN_TYPE_BLOCK_COMMENT) {
                    $indent = str_repeat($tab, $indent_level);
                    $return .= "\n" . $indent;
                    $highlighted = str_replace("\n", "\n" . $indent, $highlighted);
                }
                $return .= $highlighted;
                $newline = true;
                continue;
            }

            if ($inline_parentheses) {

                // End of inline parentheses
                if ($TOKEN_VALUE === ')') {
                    $return = rtrim($return, ' ');

                    if ($inline_indented) {
                        array_shift($indent_types);
                        $indent_level--;
                        $return .= "\n" . str_repeat($tab, $indent_level);
                    }

                    $inline_parentheses = false;

                    $return .= $highlighted . ' ';
                    continue;
                }

                if ($TOKEN_VALUE === ',') {
                    if ($inline_count >= 80) {
                        $inline_count = 0;
                        $newline = true;
                    }
                }

                $inline_count += mb_strlen($TOKEN_VALUE);
            }

            // Keywords BEGIN and CASE increase the text indent level and start a new line
            $startTextBlock = $TOKEN_VALUE === 'CASE'
                || $TOKEN_VALUE === 'BEGIN' && ! in_array($NEXT_VALUE, ['TRANSACTION', 'TRANS'])
                || $LAST_VALUE === 'BEGIN' && in_array($TOKEN_VALUE, ['TRY', 'CATCH'])
                || in_array($TOKEN_VALUE, ['BEGIN TRY', 'BEGIN CATCH'])
                ;
            if ($startTextBlock) {

                $increase_indent_type = 'text';
                $newline = true;

            } // Keyword END decreases the text indent level
            elseif (strtoupper($TOKEN_VALUE) === 'END') {

                 $increase_indent_type = null;
                $return = rtrim($return, ' ');
                $indent_level--;

                // Reset indent level
                while ($j = array_shift($indent_types)) {
                    if ($j === 'special') {
                        $indent_level--;
                    } else { // TODO: Check if it is block indent (must be an error)
                        break;
                    }
                }

                if ($indent_level < 0) {
                    // This is an error
                    $indent_level = 0;

                    if ($highlight) {
                        $return .= "\n" . self::highlightError($TOKEN_VALUE);
                        continue;
                    }
                }

                if ($added_newline) {
                    $return = rtrim($return, $tab) . str_repeat($tab, $indent_level);
                } else {
                    $return .= "\n" . str_repeat($tab, $indent_level);
                }

            } // Opening parentheses increase the block indent level and start a new line
            elseif ($TOKEN_VALUE === '(') {
                // First check if this should be an inline parentheses block
                // Examples are "NOW()", "COUNT(*)", "int(10)", key(`somecolumn`), DECIMAL(7,2)
                $length = 0;
                for ($j = 1; $j <= 250; $j++) {
                    // Reached end of string
                    if (!isset($tokens[$i + $j])) break;

                    $next = $tokens[$i + $j];

                    // Reached closing parentheses, able to inline it
                    if ($next[self::TOKEN_VALUE] === ')') {
                        $inline_parentheses = true;
                        $inline_count = 0;
                        $inline_indented = false;
                        break;
                    }

                    // Reached an invalid token for inline parentheses
                    if ($next[self::TOKEN_VALUE] === ';' || $next[self::TOKEN_VALUE] === '(') {
                        break;
                    }

                    // Reached an invalid token type for inline parentheses
                    if ($next[self::TOKEN_TYPE] === self::TOKEN_TYPE_RESERVED_TOPLEVEL
                        || $next[self::TOKEN_TYPE] === self::TOKEN_TYPE_RESERVED_NEWLINE
                        || $next[self::TOKEN_TYPE] === self::TOKEN_TYPE_RESERVED_NEWLINE_TOPLEVEL
                        || $next[self::TOKEN_TYPE] === self::TOKEN_TYPE_COMMENT
                        || $next[self::TOKEN_TYPE] === self::TOKEN_TYPE_BLOCK_COMMENT
                        || $next[self::TOKEN_TYPE] === self::TOKEN_TYPE_EMPTY_LINE
                    ) {
                        break;
                    }

                    $length += mb_strlen($next[self::TOKEN_VALUE]);
                }

                if ($inline_parentheses && $length > 80) {
                    $increase_indent_type = 'block';
                    $inline_indented = true;
                    $newline = true;
                }

                // Take out the preceding space unless there was whitespace there in the original query
                if (isset($original_tokens[$token['i'] - 1]) && $original_tokens[$token['i'] - 1][self::TOKEN_TYPE] !== self::TOKEN_TYPE_WHITESPACE) {
                    $return = rtrim($return, ' ');
                }

                if (!$inline_parentheses) {
                    $increase_indent_type = 'block';
                    // Add a newline after the parentheses
                    $newline = true;
                }

            } // Closing parentheses decrease the block indent level
            elseif ($TOKEN_VALUE === ')') {
                // Remove whitespace before the closing parentheses
                $return = rtrim($return, ' ');

                $increase_indent_type = null;
                $indent_level--;

                // Reset indent level
                while ($j = array_shift($indent_types)) {
                    if ($j === 'special') {
                        $indent_level--;
                    } else {
                        break;
                    }
                }

                if ($indent_level < 0) {
                    // This is an error
                    $indent_level = 0;

                    if ($highlight) {
                        $return .= "\n" . self::highlightError($TOKEN_VALUE);
                        continue;
                    }
                }

                // Add a newline before the closing parentheses (if not already added)
                if (!$added_newline) {
                    $return .= "\n" . str_repeat($tab, $indent_level);
                }

            }
            elseif (in_array(strtoupper($TOKEN_VALUE), ['TRY', 'CATCH'])) {

                $increase_indent_type = null;
                $newline = true;

            } // Top level reserved words start a new line and increase the special indent level
            elseif ($TOKEN_TYPE === self::TOKEN_TYPE_RESERVED_TOPLEVEL || $TOKEN_TYPE === self::TOKEN_TYPE_RESERVED_NEWLINE_TOPLEVEL) {
                $increase_indent_type = 'special';

                // If the last indent type was 'special', decrease the special indent for this round
                reset($indent_types);
                if (current($indent_types) === 'special') {
                    $indent_level--;
                    array_shift($indent_types);
                }

                // Add a newline after the top level reserved word
//                $newline = true;
                // Add a newline before the top level reserved word (if not already added)
                if (!$added_newline) {
                    $return .= "\n" . str_repeat($tab, $indent_level);
                } // If we already added a newline, redo the indentation since it may be different now
                else {
                    $return = rtrim($return, $tab) . str_repeat($tab, $indent_level);
                }

                // If the token may have extra whitespace
                if (mb_strpos($TOKEN_VALUE, ' ') !== false || mb_strpos($TOKEN_VALUE, "\n") !== false
                    || mb_strpos($TOKEN_VALUE, "\t") !== false
                ) {
                    $highlighted = preg_replace('/\s+/', ' ', $highlighted);
                }
            } // Commas MAY start a new line (unless within inline parentheses)
            elseif ($TOKEN_VALUE === ',' && !$inline_parentheses) {
                $newline = true;
            } // Newline reserved words start a new line
            elseif ($TOKEN_TYPE === self::TOKEN_TYPE_RESERVED_NEWLINE || $TOKEN_TYPE === self::TOKEN_TYPE_RESERVED_NEWLINE_TOPLEVEL) {
                // Add a newline before the reserved word (if not already added)
                if (!$added_newline) {
                    $return .= "\n" . str_repeat($tab, $indent_level);
                }

                // If the token may have extra whitespace
                if (mb_strpos($TOKEN_VALUE, ' ') !== false || mb_strpos($TOKEN_VALUE, "\n") !== false
                    || mb_strpos($TOKEN_VALUE, "\t") !== false
                ) {
                    $highlighted = preg_replace('/\s+/', ' ', $highlighted);
                }
            } // Multiple boundary characters in a row should not have spaces between them (not including parentheses)
            elseif ($TOKEN_TYPE === self::TOKEN_TYPE_BOUNDARY) {
                if (isset($tokens[$i - 1]) && $tokens[$i - 1][self::TOKEN_TYPE] === self::TOKEN_TYPE_BOUNDARY) {
                    if (isset($original_tokens[$token['i'] - 1]) && $original_tokens[$token['i'] - 1][self::TOKEN_TYPE] !== self::TOKEN_TYPE_WHITESPACE) {
                        $return = rtrim($return, ' ');
                    }
                }
            }

            // Uppercase reserved words
            if (self::$uppercase
                && in_array($TOKEN_TYPE, array(self::TOKEN_TYPE_RESERVED, self::TOKEN_TYPE_RESERVED_NEWLINE, self::TOKEN_TYPE_RESERVED_TOPLEVEL, self::TOKEN_TYPE_RESERVED_NEWLINE_TOPLEVEL))
            ) {
                $highlighted = strtoupper($highlighted);
            }


            // If the token shouldn't have a space before it
            if ($TOKEN_VALUE === '.' || $TOKEN_VALUE === ',' || $TOKEN_VALUE === ';') {
                $return = rtrim($return, ' ');
            }

            if ($TOKEN_TYPE !== self::TOKEN_TYPE_EMPTY_LINE)
            {
                $return .= $highlighted . ' ';
            }

            // If the token shouldn't have a space after it
            if ($TOKEN_TYPE === self::TOKEN_TYPE_EMPTY_LINE || $TOKEN_VALUE === '(' || $TOKEN_VALUE === '.') {
                $return = rtrim($return, ' ');
            }

            // If this is the "-" of a negative number, it shouldn't have a space after it
            if ($TOKEN_VALUE === '-' && isset($tokens[$i + 1]) && $tokens[$i + 1][self::TOKEN_TYPE] === self::TOKEN_TYPE_NUMBER
                && isset($tokens[$i - 1])
            ) {
                $prev = $tokens[$i - 1][self::TOKEN_TYPE];
                if ($prev !== self::TOKEN_TYPE_QUOTE && $prev !== self::TOKEN_TYPE_BACKTICK_QUOTE && $prev !== self::TOKEN_TYPE_WORD
                    && $prev !== self::TOKEN_TYPE_NUMBER
                ) {
                    $return = rtrim($return, ' ');
                }
            }
            if ($TOKEN_TYPE === self::TOKEN_TYPE_EMPTY_LINE) {
                $increase_indent_type = null;
                $newline = true;
                $blankline = true;
            }
        }

        // If there are unmatched parentheses
        if ($highlight && array_search('block', $indent_types) !== false) {
            $return .= "\n" . self::highlightError("WARNING: unclosed parentheses or section");
        }

        // Replace tab characters with the configuration tab character
        $return = trim(str_replace("\t", self::$tab, $return));

        if ($highlight) {
            $return = self::output($return);
        }

        return $return;
    }

    /**
     * Add syntax highlighting to a SQL string
     *
     * @param String $string The SQL string
     *
     * @return String The SQL string with HTML styles applied
     */
    public static function highlight($string)
    {
        $tokens = self::tokenize($string);

        $return = '';

        foreach ($tokens as $token) {
            $return .= self::highlightToken($token);
        }

        return self::output($return);
    }

    /**
     * Split a SQL string into multiple queries.
     * Uses ";" as a query delimiter.
     *
     * @param String $string The SQL string
     *
     * @return Array An array of individual query strings without trailing semicolons
     */
    public static function splitQuery($string)
    {
        $queries = array();
        $current_query = '';
        $empty = true;

        $tokens = self::tokenize($string);

        foreach ($tokens as $token) {
            // If this is a query separator
            if ($token[self::TOKEN_VALUE] === ';') {
                if (!$empty) {
                    $queries[] = $current_query . ';';
                }
                $current_query = '';
                $empty = true;
                continue;
            }

            // If this is a non-empty character
            if ($token[self::TOKEN_TYPE] !== self::TOKEN_TYPE_WHITESPACE && $token[self::TOKEN_TYPE] !== self::TOKEN_TYPE_COMMENT
                && $token[self::TOKEN_TYPE] !== self::TOKEN_TYPE_BLOCK_COMMENT
            ) {
                $empty = false;
            }

            $current_query .= $token[self::TOKEN_VALUE];
        }

        if (!$empty) {
            $queries[] = trim($current_query);
        }

        return $queries;
    }

    /**
     * Remove all comments from a SQL string
     *
     * @param String $string The SQL string
     *
     * @return String The SQL string without comments
     */
    public static function removeComments($string)
    {
        $result = '';

        $tokens = self::tokenize($string);

        foreach ($tokens as $token) {
            // Skip comment tokens
            if ($token[self::TOKEN_TYPE] === self::TOKEN_TYPE_COMMENT || $token[self::TOKEN_TYPE] === self::TOKEN_TYPE_BLOCK_COMMENT) {
                continue;
            }

            $result .= $token[self::TOKEN_VALUE];
        }
        $result = self::format($result, false);

        return $result;
    }

    /**
     * Compress a query by collapsing white space and removing comments
     *
     * @param String $string The SQL string
     *
     * @return String The SQL string without comments
     */
    public static function compress($string)
    {
        $result = '';

        $tokens = self::tokenize($string);

        $whitespace = true;
        foreach ($tokens as $token) {
            // Skip comment tokens
            if ($token[self::TOKEN_TYPE] === self::TOKEN_TYPE_COMMENT || $token[self::TOKEN_TYPE] === self::TOKEN_TYPE_BLOCK_COMMENT) {
                continue;
            } // Remove extra whitespace in reserved words (e.g "OUTER     JOIN" becomes "OUTER JOIN")
            elseif ($token[self::TOKEN_TYPE] === self::TOKEN_TYPE_RESERVED || $token[self::TOKEN_TYPE] === self::TOKEN_TYPE_RESERVED_NEWLINE
                || $token[self::TOKEN_TYPE] === self::TOKEN_TYPE_RESERVED_TOPLEVEL || $token[self::TOKEN_TYPE] === self::TOKEN_TYPE_RESERVED_NEWLINE_TOPLEVEL
            ) {
                $token[self::TOKEN_VALUE] = preg_replace('/\s+/', ' ', $token[self::TOKEN_VALUE]);
            }

            if ($token[self::TOKEN_TYPE] === self::TOKEN_TYPE_WHITESPACE) {
                // If the last token was whitespace, don't add another one
                if ($whitespace) {
                    continue;
                } else {
                    $whitespace = true;
                    // Convert all whitespace to a single space
                    $token[self::TOKEN_VALUE] = ' ';
                }
            } else {
                $whitespace = false;
            }

            $result .= $token[self::TOKEN_VALUE];
        }

        return rtrim($result);
    }

    /**
     * Highlights a token depending on its type.
     *
     * @param Array $token An associative array containing type and value.
     *
     * @return String HTML code of the highlighted token.
     */
    protected static function highlightToken($token)
    {
        $type = $token[self::TOKEN_TYPE];

        if (self::is_cli()) {
            $token = $token[self::TOKEN_VALUE];
        } else {
            if (defined('ENT_IGNORE')) {
                $token = htmlentities($token[self::TOKEN_VALUE], ENT_COMPAT | ENT_IGNORE, 'UTF-8');
            } else {
                $token = htmlentities($token[self::TOKEN_VALUE], ENT_COMPAT, 'UTF-8');
            }
        }

        if ($type === self::TOKEN_TYPE_BOUNDARY) {
            return self::highlightBoundary($token);
        } elseif ($type === self::TOKEN_TYPE_WORD) {
            return self::highlightWord($token);
        } elseif ($type === self::TOKEN_TYPE_BACKTICK_QUOTE) {
            return self::highlightBacktickQuote($token);
        } elseif ($type === self::TOKEN_TYPE_QUOTE) {
            return self::highlightQuote($token);
        } elseif ($type === self::TOKEN_TYPE_RESERVED) {
            return self::highlightReservedWord($token);
        } elseif ($type === self::TOKEN_TYPE_RESERVED_TOPLEVEL) {
            return self::highlightReservedWord($token);
        } elseif ($type === self::TOKEN_TYPE_RESERVED_NEWLINE_TOPLEVEL) {
            return self::highlightReservedWord($token);
        } elseif ($type === self::TOKEN_TYPE_RESERVED_NEWLINE   ) {
            return self::highlightReservedWord($token);
        } elseif ($type === self::TOKEN_TYPE_NUMBER) {
            return self::highlightNumber($token);
        } elseif ($type === self::TOKEN_TYPE_VARIABLE) {
            return self::highlightVariable($token);
        } elseif ($type === self::TOKEN_TYPE_COMMENT || $type === self::TOKEN_TYPE_BLOCK_COMMENT) {
            return self::highlightComment($token);
        }

        return $token;
    }

    /**
     * Highlights a quoted string
     *
     * @param String $value The token's value
     *
     * @return String HTML code of the highlighted token.
     */
    protected static function highlightQuote($value)
    {
        if (self::is_cli()) {
            return self::$cli_quote . $value . "\x1b[0m";
        } else {
            return '<span ' . self::$quote_attributes . '>' . $value . '</span>';
        }
    }

    /**
     * Highlights a backtick quoted string
     *
     * @param String $value The token's value
     *
     * @return String HTML code of the highlighted token.
     */
    protected static function highlightBacktickQuote($value)
    {
        if (self::is_cli()) {
            return self::$cli_backtick_quote . $value . "\x1b[0m";
        } else {
            return '<span ' . self::$backtick_quote_attributes . '>' . $value . '</span>';
        }
    }

    /**
     * Highlights a reserved word
     *
     * @param String $value The token's value
     *
     * @return String HTML code of the highlighted token.
     */
    protected static function highlightReservedWord($value)
    {
        if (self::is_cli()) {
            return self::$cli_reserved . $value . "\x1b[0m";
        } else {
            return '<span ' . self::$reserved_attributes . '>' . $value . '</span>';
        }
    }

    /**
     * Highlights a boundary token
     *
     * @param String $value The token's value
     *
     * @return String HTML code of the highlighted token.
     */
    protected static function highlightBoundary($value)
    {
        if ($value === '(' || $value === ')') return $value;

        if (self::is_cli()) {
            return self::$cli_boundary . $value . "\x1b[0m";
        } else {
            return '<span ' . self::$boundary_attributes . '>' . $value . '</span>';
        }
    }

    /**
     * Highlights a number
     *
     * @param String $value The token's value
     *
     * @return String HTML code of the highlighted token.
     */
    protected static function highlightNumber($value)
    {
        if (self::is_cli()) {
            return self::$cli_number . $value . "\x1b[0m";
        } else {
            return '<span ' . self::$number_attributes . '>' . $value . '</span>';
        }
    }

    /**
     * Highlights an error
     *
     * @param String $value The token's value
     *
     * @return String HTML code of the highlighted token.
     */
    protected static function highlightError($value)
    {
        if (self::is_cli()) {
            return self::$cli_error . $value . "\x1b[0m";
        } else {
            return '<span ' . self::$error_attributes . '>' . $value . '</span>';
        }
    }

    /**
     * Highlights a comment
     *
     * @param String $value The token's value
     *
     * @return String HTML code of the highlighted token.
     */
    protected static function highlightComment($value)
    {
        if (self::is_cli()) {
            return self::$cli_comment . $value . "\x1b[0m";
        } else {
            return '<span ' . self::$comment_attributes . '>' . $value . '</span>';
        }
    }

    /**
     * Highlights a word token
     *
     * @param String $value The token's value
     *
     * @return String HTML code of the highlighted token.
     */
    protected static function highlightWord($value)
    {
        if (self::is_cli()) {
            return self::$cli_word . $value . "\x1b[0m";
        } else {
            return '<span ' . self::$word_attributes . '>' . $value . '</span>';
        }
    }

    /**
     * Highlights a variable token
     *
     * @param String $value The token's value
     *
     * @return String HTML code of the highlighted token.
     */
    protected static function highlightVariable($value)
    {
        if (self::is_cli()) {
            return self::$cli_variable . $value . "\x1b[0m";
        } else {
            return '<span ' . self::$variable_attributes . '>' . $value . '</span>';
        }
    }

    /**
     * Helper function for building regular expressions for reserved words and boundary characters
     *
     * @param String $a The string to be quoted
     *
     * @return String The quoted string
     */
    private static function quote_regex($a)
    {
        return preg_quote($a, '/');
    }

    /**
     * Helper function for building string output
     *
     * @param String $string The string to be quoted
     *
     * @return String The quoted string
     */
    private static function output($string)
    {
        if (self::is_cli()) {
            return $string . "\n";
        } else {
            $string = trim($string);
            if (!self::$use_pre) {
                return $string;
            }

            return '<pre ' . self::$pre_attributes . '>' . $string . '</pre>';
        }
    }

    private static function is_cli()
    {
        if (isset(self::$cli)) {
            return self::$cli;
        } else return php_sapi_name() === 'cli';
    }

}
