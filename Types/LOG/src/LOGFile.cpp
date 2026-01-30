#include "log.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace GView::Type::LOG
{

using namespace GView::View::LexicalViewer;

// Character classification for lexical analysis
namespace CharType
{
    constexpr uint8 Word          = 0;
    constexpr uint8 Space         = 1;
    constexpr uint8 NewLine       = 2;
    constexpr uint8 Digit         = 3;
    constexpr uint8 Bracket       = 4;
    constexpr uint8 Quote         = 5;
    constexpr uint8 Separator     = 6;
    constexpr uint8 Punctuation   = 7;

    inline uint8 GetCharType(char16 c)
    {
        if (c == ' ' || c == '\t')
            return Space;
        if (c == '\n' || c == '\r')
            return NewLine;
        if (c >= '0' && c <= '9')
            return Digit;
        if (c == '[' || c == ']' || c == '(' || c == ')' || c == '{' || c == '}' || c == '<' || c == '>')
            return Bracket;
        if (c == '"' || c == '\'')
            return Quote;
        if (c == ':' || c == ',' || c == ';' || c == '|' || c == '-' || c == '/')
            return Separator;
        if (c == '.' || c == '!' || c == '?' || c == '=' || c == '+' || c == '*' || c == '#' || c == '@')
            return Punctuation;
        return Word;
    }
} // namespace CharType

LOGFile::LOGFile() : detectedFormat(LogFormat::Unknown), panelsMask(0)
{
    panelsMask |= (1ULL << static_cast<uint8>(Panels::IDs::Information));
    panelsMask |= (1ULL << static_cast<uint8>(Panels::IDs::Entries));
    panelsMask |= (1ULL << static_cast<uint8>(Panels::IDs::Errors));
}

bool LOGFile::HasPanel(Panels::IDs id)
{
    return (panelsMask & (1ULL << static_cast<uint8>(id))) != 0;
}

bool LOGFile::Update()
{
    CHECK(obj.IsValid(), false, "Invalid object reference");
    
    auto size = obj->GetData().GetSize();
    
    if (size == 0)
        return false;

    // Read the entire content (up to a reasonable limit for parsing)
    constexpr uint64 MAX_PARSE_SIZE = 50 * 1024 * 1024; // 50 MB limit for full parsing
    uint64 parseSize = std::min(size, MAX_PARSE_SIZE);
    
    auto buffer = obj->GetData().Get(0, static_cast<uint32>(parseSize), false);
    std::string_view content(reinterpret_cast<const char*>(buffer.GetData()), buffer.GetLength());
    
    // Detect log format
    detectedFormat = DetectLogFormat(content);
    
    // Parse based on detected format
    entries.clear();
    
    switch (detectedFormat)
    {
    case LogFormat::Apache:
        ParseApacheLog(content);
        break;
    case LogFormat::Syslog:
        ParseSyslog(content);
        break;
    case LogFormat::Log4j:
        ParseLog4j(content);
        break;
    default:
        ParseGenericLog(content);
        break;
    }
    
    // Update statistics after parsing
    UpdateStatistics();
    
    return true;
}

LogFormat LOGFile::DetectLogFormat(const std::string_view& content)
{
    // Sample the first few lines
    size_t sampleEnd = std::min(content.size(), static_cast<size_t>(4096));
    std::string_view sample = content.substr(0, sampleEnd);
    
    // Check for Apache/Nginx access log format
    // Pattern: IP - - [timestamp] "METHOD URL HTTP/x.x" status size
    if (sample.find(" - - [") != std::string_view::npos && 
        (sample.find("\" 200 ") != std::string_view::npos ||
         sample.find("\" 404 ") != std::string_view::npos ||
         sample.find("\" 500 ") != std::string_view::npos ||
         sample.find("GET ") != std::string_view::npos ||
         sample.find("POST ") != std::string_view::npos))
    {
        return LogFormat::Apache;
    }
    
    // Check for Apache error log format
    // Pattern: [day mon dd hh:mm:ss.microsec yyyy] [level] [pid tid] ...
    if (sample.find("[error]") != std::string_view::npos ||
        sample.find("[warn]") != std::string_view::npos ||
        sample.find("[notice]") != std::string_view::npos ||
        sample.find("[crit]") != std::string_view::npos)
    {
        return LogFormat::ApacheError;
    }
    
    // Check for Syslog format
    // Pattern: Mon DD HH:MM:SS hostname process[pid]: message
    bool hasSyslogMonth = (sample.find("Jan ") != std::string_view::npos ||
                          sample.find("Feb ") != std::string_view::npos ||
                          sample.find("Mar ") != std::string_view::npos ||
                          sample.find("Apr ") != std::string_view::npos ||
                          sample.find("May ") != std::string_view::npos ||
                          sample.find("Jun ") != std::string_view::npos ||
                          sample.find("Jul ") != std::string_view::npos ||
                          sample.find("Aug ") != std::string_view::npos ||
                          sample.find("Sep ") != std::string_view::npos ||
                          sample.find("Oct ") != std::string_view::npos ||
                          sample.find("Nov ") != std::string_view::npos ||
                          sample.find("Dec ") != std::string_view::npos);
    
    if (hasSyslogMonth && sample.find("]: ") != std::string_view::npos)
    {
        return LogFormat::Syslog;
    }
    
    // Check for Log4j/Log4net format
    // Pattern: timestamp LEVEL [logger] - message
    // Or: timestamp [LEVEL] logger - message
    if ((sample.find(" INFO ") != std::string_view::npos ||
         sample.find(" DEBUG ") != std::string_view::npos ||
         sample.find(" ERROR ") != std::string_view::npos ||
         sample.find(" WARN ") != std::string_view::npos ||
         sample.find("[INFO]") != std::string_view::npos ||
         sample.find("[DEBUG]") != std::string_view::npos ||
         sample.find("[ERROR]") != std::string_view::npos ||
         sample.find("[WARN]") != std::string_view::npos) &&
        (sample.find(" - ") != std::string_view::npos))
    {
        return LogFormat::Log4j;
    }
    
    // Check for JSON logs
    if (sample.find("{\"") != std::string_view::npos &&
        (sample.find("\"timestamp\"") != std::string_view::npos ||
         sample.find("\"level\"") != std::string_view::npos ||
         sample.find("\"message\"") != std::string_view::npos))
    {
        return LogFormat::JSON;
    }
    
    // Default to custom/generic
    return LogFormat::Custom;
}

LogLevel LOGFile::ParseLogLevel(const std::string_view& levelStr)
{
    // Convert to uppercase for comparison
    std::string upper;
    upper.reserve(levelStr.size());
    for (char c : levelStr)
    {
        upper += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    
    if (upper == "TRACE" || upper == "TRC")
        return LogLevel::Trace;
    if (upper == "DEBUG" || upper == "DBG" || upper == "DEBU")
        return LogLevel::Debug;
    if (upper == "INFO" || upper == "INF" || upper == "INFORMATION" || upper == "NOTICE")
        return LogLevel::Info;
    if (upper == "WARN" || upper == "WARNING" || upper == "WRN")
        return LogLevel::Warning;
    if (upper == "ERROR" || upper == "ERR" || upper == "ERRO")
        return LogLevel::Error;
    if (upper == "FATAL" || upper == "FTL" || upper == "CRIT" || upper == "CRITICAL")
        return LogLevel::Fatal;
    
    return LogLevel::Unknown;
}

bool LOGFile::ParseApacheLog(const std::string_view& content)
{
    // Apache Combined Log Format:
    // IP - - [timestamp] "method url protocol" status size "referer" "user-agent"
    
    uint64 pos = 0;
    uint32 lineNum = 1;
    
    while (pos < content.size())
    {
        // Find end of line
        uint64 lineStart = pos;
        uint64 lineEnd = content.find('\n', pos);
        if (lineEnd == std::string_view::npos)
            lineEnd = content.size();
        
        std::string_view line = content.substr(pos, lineEnd - pos);
        if (!line.empty() && line.back() == '\r')
            line = line.substr(0, line.size() - 1);
        
        if (!line.empty())
        {
            LogEntry entry;
            entry.lineStart = lineStart;
            entry.lineEnd = lineEnd;
            entry.lineNumber = lineNum;
            
            // Parse IP address
            size_t ipEnd = line.find(' ');
            if (ipEnd != std::string_view::npos)
            {
                entry.ipAddress = std::string(line.substr(0, ipEnd));
                
                // Find timestamp in brackets
                size_t tsStart = line.find('[');
                size_t tsEnd = line.find(']');
                if (tsStart != std::string_view::npos && tsEnd != std::string_view::npos)
                {
                    entry.timestamp = std::string(line.substr(tsStart + 1, tsEnd - tsStart - 1));
                }
                
                // Find request in quotes
                size_t reqStart = line.find('"');
                if (reqStart != std::string_view::npos)
                {
                    size_t reqEnd = line.find('"', reqStart + 1);
                    if (reqEnd != std::string_view::npos)
                    {
                        std::string_view request = line.substr(reqStart + 1, reqEnd - reqStart - 1);
                        
                        // Parse method
                        size_t methodEnd = request.find(' ');
                        if (methodEnd != std::string_view::npos)
                        {
                            entry.httpMethod = std::string(request.substr(0, methodEnd));
                            
                            // Parse URL
                            size_t urlEnd = request.find(' ', methodEnd + 1);
                            if (urlEnd != std::string_view::npos)
                            {
                                entry.url = std::string(request.substr(methodEnd + 1, urlEnd - methodEnd - 1));
                            }
                        }
                        
                        // Parse status code and size after closing quote
                        std::string_view afterRequest = line.substr(reqEnd + 1);
                        size_t numStart = afterRequest.find_first_of("0123456789");
                        if (numStart != std::string_view::npos)
                        {
                            entry.httpStatus = std::atoi(afterRequest.data() + numStart);
                            
                            // Determine log level from HTTP status
                            if (entry.httpStatus >= 500)
                                entry.level = LogLevel::Error;
                            else if (entry.httpStatus >= 400)
                                entry.level = LogLevel::Warning;
                            else
                                entry.level = LogLevel::Info;
                        }
                    }
                }
                
                entry.message = std::string(line);
            }
            
            entries.push_back(std::move(entry));
        }
        
        pos = lineEnd + 1;
        lineNum++;
    }
    
    return true;
}

bool LOGFile::ParseSyslog(const std::string_view& content)
{
    // Syslog format: Mon DD HH:MM:SS hostname process[pid]: message
    
    uint64 pos = 0;
    uint32 lineNum = 1;
    
    while (pos < content.size())
    {
        uint64 lineStart = pos;
        uint64 lineEnd = content.find('\n', pos);
        if (lineEnd == std::string_view::npos)
            lineEnd = content.size();
        
        std::string_view line = content.substr(pos, lineEnd - pos);
        if (!line.empty() && line.back() == '\r')
            line = line.substr(0, line.size() - 1);
        
        if (!line.empty())
        {
            LogEntry entry;
            entry.lineStart = lineStart;
            entry.lineEnd = lineEnd;
            entry.lineNumber = lineNum;
            entry.message = std::string(line);
            
            // Extract timestamp (first 15 characters typically: "Jan  1 12:00:00")
            if (line.size() >= 15)
            {
                entry.timestamp = std::string(line.substr(0, 15));
            }
            
            // Find process name and message
            size_t colonPos = line.find(": ");
            if (colonPos != std::string_view::npos && colonPos > 15)
            {
                // Extract source (hostname + process)
                std::string_view sourcePart = line.substr(16, colonPos - 16);
                size_t spacePos = sourcePart.find(' ');
                if (spacePos != std::string_view::npos)
                {
                    entry.source = std::string(sourcePart.substr(spacePos + 1));
                }
                
                entry.message = std::string(line.substr(colonPos + 2));
            }
            
            // Try to detect log level from message content
            std::string upperMsg = entry.message;
            std::transform(upperMsg.begin(), upperMsg.end(), upperMsg.begin(),
                          [](unsigned char c) { return std::toupper(c); });
            
            if (upperMsg.find("ERROR") != std::string::npos || 
                upperMsg.find("FAIL") != std::string::npos)
                entry.level = LogLevel::Error;
            else if (upperMsg.find("WARN") != std::string::npos)
                entry.level = LogLevel::Warning;
            else if (upperMsg.find("DEBUG") != std::string::npos)
                entry.level = LogLevel::Debug;
            else
                entry.level = LogLevel::Info;
            
            entries.push_back(std::move(entry));
        }
        
        pos = lineEnd + 1;
        lineNum++;
    }
    
    return true;
}

bool LOGFile::ParseLog4j(const std::string_view& content)
{
    // Log4j format variations:
    // 2024-01-15 10:30:00.123 INFO [main] ClassName - Message
    // 2024-01-15 10:30:00,123 [INFO] logger - Message
    
    uint64 pos = 0;
    uint32 lineNum = 1;
    
    while (pos < content.size())
    {
        uint64 lineStart = pos;
        uint64 lineEnd = content.find('\n', pos);
        if (lineEnd == std::string_view::npos)
            lineEnd = content.size();
        
        std::string_view line = content.substr(pos, lineEnd - pos);
        if (!line.empty() && line.back() == '\r')
            line = line.substr(0, line.size() - 1);
        
        if (!line.empty())
        {
            LogEntry entry;
            entry.lineStart = lineStart;
            entry.lineEnd = lineEnd;
            entry.lineNumber = lineNum;
            entry.level = LogLevel::Unknown;
            
            // Try to find timestamp at the beginning
            // Common patterns: YYYY-MM-DD HH:MM:SS or YYYY/MM/DD HH:MM:SS
            size_t timestampEnd = 0;
            if (line.size() >= 19 && 
                (line[4] == '-' || line[4] == '/') &&
                (line[7] == '-' || line[7] == '/'))
            {
                // ISO-like timestamp
                timestampEnd = 19;
                // Check for milliseconds
                if (line.size() > 23 && (line[19] == '.' || line[19] == ','))
                {
                    timestampEnd = 23;
                }
                entry.timestamp = std::string(line.substr(0, timestampEnd));
            }
            
            // Find log level
            std::string_view remaining = timestampEnd > 0 ? line.substr(timestampEnd) : line;
            
            // Look for level indicators
            const char* levels[] = { "TRACE", "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL" };
            for (const char* lvl : levels)
            {
                size_t lvlPos = remaining.find(lvl);
                if (lvlPos != std::string_view::npos && lvlPos < 20)
                {
                    entry.level = ParseLogLevel(lvl);
                    
                    // Find message after level
                    size_t msgStart = remaining.find(" - ", lvlPos);
                    if (msgStart != std::string_view::npos)
                    {
                        // Extract source/logger between level and " - "
                        size_t sourceStart = lvlPos + strlen(lvl);
                        while (sourceStart < msgStart && 
                               (remaining[sourceStart] == ' ' || remaining[sourceStart] == '['))
                        {
                            sourceStart++;
                        }
                        size_t sourceEnd = msgStart;
                        while (sourceEnd > sourceStart && 
                               (remaining[sourceEnd-1] == ' ' || remaining[sourceEnd-1] == ']'))
                        {
                            sourceEnd--;
                        }
                        if (sourceEnd > sourceStart)
                        {
                            entry.source = std::string(remaining.substr(sourceStart, sourceEnd - sourceStart));
                        }
                        
                        entry.message = std::string(remaining.substr(msgStart + 3));
                    }
                    else
                    {
                        entry.message = std::string(remaining.substr(lvlPos + strlen(lvl)));
                    }
                    break;
                }
            }
            
            if (entry.message.empty())
            {
                entry.message = std::string(line);
            }
            
            entries.push_back(std::move(entry));
        }
        
        pos = lineEnd + 1;
        lineNum++;
    }
    
    return true;
}

bool LOGFile::ParseGenericLog(const std::string_view& content)
{
    // Generic parsing - try to extract what we can from each line
    
    uint64 pos = 0;
    uint32 lineNum = 1;
    
    while (pos < content.size())
    {
        uint64 lineStart = pos;
        uint64 lineEnd = content.find('\n', pos);
        if (lineEnd == std::string_view::npos)
            lineEnd = content.size();
        
        std::string_view line = content.substr(pos, lineEnd - pos);
        if (!line.empty() && line.back() == '\r')
            line = line.substr(0, line.size() - 1);
        
        if (!line.empty())
        {
            LogEntry entry;
            entry.lineStart = lineStart;
            entry.lineEnd = lineEnd;
            entry.lineNumber = lineNum;
            entry.message = std::string(line);
            entry.level = LogLevel::Unknown;
            
            // Try to extract timestamp from various positions
            // Look for bracketed content at the start
            if (line[0] == '[')
            {
                size_t bracketEnd = line.find(']');
                if (bracketEnd != std::string_view::npos)
                {
                    entry.timestamp = std::string(line.substr(1, bracketEnd - 1));
                }
            }
            // Look for ISO-like timestamp
            else if (line.size() >= 10 && line[4] == '-' && line[7] == '-')
            {
                size_t tsEnd = 10;
                if (line.size() > 19 && line[10] == ' ' && line[13] == ':')
                {
                    tsEnd = 19;
                    if (line.size() > 23 && (line[19] == '.' || line[19] == ','))
                    {
                        tsEnd = 23;
                    }
                }
                entry.timestamp = std::string(line.substr(0, tsEnd));
            }
            
            // Detect log level from content
            std::string upperLine;
            upperLine.reserve(line.size());
            for (char c : line)
            {
                upperLine += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            }
            
            if (upperLine.find("FATAL") != std::string::npos || 
                upperLine.find("CRITICAL") != std::string::npos)
                entry.level = LogLevel::Fatal;
            else if (upperLine.find("ERROR") != std::string::npos || 
                     upperLine.find("EXCEPTION") != std::string::npos ||
                     upperLine.find("FAIL") != std::string::npos)
                entry.level = LogLevel::Error;
            else if (upperLine.find("WARN") != std::string::npos)
                entry.level = LogLevel::Warning;
            else if (upperLine.find("DEBUG") != std::string::npos)
                entry.level = LogLevel::Debug;
            else if (upperLine.find("TRACE") != std::string::npos)
                entry.level = LogLevel::Trace;
            else if (upperLine.find("INFO") != std::string::npos)
                entry.level = LogLevel::Info;
            
            entries.push_back(std::move(entry));
        }
        
        pos = lineEnd + 1;
        lineNum++;
    }
    
    return true;
}

void LOGFile::UpdateStatistics()
{
    stats = LogStatistics();
    stats.totalLines = static_cast<uint32>(entries.size());
    
    for (const auto& entry : entries)
    {
        switch (entry.level)
        {
        case LogLevel::Trace:
            stats.traceCount++;
            break;
        case LogLevel::Debug:
            stats.debugCount++;
            break;
        case LogLevel::Info:
            stats.infoCount++;
            break;
        case LogLevel::Warning:
            stats.warningCount++;
            break;
        case LogLevel::Error:
            stats.errorCount++;
            break;
        case LogLevel::Fatal:
        case LogLevel::Critical:
            stats.fatalCount++;
            break;
        default:
            stats.unknownCount++;
            break;
        }
        
        // HTTP status statistics
        if (entry.httpStatus >= 200 && entry.httpStatus < 300)
            stats.http2xxCount++;
        else if (entry.httpStatus >= 300 && entry.httpStatus < 400)
            stats.http3xxCount++;
        else if (entry.httpStatus >= 400 && entry.httpStatus < 500)
            stats.http4xxCount++;
        else if (entry.httpStatus >= 500)
            stats.http5xxCount++;
    }
    
    // Set first and last timestamps
    if (!entries.empty())
    {
        for (const auto& entry : entries)
        {
            if (!entry.timestamp.empty())
            {
                stats.firstTimestamp = entry.timestamp;
                break;
            }
        }
        for (auto it = entries.rbegin(); it != entries.rend(); ++it)
        {
            if (!it->timestamp.empty())
            {
                stats.lastTimestamp = it->timestamp;
                break;
            }
        }
    }
}

std::string_view LOGFile::LogLevelToString(LogLevel level)
{
    switch (level)
    {
    case LogLevel::Trace:    return "TRACE";
    case LogLevel::Debug:    return "DEBUG";
    case LogLevel::Info:     return "INFO";
    case LogLevel::Warning:  return "WARNING";
    case LogLevel::Error:    return "ERROR";
    case LogLevel::Fatal:    return "FATAL";
    case LogLevel::Critical: return "CRITICAL";
    default:                 return "UNKNOWN";
    }
}

std::string_view LOGFile::LogFormatToString(LogFormat format)
{
    switch (format)
    {
    case LogFormat::Apache:       return "Apache/Nginx Access Log";
    case LogFormat::ApacheError:  return "Apache/Nginx Error Log";
    case LogFormat::Syslog:       return "Syslog";
    case LogFormat::WindowsEvent: return "Windows Event Log";
    case LogFormat::IIS:          return "IIS Log";
    case LogFormat::Log4j:        return "Log4j/Log4net";
    case LogFormat::JSON:         return "JSON Structured Log";
    case LogFormat::Custom:       return "Generic/Custom";
    default:                      return "Unknown";
    }
}

ColorPair LOGFile::GetLogLevelColor(LogLevel level)
{
    switch (level)
    {
    case LogLevel::Trace:    return ColorPair{ Color::Gray, Color::Transparent };
    case LogLevel::Debug:    return ColorPair{ Color::Aqua, Color::Transparent };
    case LogLevel::Info:     return ColorPair{ Color::Green, Color::Transparent };
    case LogLevel::Warning:  return ColorPair{ Color::Yellow, Color::Transparent };
    case LogLevel::Error:    return ColorPair{ Color::Red, Color::Transparent };
    case LogLevel::Fatal:
    case LogLevel::Critical: return ColorPair{ Color::Magenta, Color::Transparent };
    default:                 return ColorPair{ Color::White, Color::Transparent };
    }
}

// LexicalViewer::ParseInterface implementations
void LOGFile::GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str)
{
    switch (id)
    {
    case TokenType::Timestamp:    str.Set("Timestamp"); break;
    case TokenType::Level:        str.Set("Level"); break;
    case TokenType::LevelError:   str.Set("Error"); break;
    case TokenType::LevelWarning: str.Set("Warning"); break;
    case TokenType::LevelInfo:    str.Set("Info"); break;
    case TokenType::LevelDebug:   str.Set("Debug"); break;
    case TokenType::Source:       str.Set("Source"); break;
    case TokenType::Message:      str.Set("Message"); break;
    case TokenType::IPAddress:    str.Set("IP Address"); break;
    case TokenType::HTTPMethod:   str.Set("HTTP Method"); break;
    case TokenType::HTTPStatus:   str.Set("HTTP Status"); break;
    case TokenType::URL:          str.Set("URL"); break;
    case TokenType::Number:       str.Set("Number"); break;
    case TokenType::Bracket:      str.Set("Bracket"); break;
    case TokenType::String:       str.Set("String"); break;
    case TokenType::Separator:    str.Set("Separator"); break;
    default:                      str.Set("Unknown"); break;
    }
}

void LOGFile::PreprocessText(GView::View::LexicalViewer::TextEditor& /*editor*/)
{
    // No preprocessing needed for log files
}

void LOGFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    const auto& text = syntax.text;
    auto& tokens = syntax.tokens;
    uint32 len = text.Len();
    uint32 pos = 0;
    
    while (pos < len)
    {
        // Skip whitespace
        while (pos < len && (text[pos] == ' ' || text[pos] == '\t'))
            pos++;
        
        if (pos >= len)
            break;
        
        uint32 start = pos;
        char16 ch = text[pos];
        
        // Handle newlines
        if (ch == '\n' || ch == '\r')
        {
            pos++;
            if (pos < len && ((ch == '\r' && text[pos] == '\n') || (ch == '\n' && text[pos] == '\r')))
                pos++;
            continue;
        }
        
        // Handle brackets
        if (ch == '[' || ch == ']' || ch == '(' || ch == ')' || ch == '{' || ch == '}' || ch == '<' || ch == '>')
        {
            tokens.Add(TokenType::Bracket, start, start + 1, TokenColor::Operator);
            pos++;
            continue;
        }
        
        // Handle quoted strings
        if (ch == '"' || ch == '\'')
        {
            char16 quote = ch;
            pos++;
            while (pos < len && text[pos] != quote && text[pos] != '\n' && text[pos] != '\r')
            {
                if (text[pos] == '\\' && pos + 1 < len)
                    pos++;
                pos++;
            }
            if (pos < len && text[pos] == quote)
                pos++;
            tokens.Add(TokenType::String, start, pos, TokenColor::String);
            continue;
        }
        
        // Handle numbers (including IP addresses and timestamps)
        if (ch >= '0' && ch <= '9')
        {
            // Check if it looks like an IP address or timestamp
            bool hasColon = false;
            bool hasDot = false;
            bool hasDash = false;
            uint32 colonCount = 0;
            uint32 dotCount = 0;
            
            while (pos < len)
            {
                char16 c = text[pos];
                if (c >= '0' && c <= '9')
                {
                    pos++;
                }
                else if (c == '.')
                {
                    hasDot = true;
                    dotCount++;
                    pos++;
                }
                else if (c == ':')
                {
                    hasColon = true;
                    colonCount++;
                    pos++;
                }
                else if (c == '-')
                {
                    hasDash = true;
                    pos++;
                }
                else if (c == '/' || c == 'T' || c == 'Z' || c == '+')
                {
                    pos++;
                }
                else
                {
                    break;
                }
            }
            
            uint32 tokenType = TokenType::Number;
            TokenColor tokenColor = TokenColor::Number;
            if (dotCount == 3 && !hasColon && !hasDash)
            {
                tokenType = TokenType::IPAddress;
                tokenColor = TokenColor::Keyword2;
            }
            else if (hasDash || hasColon)
            {
                tokenType = TokenType::Timestamp;
                tokenColor = TokenColor::Keyword;
            }
            
            tokens.Add(tokenType, start, pos, tokenColor);
            continue;
        }
        
        // Handle words (check for log levels, HTTP methods, etc.)
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_')
        {
            while (pos < len)
            {
                char16 c = text[pos];
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
                    (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')
                {
                    pos++;
                }
                else
                {
                    break;
                }
            }
            
            // Extract the word for classification
            std::u16string word;
            for (uint32 i = start; i < pos && i < len; i++)
            {
                word += text[i];
            }
            
            // Convert to uppercase for comparison
            std::string wordUpper;
            for (char16 c : word)
            {
                if (c < 128)
                    wordUpper += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            }
            
            uint32 tokenType = TokenType::Message;
            TokenColor tokenColor = TokenColor::Word;
            
            // Check for log levels
            if (wordUpper == "ERROR" || wordUpper == "ERR" || wordUpper == "ERRO")
            {
                tokenType = TokenType::LevelError;
                tokenColor = TokenColor::Error;
            }
            else if (wordUpper == "WARN" || wordUpper == "WARNING" || wordUpper == "WRN")
            {
                tokenType = TokenType::LevelWarning;
                tokenColor = TokenColor::Keyword2;
            }
            else if (wordUpper == "INFO" || wordUpper == "INF" || wordUpper == "INFORMATION")
            {
                tokenType = TokenType::LevelInfo;
                tokenColor = TokenColor::Keyword;
            }
            else if (wordUpper == "DEBUG" || wordUpper == "DBG" || wordUpper == "DEBU")
            {
                tokenType = TokenType::LevelDebug;
                tokenColor = TokenColor::Comment;
            }
            else if (wordUpper == "TRACE" || wordUpper == "TRC")
            {
                tokenType = TokenType::LevelDebug;
                tokenColor = TokenColor::Comment;
            }
            else if (wordUpper == "FATAL" || wordUpper == "FTL" || wordUpper == "CRITICAL" || wordUpper == "CRIT")
            {
                tokenType = TokenType::LevelError;
                tokenColor = TokenColor::Error;
            }
            // Check for HTTP methods
            else if (wordUpper == "GET" || wordUpper == "POST" || wordUpper == "PUT" || 
                     wordUpper == "DELETE" || wordUpper == "PATCH" || wordUpper == "HEAD" ||
                     wordUpper == "OPTIONS" || wordUpper == "CONNECT" || wordUpper == "TRACE")
            {
                tokenType = TokenType::HTTPMethod;
                tokenColor = TokenColor::Keyword2;
            }
            // Check for HTTP status descriptions
            else if (wordUpper == "HTTP")
            {
                tokenType = TokenType::HTTPMethod;
                tokenColor = TokenColor::Keyword2;
            }
            
            tokens.Add(tokenType, start, pos, tokenColor);
            continue;
        }
        
        // Handle separators and other characters
        pos++;
        tokens.Add(TokenType::Separator, start, pos, TokenColor::Operator);
    }
}

bool LOGFile::StringToContent(std::u16string_view /*stringValue*/, AppCUI::Utils::UnicodeStringBuilder& /*result*/)
{
    return false;
}

bool LOGFile::ContentToString(std::u16string_view /*content*/, AppCUI::Utils::UnicodeStringBuilder& /*result*/)
{
    return false;
}

GView::Utils::JsonBuilderInterface* LOGFile::GetSmartAssistantContext(const std::string_view& /*prompt*/, std::string_view /*displayPrompt*/)
{
    auto builder = GView::Utils::JsonBuilderInterface::Create();
    
    builder->AddU16String("Name", obj->GetName());
    builder->AddUInt("ContentSize", obj->GetData().GetSize());
    builder->AddString("Format", std::string(LogFormatToString(detectedFormat)));
    builder->AddUInt("TotalLines", stats.totalLines);
    builder->AddUInt("ErrorCount", stats.errorCount);
    builder->AddUInt("WarningCount", stats.warningCount);
    builder->AddUInt("InfoCount", stats.infoCount);
    
    if (!stats.firstTimestamp.empty())
        builder->AddString("FirstTimestamp", stats.firstTimestamp);
    if (!stats.lastTimestamp.empty())
        builder->AddString("LastTimestamp", stats.lastTimestamp);
    
    return builder;
}

} // namespace GView::Type::LOG
