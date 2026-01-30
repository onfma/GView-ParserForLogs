#pragma once

#include "GView.hpp"
#include <vector>
#include <string>
#include <optional>
#include <regex>

namespace GView
{
namespace Type
{
    namespace LOG
    {
        // Log entry severity levels
        enum class LogLevel : uint8
        {
            Unknown = 0,
            Trace,
            Debug,
            Info,
            Warning,
            Error,
            Fatal,
            Critical
        };

        // Recognized log formats
        enum class LogFormat : uint8
        {
            Unknown = 0,
            Apache,          // Apache/Nginx access logs
            ApacheError,     // Apache/Nginx error logs
            Syslog,          // Standard syslog format
            WindowsEvent,    // Windows Event Log format
            IIS,             // IIS web server logs
            Log4j,           // Log4j/Log4net format
            JSON,            // JSON-structured logs
            Custom           // Custom/unrecognized format
        };

        // Token types for lexical highlighting
        namespace TokenType
        {
            constexpr uint32 Timestamp    = 0;
            constexpr uint32 Level        = 1;
            constexpr uint32 LevelError   = 2;
            constexpr uint32 LevelWarning = 3;
            constexpr uint32 LevelInfo    = 4;
            constexpr uint32 LevelDebug   = 5;
            constexpr uint32 Source       = 6;
            constexpr uint32 Message      = 7;
            constexpr uint32 IPAddress    = 8;
            constexpr uint32 HTTPMethod   = 9;
            constexpr uint32 HTTPStatus   = 10;
            constexpr uint32 URL          = 11;
            constexpr uint32 Number       = 12;
            constexpr uint32 Bracket      = 13;
            constexpr uint32 String       = 14;
            constexpr uint32 Separator    = 15;
            constexpr uint32 Invalid      = 0xFFFFFFFF;
        } // namespace TokenType

        // Structure representing a parsed log entry
        struct LogEntry
        {
            uint64 lineStart;          // Start offset in file
            uint64 lineEnd;            // End offset in file
            uint32 lineNumber;         // Line number (1-based)
            
            std::string timestamp;     // Extracted timestamp
            LogLevel level;            // Log severity level
            std::string source;        // Source/logger name
            std::string message;       // Log message content
            
            // Web server specific fields
            std::string ipAddress;     // Client IP
            std::string httpMethod;    // GET, POST, etc.
            std::string url;           // Requested URL
            int httpStatus;            // HTTP status code
            int64 responseSize;        // Response size in bytes
            std::string userAgent;     // User agent string
            std::string referer;       // Referer header
            
            LogEntry() : lineStart(0), lineEnd(0), lineNumber(0), 
                         level(LogLevel::Unknown), httpStatus(0), responseSize(0) {}
        };

        // Statistics about the log file
        struct LogStatistics
        {
            uint32 totalLines;
            uint32 errorCount;
            uint32 warningCount;
            uint32 infoCount;
            uint32 debugCount;
            uint32 traceCount;
            uint32 fatalCount;
            uint32 unknownCount;
            
            // Web server stats
            uint32 http2xxCount;       // Success responses
            uint32 http3xxCount;       // Redirects
            uint32 http4xxCount;       // Client errors
            uint32 http5xxCount;       // Server errors
            
            std::string firstTimestamp;
            std::string lastTimestamp;
            
            LogStatistics() : totalLines(0), errorCount(0), warningCount(0),
                              infoCount(0), debugCount(0), traceCount(0),
                              fatalCount(0), unknownCount(0),
                              http2xxCount(0), http3xxCount(0),
                              http4xxCount(0), http5xxCount(0) {}
        };

        namespace Panels
        {
            enum class IDs : uint8
            {
                Information = 0,
                Entries,
                Errors
            };
        };

        // Forward declarations for plugins
        namespace Plugins
        {
            class FilterByLevel : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(
                      GView::View::LexicalViewer::PluginData& data, Reference<Window> parent) override;
            };

            class ExtractErrors : public GView::View::LexicalViewer::Plugin
            {
              public:
                virtual std::string_view GetName() override;
                virtual std::string_view GetDescription() override;
                virtual bool CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data) override;
                virtual GView::View::LexicalViewer::PluginAfterActionRequest Execute(
                      GView::View::LexicalViewer::PluginData& data, Reference<Window> parent) override;
            };
        } // namespace Plugins

        class LOGFile : public TypeInterface, public GView::View::LexicalViewer::ParseInterface
        {
          private:
            LogFormat detectedFormat;
            LogStatistics stats;
            std::vector<LogEntry> entries;
            uint64 panelsMask;

            // Parsing helpers
            bool ParseApacheLog(const std::string_view& content);
            bool ParseSyslog(const std::string_view& content);
            bool ParseLog4j(const std::string_view& content);
            bool ParseGenericLog(const std::string_view& content);
            
            LogLevel ParseLogLevel(const std::string_view& levelStr);
            LogFormat DetectLogFormat(const std::string_view& content);
            
            void UpdateStatistics();

          public:
            struct
            {
                Plugins::FilterByLevel filterByLevel;
                Plugins::ExtractErrors extractErrors;
            } plugins;

            Reference<GView::Object> obj;
            Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

          public:
            LOGFile();
            virtual ~LOGFile() = default;

            bool Update();
            bool HasPanel(Panels::IDs id);

            // TypeInterface implementation
            std::string_view GetTypeName() override
            {
                return "LOG";
            }

            void RunCommand(std::string_view) override {}

            virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
            {
                return true;
            }

            // LexicalViewer::ParseInterface implementation
            virtual void GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str) override;
            virtual void PreprocessText(GView::View::LexicalViewer::TextEditor& editor) override;
            virtual void AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax) override;
            virtual bool StringToContent(std::u16string_view stringValue, AppCUI::Utils::UnicodeStringBuilder& result) override;
            virtual bool ContentToString(std::u16string_view content, AppCUI::Utils::UnicodeStringBuilder& result) override;

            // SelectionZone interface
            uint32 GetSelectionZonesCount() override
            {
                CHECK(selectionZoneInterface.IsValid(), 0, "");
                return selectionZoneInterface->GetSelectionZonesCount();
            }

            TypeInterface::SelectionZone GetSelectionZone(uint32 index) override
            {
                static auto d = TypeInterface::SelectionZone{ 0, 0 };
                CHECK(selectionZoneInterface.IsValid(), d, "");
                CHECK(index < selectionZoneInterface->GetSelectionZonesCount(), d, "");
                return selectionZoneInterface->GetSelectionZone(index);
            }

            GView::Utils::JsonBuilderInterface* GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt) override;

            // Accessors
            LogFormat GetDetectedFormat() const { return detectedFormat; }
            const LogStatistics& GetStatistics() const { return stats; }
            const std::vector<LogEntry>& GetEntries() const { return entries; }
            
            static std::string_view LogLevelToString(LogLevel level);
            static std::string_view LogFormatToString(LogFormat format);
            static ColorPair GetLogLevelColor(LogLevel level);
        };

        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
              private:
                Reference<GView::Type::LOG::LOGFile> log;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> statistics;

                void UpdateGeneralInformation();
                void UpdateStatistics();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::LOG::LOGFile> log);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };

            class Entries : public AppCUI::Controls::TabPage
            {
              private:
                Reference<GView::Type::LOG::LOGFile> log;
                Reference<AppCUI::Controls::ListView> list;

                void PopulateList();

              public:
                Entries(Reference<GView::Type::LOG::LOGFile> log);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override;
                bool OnEvent(Reference<Control> sender, AppCUI::Controls::Event eventType, int controlID) override;
            };

            class Errors : public AppCUI::Controls::TabPage
            {
              private:
                Reference<GView::Type::LOG::LOGFile> log;
                Reference<AppCUI::Controls::ListView> list;

                void PopulateList();

              public:
                Errors(Reference<GView::Type::LOG::LOGFile> log);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override;
                bool OnEvent(Reference<Control> sender, AppCUI::Controls::Event eventType, int controlID) override;
            };
        }; // namespace Panels

    } // namespace LOG
} // namespace Type
} // namespace GView
