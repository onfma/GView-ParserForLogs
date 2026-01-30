#include "log.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

extern "C"
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        // Check for common log file extensions
        if (extension == ".log" || extension == ".txt" || extension == ".logs")
        {
            // Look for common log patterns in the first part of the file
            std::string_view content(reinterpret_cast<const char*>(buf.GetData()), 
                                     std::min(static_cast<size_t>(buf.GetLength()), static_cast<size_t>(4096)));
            
            // Check for timestamp patterns (various formats)
            // ISO 8601: 2024-01-15T10:30:00
            // Common: 2024-01-15 10:30:00
            // Apache: [15/Jan/2024:10:30:00 +0000]
            // Syslog: Jan 15 10:30:00
            
            bool hasTimestamp = false;
            bool hasLogLevel = false;
            
            // Check for date patterns
            if (content.find("202") != std::string_view::npos || // Years 2020+
                content.find("/Jan/") != std::string_view::npos ||
                content.find("/Feb/") != std::string_view::npos ||
                content.find("/Mar/") != std::string_view::npos ||
                content.find("/Apr/") != std::string_view::npos ||
                content.find("/May/") != std::string_view::npos ||
                content.find("/Jun/") != std::string_view::npos ||
                content.find("/Jul/") != std::string_view::npos ||
                content.find("/Aug/") != std::string_view::npos ||
                content.find("/Sep/") != std::string_view::npos ||
                content.find("/Oct/") != std::string_view::npos ||
                content.find("/Nov/") != std::string_view::npos ||
                content.find("/Dec/") != std::string_view::npos ||
                content.find("Jan ") != std::string_view::npos ||
                content.find("Feb ") != std::string_view::npos ||
                content.find("Mar ") != std::string_view::npos ||
                content.find("Apr ") != std::string_view::npos ||
                content.find("May ") != std::string_view::npos ||
                content.find("Jun ") != std::string_view::npos ||
                content.find("Jul ") != std::string_view::npos ||
                content.find("Aug ") != std::string_view::npos ||
                content.find("Sep ") != std::string_view::npos ||
                content.find("Oct ") != std::string_view::npos ||
                content.find("Nov ") != std::string_view::npos ||
                content.find("Dec ") != std::string_view::npos)
            {
                hasTimestamp = true;
            }
            
            // Check for log level indicators
            if (content.find("ERROR") != std::string_view::npos ||
                content.find("WARN") != std::string_view::npos ||
                content.find("INFO") != std::string_view::npos ||
                content.find("DEBUG") != std::string_view::npos ||
                content.find("TRACE") != std::string_view::npos ||
                content.find("FATAL") != std::string_view::npos ||
                content.find("error") != std::string_view::npos ||
                content.find("warn") != std::string_view::npos ||
                content.find("info") != std::string_view::npos ||
                content.find("debug") != std::string_view::npos ||
                content.find("[error]") != std::string_view::npos ||
                content.find("[warn]") != std::string_view::npos ||
                content.find("[info]") != std::string_view::npos)
            {
                hasLogLevel = true;
            }
            
            // Check for HTTP log patterns (Apache/Nginx)
            if (content.find("GET ") != std::string_view::npos ||
                content.find("POST ") != std::string_view::npos ||
                content.find("HTTP/") != std::string_view::npos ||
                content.find("\" 200 ") != std::string_view::npos ||
                content.find("\" 404 ") != std::string_view::npos ||
                content.find("\" 500 ") != std::string_view::npos)
            {
                return true; // Web server access log
            }
            
            // Accept if we found timestamps or log levels
            if (hasTimestamp || hasLogLevel)
            {
                return true;
            }
        }
        
        // Also check for access.log or error.log naming
        if (extension.empty())
        {
            // Could be access.log, error.log, etc. without extension detection
            return false;
        }
        
        return false;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new LOG::LOGFile();
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto log = win->GetObject()->GetContentType<LOG::LOGFile>();
        log->obj = win->GetObject();
        log->Update();

        // Create lexical viewer with syntax highlighting
        LexicalViewer::Settings lexSettings;
        lexSettings.SetParser(log.ToObjectRef<LexicalViewer::ParseInterface>());
        lexSettings.AddPlugin(&log->plugins.filterByLevel);
        lexSettings.AddPlugin(&log->plugins.extractErrors);
        win->CreateViewer(lexSettings);

        // Create text viewer as fallback
        win->CreateViewer<TextViewer::Settings>("Text View");

        // Create buffer viewer
        View::BufferViewer::Settings bufSettings{};
        log->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(bufSettings);

        // Add panels
        if (log->HasPanel(LOG::Panels::IDs::Information))
        {
            win->AddPanel(Pointer<TabPage>(new LOG::Panels::Information(log)), true);
        }
        if (log->HasPanel(LOG::Panels::IDs::Entries))
        {
            win->AddPanel(Pointer<TabPage>(new LOG::Panels::Entries(log)), false);
        }
        if (log->HasPanel(LOG::Panels::IDs::Errors))
        {
            win->AddPanel(Pointer<TabPage>(new LOG::Panels::Errors(log)), false);
        }

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Extension"]   = { "log", "logs" };
        sect["Priority"]    = 1;
        sect["Description"] = "Log files (*.log, *.logs) - Web server, application, system logs";
    }
}

int main()
{
    return 0;
}
