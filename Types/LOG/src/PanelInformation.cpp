#include "log.hpp"

using namespace GView::Type::LOG;
using namespace AppCUI::Controls;
using namespace AppCUI::Utils;

// ==================== Information Panel ====================

Panels::Information::Information(Reference<GView::Type::LOG::LOGFile> _log) : TabPage("Informa&tion")
{
    log = _log;
    
    general = Factory::ListView::Create(
        this, "x:0,y:0,w:100%,h:10", 
        { "n:Field,w:16", "n:Value,w:100" }, 
        ListViewFlags::None
    );
    
    statistics = Factory::ListView::Create(
        this, "x:0,y:11,w:100%,h:10", 
        { "n:Level,w:12", "n:Count,w:10", "n:Percentage,w:12" }, 
        ListViewFlags::None
    );

    this->Update();
}

void Panels::Information::UpdateGeneralInformation()
{
    LocalString<256> tempStr;
    NumericFormatter n;

    general->DeleteAllItems();
    
    // File information
    general->AddItem("File").SetType(ListViewItem::Type::Category);
    general->AddItem({ "Size", 
        tempStr.Format("%s bytes", 
            n.ToString(log->obj->GetData().GetSize(), { NumericFormatFlags::None, 10, 3, ',' }).data()) 
    });
    
    // Log format
    general->AddItem({ "Format", LOGFile::LogFormatToString(log->GetDetectedFormat()).data() });
    
    // Total entries
    general->AddItem({ "Total Lines", 
        tempStr.Format("%s", 
            n.ToString(log->GetStatistics().totalLines, { NumericFormatFlags::None, 10, 3, ',' }).data()) 
    });
    
    // Time range
    const auto& stats = log->GetStatistics();
    if (!stats.firstTimestamp.empty())
    {
        general->AddItem({ "First Entry", stats.firstTimestamp.c_str() });
    }
    if (!stats.lastTimestamp.empty())
    {
        general->AddItem({ "Last Entry", stats.lastTimestamp.c_str() });
    }
}

void Panels::Information::UpdateStatistics()
{
    LocalString<64> tempStr;
    NumericFormatter n;
    
    statistics->DeleteAllItems();
    
    const auto& stats = log->GetStatistics();
    uint32 total = stats.totalLines > 0 ? stats.totalLines : 1;
    
    statistics->AddItem("Level Statistics").SetType(ListViewItem::Type::Category);
    
    auto addStatRow = [&](const char* level, uint32 count) {
        float pct = (count * 100.0f) / total;
        statistics->AddItem({ level, 
            n.ToString(count, { NumericFormatFlags::None, 10, 3, ',' }).data(),
            tempStr.Format("%.1f%%", pct)
        });
    };
    
    // Add rows for each level
    addStatRow("FATAL", stats.fatalCount);
    addStatRow("ERROR", stats.errorCount);
    addStatRow("WARNING", stats.warningCount);
    addStatRow("INFO", stats.infoCount);
    addStatRow("DEBUG", stats.debugCount);
    addStatRow("TRACE", stats.traceCount);
    addStatRow("UNKNOWN", stats.unknownCount);
    
    // HTTP statistics if applicable
    if (stats.http2xxCount > 0 || stats.http4xxCount > 0 || stats.http5xxCount > 0)
    {
        statistics->AddItem("HTTP Status").SetType(ListViewItem::Type::Category);
        addStatRow("2xx (OK)", stats.http2xxCount);
        addStatRow("3xx (Redirect)", stats.http3xxCount);
        addStatRow("4xx (Client)", stats.http4xxCount);
        addStatRow("5xx (Server)", stats.http5xxCount);
    }
}

void Panels::Information::RecomputePanelsPositions()
{
    int w = this->GetWidth();
    int h = this->GetHeight();

    if (!general.IsValid() || !statistics.IsValid())
        return;

    int halfHeight = h / 2;
    general->Resize(w, halfHeight);
    general->MoveTo(0, 0);
    
    statistics->Resize(w, h - halfHeight - 1);
    statistics->MoveTo(0, halfHeight + 1);
}

void Panels::Information::Update()
{
    UpdateGeneralInformation();
    UpdateStatistics();
    RecomputePanelsPositions();
}

// ==================== Entries Panel ====================

Panels::Entries::Entries(Reference<GView::Type::LOG::LOGFile> _log) : TabPage("&Entries")
{
    log = _log;
    
    list = Factory::ListView::Create(
        this, "x:0,y:0,w:100%,h:100%",
        { "n:#,w:6", "n:Level,w:8", "n:Timestamp,w:24", "n:Source,w:20", "n:Message,w:200" },
        ListViewFlags::AllowMultipleItemsSelection
    );
    
    this->Update();
}

void Panels::Entries::PopulateList()
{
    list->DeleteAllItems();
    
    LocalString<16> lineNum;
    const auto& entries = log->GetEntries();
    
    // Limit display for very large files
    constexpr size_t MAX_DISPLAY_ENTRIES = 10000;
    size_t displayCount = std::min(entries.size(), MAX_DISPLAY_ENTRIES);
    
    for (size_t i = 0; i < displayCount; i++)
    {
        const auto& entry = entries[i];
        
        list->AddItem({
            lineNum.Format("%u", entry.lineNumber),
            LOGFile::LogLevelToString(entry.level).data(),
            entry.timestamp.c_str(),
            entry.source.c_str(),
            entry.message.c_str()
        });
    }
    
    if (entries.size() > MAX_DISPLAY_ENTRIES)
    {
        LocalString<64> moreMsg;
        list->AddItem({ "...", "...", "...", "...", 
            moreMsg.Format("(Showing %zu of %zu entries)", MAX_DISPLAY_ENTRIES, entries.size())
        });
    }
}

void Panels::Entries::Update()
{
    PopulateList();
}

void Panels::Entries::OnAfterResize(int newWidth, int newHeight)
{
    if (list.IsValid())
    {
        list->Resize(newWidth, newHeight);
    }
}

bool Panels::Entries::OnEvent(Reference<Control> sender, AppCUI::Controls::Event eventType, int /*controlID*/)
{
    if (eventType == Event::ListViewItemPressed && sender == list)
    {
        return true;
    }
    return false;
}

// ==================== Errors Panel ====================

Panels::Errors::Errors(Reference<GView::Type::LOG::LOGFile> _log) : TabPage("E&rrors")
{
    log = _log;
    
    list = Factory::ListView::Create(
        this, "x:0,y:0,w:100%,h:100%",
        { "n:#,w:6", "n:Level,w:8", "n:Timestamp,w:24", "n:Message,w:200" },
        ListViewFlags::AllowMultipleItemsSelection
    );
    
    this->Update();
}

void Panels::Errors::PopulateList()
{
    list->DeleteAllItems();
    
    LocalString<16> lineNum;
    const auto& entries = log->GetEntries();
    
    uint32 errorCount = 0;
    constexpr uint32 MAX_DISPLAY_ERRORS = 5000;
    
    for (const auto& entry : entries)
    {
        // Show only errors, warnings, and fatal
        if (entry.level == LogLevel::Error || 
            entry.level == LogLevel::Warning || 
            entry.level == LogLevel::Fatal ||
            entry.level == LogLevel::Critical)
        {
            if (errorCount >= MAX_DISPLAY_ERRORS)
            {
                list->AddItem({ "...", "...", "...", 
                    "(More errors not shown - use filtering)" 
                });
                break;
            }
            
            list->AddItem({
                lineNum.Format("%u", entry.lineNumber),
                LOGFile::LogLevelToString(entry.level).data(),
                entry.timestamp.c_str(),
                entry.message.c_str()
            });
            
            errorCount++;
        }
    }
    
    if (errorCount == 0)
    {
        list->AddItem({ "", "", "", "No errors or warnings found in the log file." });
    }
}

void Panels::Errors::Update()
{
    PopulateList();
}

void Panels::Errors::OnAfterResize(int newWidth, int newHeight)
{
    if (list.IsValid())
    {
        list->Resize(newWidth, newHeight);
    }
}

bool Panels::Errors::OnEvent(Reference<Control> sender, AppCUI::Controls::Event eventType, int /*controlID*/)
{
    if (eventType == Event::ListViewItemPressed && sender == list)
    {
        return true;
    }
    return false;
}
