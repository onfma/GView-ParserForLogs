#include "log.hpp"

namespace GView::Type::LOG::Plugins
{

// ==================== FilterByLevel Plugin ====================

std::string_view FilterByLevel::GetName()
{
    return "Filter by Level";
}

std::string_view FilterByLevel::GetDescription()
{
    return "Filter log entries to show only specific severity levels";
}

bool FilterByLevel::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& /*data*/)
{
    return true;
}

GView::View::LexicalViewer::PluginAfterActionRequest FilterByLevel::Execute(
    GView::View::LexicalViewer::PluginData& /*data*/, Reference<Window> /*parent*/)
{
    return GView::View::LexicalViewer::PluginAfterActionRequest::None;
}

// ==================== ExtractErrors Plugin ====================

std::string_view ExtractErrors::GetName()
{
    return "Extract Errors";
}

std::string_view ExtractErrors::GetDescription()
{
    return "Extract all error and warning entries to a new buffer";
}

bool ExtractErrors::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& /*data*/)
{
    return true;
}

GView::View::LexicalViewer::PluginAfterActionRequest ExtractErrors::Execute(
    GView::View::LexicalViewer::PluginData& /*data*/, Reference<Window> /*parent*/)
{
    return GView::View::LexicalViewer::PluginAfterActionRequest::None;
}

} // namespace GView::Type::LOG::Plugins
